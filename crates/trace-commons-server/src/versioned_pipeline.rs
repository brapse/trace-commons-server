// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable implementation of the versioned four-phase pipeline.
//!
//! This module is local/test-only until later phases add production policies.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::Row;
use trace_commons_gate_api::pipeline::{
    AdmissionDecision, AdmissionEvaluation, AdmissionEvidence, AdmissionInput, AdmissionPolicy,
    AtomicUnits, BUNDLE_MANIFEST_FORMAT_VERSION, BundleManifest, BundlePackage,
    IndexMembershipDecision, InstrumentAward, InstrumentAwards, InstrumentSettlement, Microcredits,
    PIPELINE_OUTCOME_SCHEMA_ID, PIPELINE_OUTCOME_SCHEMA_VERSION, Phase, PhaseResult, PolicyError,
    PolicyRef, ReasonCode, ReviewDecision, ReviewEvaluation, ReviewEvidence, ReviewInput,
    ReviewPolicy, ReviewRecommendation, SchemaRef, ScoreDecision, ScoreEvaluation, ScoreEvidence,
    ScoreInput, ScorePolicy, SettleDecision, SettleEvaluation, SettleEvidence, SettleInput,
    SettlePolicy,
};
use trace_commons_gate_api::{
    Embedder, IndexWriteError, PerplexityScorer, ReferenceEmbedder, ReferencePerplexityScorer,
    VectorIndexReader, VectorIndexWriter,
};
use uuid::Uuid;

use crate::db::postgres::PgBackend;
use crate::error::DatabaseError;
use crate::trace_artifact_store::{
    EncryptedTraceArtifactReceipt, TraceArtifactKind, TraceArtifactStore,
};
use crate::trace_authority::{SubmissionAllowlists, SubmissionAuthority};
use crate::trace_corpus_storage::{
    TraceCorpusStatus, TraceCorpusStore, TraceCreditHoldReason, TraceCreditSettlementBatchStatus,
    TraceCreditSettlementNearStatus, TraceObjectArtifactKind, TraceObjectRefWrite,
    TraceSubmissionWrite, safe_residual_risk_basis_labels,
};
use crate::versioned_pipeline_authority::{
    ClassifierRedactorPipelinePrivacyBoundary, PIPELINE_AUTHORITY_CONTROL_MISSING_LABEL,
    PIPELINE_PRIVACY_CLASSIFICATION_FAILED_LABEL, PipelineAuthorityProvider,
    PipelinePrivacyBoundary, StaticPipelineAuthorityProvider,
};
use crate::versioned_pipeline_compat::{
    COMPATIBILITY_SCORE_CODE, COMPATIBILITY_SCORE_IMPLEMENTATION, COMPATIBILITY_SETTLE_CODE,
    COMPATIBILITY_SETTLE_IMPLEMENTATION, CompatibilityBundleConfig, CompatibilityScorePolicy,
    CompatibilityScoreRuntime, CompatibilitySettlePolicy,
};
use crate::versioned_pipeline_credit::{
    NearPayoutAdapter, PIPELINE_CREDIT_REASON, PIPELINE_SETTLEMENT_POLICY_VERSION,
    PIPELINE_TEST_CREDIT_CAP_MICROCREDITS, RecordingNearAdapter, RecordingSettlementAdapter,
    SettlementAdapterRegistry, SettlementRequest, credit_account_hash, disabled_near_call,
    issuer_approval_hash, microcredits_to_settled_i64, pipeline_credit_event_id,
    pipeline_near_outbox_line_id, pipeline_settlement_batch_id, source_list_hash,
};
use crate::versioned_pipeline_index::{
    IsolatedPipelineIndex, PIPELINE_INDEX_ID, SealedIndexCommand, deterministic_pipeline_embedding,
};
use trace_commons_protocol::trace_contribution::{
    NoopPrivacyFilterAdapter, PiiClassifyPolicy, ResidualPiiRisk, ResidualRiskCondition,
    TraceContributionEnvelope,
};

pub const MINIMAL_PIPELINE_BUNDLE_LABEL: &str = "minimal-local-v1";
pub const PIPELINE_OPERATIONAL_ERROR_LABEL: &str = "minimal_policy_failed";
pub const PIPELINE_ATTEMPTS_EXHAUSTED_LABEL: &str = "attempts_exhausted";
pub const PIPELINE_BUNDLE_MISSING_LABEL: &str = "bundle_package_missing";
pub const PIPELINE_BUNDLE_INVALID_LABEL: &str = "bundle_package_invalid";
pub const PIPELINE_POLICY_NOT_RUNNABLE_LABEL: &str = "bundle_policy_not_runnable";
pub const PIPELINE_INDEX_UNAVAILABLE_LABEL: &str = "index_unavailable";
pub const PIPELINE_INDEX_CONFLICT_LABEL: &str = "index_key_conflict";
pub const PIPELINE_CREDIT_HELD_LABEL: &str = "credit_held";
pub const PIPELINE_CREDIT_CAP_LABEL: &str = "credit_cap_exceeded";
pub const PIPELINE_SUBMISSION_INOPERABLE_LABEL: &str = "submission_inoperable";
pub const PIPELINE_TOMBSTONE_LABEL: &str = "content_tombstoned";
pub const PIPELINE_INVALIDATION_FAILED_LABEL: &str = "index_invalidation_failed";
const DEFAULT_LEASE_SECONDS: i64 = 30;
const DEFAULT_RETRY_MILLISECONDS: i64 = 50;
const INJECTED_PIPELINE_CRASH: &str = "injected_pipeline_crash";
pub const PIPELINE_FIXED_POSITIVE_MICROCREDITS: u64 = 1_000_000;
pub const AUTHORITY_ADMISSION_IMPLEMENTATION: &str = "trace_commons.admission.authority_privacy.v1";
pub const AUTHORITY_REVIEW_IMPLEMENTATION: &str = "trace_commons.review.authority_privacy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineCrashPoint {
    AfterArtifactStorage,
    AfterAdmissionWork,
    AfterReviewWork,
    AfterReviewCommit,
    AfterScoreWork,
    AfterScoreCommit,
    AfterIndexCommandStorage,
    AfterIndexApply,
    AfterInternalSettlement,
    AfterSettleCommit,
    AfterNearSubmit,
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn trace_credit_awards(microcredits: Microcredits) -> anyhow::Result<InstrumentAwards> {
    if microcredits == Microcredits::ZERO {
        return InstrumentAwards::new(Vec::new()).map_err(Into::into);
    }
    InstrumentAwards::new(vec![InstrumentAward::trace_credit(microcredits)?]).map_err(Into::into)
}

fn settlement_operations(run_id: Uuid, awards: &InstrumentAwards) -> Vec<InstrumentSettlement> {
    awards
        .iter()
        .map(|award| {
            let instrument = award.instrument_id().as_str();
            InstrumentSettlement::new(
                award.instrument_id().clone(),
                award.atomic_units(),
                sha256_prefixed(
                    format!(
                        "pipeline-operation-v1:{run_id}:{instrument}:{}",
                        award.atomic_units().get()
                    )
                    .as_bytes(),
                ),
                sha256_prefixed(
                    format!(
                        "pipeline-result-v1:{run_id}:{instrument}:{}",
                        award.atomic_units().get()
                    )
                    .as_bytes(),
                ),
            )
            .expect("award identity and static hashes are valid")
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineRunState {
    Pending,
    Leased,
    Retry,
    Complete,
    Failed,
}

impl PipelineRunState {
    fn as_db(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Retry => "retry",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self, DatabaseError> {
        match value {
            "pending" => Ok(Self::Pending),
            "leased" => Ok(Self::Leased),
            "retry" => Ok(Self::Retry),
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            _ => Err(DatabaseError::Serialization(
                "unknown pipeline run state".to_string(),
            )),
        }
    }
}

fn phase_as_db(phase: Option<Phase>) -> &'static str {
    match phase {
        Some(Phase::Admission) => "admission",
        Some(Phase::Review) => "review",
        Some(Phase::Score) => "score",
        Some(Phase::Settle) => "settle",
        None => "none",
    }
}

pub(crate) fn phase_from_db(value: &str) -> Result<Option<Phase>, DatabaseError> {
    match value {
        "admission" => Ok(Some(Phase::Admission)),
        "review" => Ok(Some(Phase::Review)),
        "score" => Ok(Some(Phase::Score)),
        "settle" => Ok(Some(Phase::Settle)),
        "none" => Ok(None),
        _ => Err(DatabaseError::Serialization(
            "unknown pipeline phase".to_string(),
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineRunRecord {
    #[serde(skip_serializing, default)]
    pub tenant_id: String,
    pub run_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub bundle_id: String,
    pub request_idempotency_key: String,
    pub request_content_hash: String,
    pub source_object_ref_id: Uuid,
    pub approved_revision_id: Option<Uuid>,
    pub next_phase: Option<Phase>,
    pub state: PipelineRunState,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub attempt_count: u32,
    pub max_attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    pub phase_started_at: DateTime<Utc>,
    pub last_error_label: Option<String>,
    pub index_membership: String,
    pub index_command_ref: Option<String>,
    pub index_command_hash: Option<String>,
    pub index_write_state: String,
    pub index_invalidation_state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineWithdrawalFollowUpState {
    NotRequired,
    Pending,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineWithdrawalOutcome {
    pub withdrawal: crate::trace_corpus_storage::TraceWithdrawalRecord,
    pub index_invalidation: PipelineWithdrawalFollowUpState,
    pub revocation_propagation: PipelineWithdrawalFollowUpState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PhaseOutcomeRecord {
    #[serde(skip_serializing, default)]
    pub tenant_id: String,
    pub outcome_id: Uuid,
    pub run_id: Uuid,
    pub trace_id: Uuid,
    pub phase: Phase,
    pub bundle_id: String,
    pub outcome_schema: SchemaRef,
    pub decision: serde_json::Value,
    pub evidence: serde_json::Value,
    pub evaluation: serde_json::Value,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineSettlementRecord {
    #[serde(skip_serializing, default)]
    pub tenant_id: String,
    pub run_id: Uuid,
    pub instrument_id: String,
    pub atomic_units: u64,
    pub operation_ref_hash: String,
    pub result_ref_hash: Option<String>,
    pub operation_state: String,
    pub credit_event_id: Option<Uuid>,
    pub settlement_batch_id: Option<Uuid>,
    pub payout_rail: String,
    pub payout_state: String,
    pub attempt_count: u32,
    pub max_attempts: u32,
    pub last_error_label: Option<String>,
}

enum InternalCreditResult {
    Complete {
        credit_event_id: Uuid,
        settlement_batch_id: Uuid,
    },
    Held,
}

struct SettlementUpdate<'a> {
    operation_state: &'a str,
    result_ref_hash: Option<&'a str>,
    credit_event_id: Option<Uuid>,
    settlement_batch_id: Option<Uuid>,
    payout_state: Option<&'a str>,
    error_label: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineBundleConfig {
    #[serde(default)]
    pub score_microcredits: u64,
    #[serde(default)]
    pub instrument_awards: Vec<PipelineInstrumentAwardConfig>,
    pub include_index: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<CompatibilityBundleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineInstrumentAwardConfig {
    pub instrument_id: String,
    pub atomic_units: u64,
}

impl PipelineBundleConfig {
    pub fn minimal() -> Self {
        Self {
            score_microcredits: 0,
            instrument_awards: Vec::new(),
            include_index: false,
            compatibility: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewPipelineRun {
    pub tenant_id: String,
    pub run_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub bundle_id: String,
    pub request_idempotency_key: String,
    pub request_content_hash: String,
    pub source_object_ref_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineReceiptArtifactRecord {
    #[serde(skip_serializing, default)]
    pub tenant_id: String,
    pub run_id: Uuid,
    pub request_idempotency_key: String,
    pub request_content_hash: String,
    pub object_key: Option<String>,
    pub ciphertext_sha256: Option<String>,
    pub cleanup_after: DateTime<Utc>,
    pub staged_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineLeaseClaim {
    pub tenant_id: String,
    pub run_id: Uuid,
    pub lease_token: Uuid,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PipelineReceiptResult {
    Created(PipelineRunRecord),
    Replayed(PipelineRunRecord),
    ContentConflict,
}

#[derive(Debug, Clone)]
pub struct StoredPhaseResult {
    pub phase: Phase,
    pub decision: serde_json::Value,
    pub evidence: serde_json::Value,
    pub evaluation: serde_json::Value,
}

impl StoredPhaseResult {
    pub fn from_result<D, E, V>(
        phase: Phase,
        result: &PhaseResult<D, E, V>,
    ) -> Result<Self, DatabaseError>
    where
        D: Serialize,
        E: Serialize,
        V: Serialize,
    {
        Ok(Self {
            phase,
            decision: serde_json::to_value(&result.decision)
                .map_err(|_| DatabaseError::Serialization("decision encode failed".to_string()))?,
            evidence: serde_json::to_value(&result.evidence)
                .map_err(|_| DatabaseError::Serialization("evidence encode failed".to_string()))?,
            evaluation: serde_json::to_value(&result.evaluation).map_err(|_| {
                DatabaseError::Serialization("evaluation encode failed".to_string())
            })?,
        })
    }
}

pub struct PgPipelineStore {
    backend: Arc<PgBackend>,
}

impl PgPipelineStore {
    pub fn new(backend: Arc<PgBackend>) -> Self {
        Self { backend }
    }

    async fn tenant_transaction<'a>(
        client: &'a mut deadpool_postgres::Client,
        tenant_id: &str,
    ) -> Result<Transaction<'a>, DatabaseError> {
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
        Ok(tx)
    }

    pub async fn register_bundle(
        &self,
        tenant_id: &str,
        package: &BundlePackage,
    ) -> Result<(), DatabaseError> {
        package
            .validate()
            .map_err(|_| DatabaseError::Serialization(PIPELINE_BUNDLE_INVALID_LABEL.to_string()))?;
        let package_json = serde_json::to_value(package)
            .map_err(|_| DatabaseError::Serialization(PIPELINE_BUNDLE_INVALID_LABEL.to_string()))?;
        let format_version = i32::try_from(package.manifest.format_version)
            .map_err(|_| DatabaseError::Serialization(PIPELINE_BUNDLE_INVALID_LABEL.to_string()))?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_tenants (tenant_id) VALUES ($1)
             ON CONFLICT (tenant_id) DO NOTHING",
            &[&tenant_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO pipeline_bundle_packages (
                tenant_id, bundle_id, manifest_format_version, package
             ) VALUES ($1,$2,$3,$4)
             ON CONFLICT (tenant_id, bundle_id) DO NOTHING",
            &[
                &tenant_id,
                &package.bundle_id,
                &format_version,
                &package_json,
            ],
        )
        .await?;
        let stored: serde_json::Value = tx
            .query_one(
                "SELECT package FROM pipeline_bundle_packages
                 WHERE tenant_id = $1 AND bundle_id = $2",
                &[&tenant_id, &package.bundle_id],
            )
            .await?
            .get("package");
        if stored != package_json {
            return Err(DatabaseError::Constraint(
                "bundle identifier already has different package bytes".to_string(),
            ));
        }
        for phase in [Phase::Admission, Phase::Review, Phase::Score, Phase::Settle] {
            tx.execute(
                "INSERT INTO pipeline_bundle_policy_status (
                    tenant_id, bundle_id, phase, runnable
                 ) VALUES ($1,$2,$3,TRUE)
                 ON CONFLICT (tenant_id, bundle_id, phase) DO NOTHING",
                &[&tenant_id, &package.bundle_id, &phase_as_db(Some(phase))],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn activate_bundle(
        &self,
        tenant_id: &str,
        bundle_id: &str,
    ) -> Result<(), DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let row_count = tx
            .execute(
                "INSERT INTO pipeline_active_bundles (tenant_id, bundle_id)
                 SELECT $1, bundle_id
                 FROM pipeline_bundle_packages
                 WHERE tenant_id = $1 AND bundle_id = $2
                 ON CONFLICT (tenant_id) DO UPDATE
                 SET bundle_id = EXCLUDED.bundle_id, selected_at = NOW()",
                &[&tenant_id, &bundle_id],
            )
            .await?;
        if row_count != 1 {
            return Err(DatabaseError::NotFound {
                entity: "pipeline_bundle".to_string(),
                id: bundle_id.to_string(),
            });
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn activate_bundle_if_none(
        &self,
        tenant_id: &str,
        bundle_id: &str,
    ) -> Result<(), DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO pipeline_active_bundles (tenant_id, bundle_id)
             SELECT $1, bundle_id
             FROM pipeline_bundle_packages
             WHERE tenant_id = $1 AND bundle_id = $2
             ON CONFLICT (tenant_id) DO NOTHING",
            &[&tenant_id, &bundle_id],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn active_bundle_id(&self, tenant_id: &str) -> Result<Option<String>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT bundle_id FROM pipeline_active_bundles WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await?;
        tx.commit().await?;
        Ok(row.map(|row| row.get("bundle_id")))
    }

    pub async fn load_bundle(
        &self,
        tenant_id: &str,
        bundle_id: &str,
    ) -> Result<Option<BundlePackage>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let package = load_bundle_from_transaction(&tx, tenant_id, bundle_id).await?;
        tx.commit().await?;
        Ok(package)
    }

    pub async fn policy_is_runnable(
        &self,
        tenant_id: &str,
        bundle_id: &str,
        phase: Phase,
    ) -> Result<bool, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let runnable = tx
            .query_opt(
                "SELECT runnable FROM pipeline_bundle_policy_status
                 WHERE tenant_id = $1 AND bundle_id = $2 AND phase = $3",
                &[&tenant_id, &bundle_id, &phase_as_db(Some(phase))],
            )
            .await?
            .map(|row| row.get("runnable"))
            .unwrap_or(false);
        tx.commit().await?;
        Ok(runnable)
    }

    async fn stage_receipt_artifact(
        tx: &Transaction<'_>,
        run: &NewPipelineRun,
        receipt: Option<&EncryptedTraceArtifactReceipt>,
    ) -> Result<(), DatabaseError> {
        let object_key = receipt.map(|value| value.object_key.as_str());
        let ciphertext_sha256 = receipt.map(|value| value.ciphertext_sha256.as_str());
        tx.execute(
            "INSERT INTO pipeline_receipt_artifacts (
                tenant_id, run_id, request_idempotency_key, request_content_hash,
                object_key, ciphertext_sha256
             ) VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (tenant_id, run_id) DO UPDATE
             SET object_key = COALESCE(EXCLUDED.object_key, pipeline_receipt_artifacts.object_key),
                 ciphertext_sha256 = COALESCE(
                    EXCLUDED.ciphertext_sha256,
                    pipeline_receipt_artifacts.ciphertext_sha256
                 )",
            &[
                &run.tenant_id,
                &run.run_id,
                &run.request_idempotency_key,
                &run.request_content_hash,
                &object_key,
                &ciphertext_sha256,
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn withdraw_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
    ) -> Result<PipelineWithdrawalOutcome, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let submission = tx
            .query_opt(
                "SELECT status, auth_principal_ref, trace_id, redaction_hash,
                        canonical_summary_hash
                   FROM trace_submissions
                  WHERE tenant_id = $1 AND submission_id = $2
                  FOR UPDATE",
                &[&tenant_id, &submission_id],
            )
            .await?
            .ok_or_else(|| DatabaseError::NotFound {
                entity: "trace_submission".to_string(),
                id: submission_id.to_string(),
            })?;
        if submission.get::<_, String>("auth_principal_ref") != actor_principal_ref {
            return Err(DatabaseError::NotFound {
                entity: "trace_submission".to_string(),
                id: submission_id.to_string(),
            });
        }

        let run_row = tx
            .query_opt(
                "SELECT *
                   FROM pipeline_runs
                  WHERE tenant_id = $1 AND submission_id = $2
                  ORDER BY created_at DESC
                  LIMIT 1
                  FOR UPDATE",
                &[&tenant_id, &submission_id],
            )
            .await?;
        let prior_status: String = submission.get("status");
        let trace_id: Uuid = submission.get("trace_id");
        let redaction_hash: String = submission.get("redaction_hash");
        let canonical_summary_hash: Option<String> = submission.get("canonical_summary_hash");
        let object_rows = tx
            .query(
                "SELECT object_ref_id
                   FROM trace_object_refs
                  WHERE tenant_id = $1 AND submission_id = $2
                    AND deleted_at IS NULL
                  ORDER BY object_ref_id",
                &[&tenant_id, &submission_id],
            )
            .await?;
        let has_managed_export = tx
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                      FROM trace_export_manifest_items
                     WHERE tenant_id = $1 AND submission_id = $2
                       AND source_invalidated_at IS NULL
                ) AS present",
                &[&tenant_id, &submission_id],
            )
            .await?
            .get::<_, bool>("present");
        let has_approved_revision = run_row
            .as_ref()
            .and_then(|row| row.get::<_, Option<Uuid>>("approved_revision_id"))
            .is_some();
        let distribution_reach = if has_managed_export {
            "commons_distributed"
        } else if has_approved_revision {
            "commons_not_distributed"
        } else {
            "not_distributed"
        };

        tx.execute(
            "INSERT INTO trace_withdrawals (
                tenant_id, submission_id, withdrawn_at, prior_status, distribution_reach
             ) VALUES ($1,$2,NOW(),$3,$4)
             ON CONFLICT (tenant_id, submission_id) DO NOTHING",
            &[
                &tenant_id,
                &submission_id,
                &prior_status,
                &distribution_reach,
            ],
        )
        .await?;
        let tombstone_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("pipeline-withdrawal:{tenant_id}:{submission_id}").as_bytes(),
        );
        tx.execute(
            "INSERT INTO trace_tombstones (
                tenant_id, tombstone_id, submission_id, trace_id, redaction_hash,
                canonical_summary_hash, reason, effective_at, created_by_principal_ref
             ) VALUES ($1,$2,$3,$4,$5,$6,'withdrawn',NOW(),$7)
             ON CONFLICT (tenant_id, submission_id) DO NOTHING",
            &[
                &tenant_id,
                &tombstone_id,
                &submission_id,
                &trace_id,
                &redaction_hash,
                &canonical_summary_hash,
                &actor_principal_ref,
            ],
        )
        .await?;
        tx.execute(
            "UPDATE trace_submissions
                SET status = 'revoked',
                    withdrawn_at = COALESCE(withdrawn_at, NOW()),
                    revoked_at = COALESCE(revoked_at, NOW()),
                    updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE trace_object_refs
                SET invalidated_at = COALESCE(invalidated_at, NOW()), updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2 AND invalidated_at IS NULL",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE trace_derived_records
                SET status = 'revoked', updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2 AND status <> 'revoked'",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE trace_vector_entries
                SET status = 'invalidated',
                    invalidated_at = COALESCE(invalidated_at, NOW()), updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2
                AND status <> 'invalidated' AND deleted_at IS NULL",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE trace_export_manifest_items
                SET source_invalidated_at = COALESCE(source_invalidated_at, NOW()),
                    source_invalidation_reason = 'revoked', updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2
                AND source_invalidated_at IS NULL",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE trace_export_manifests
                SET invalidated_at = COALESCE(invalidated_at, NOW()), updated_at = NOW()
              WHERE tenant_id = $1 AND $2 = ANY(source_submission_ids)
                AND invalidated_at IS NULL AND deleted_at IS NULL",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE pipeline_export_snapshot_items
                SET invalidated_at = COALESCE(invalidated_at, NOW()),
                    invalidation_reason = 'withdrawn'
              WHERE tenant_id = $1 AND submission_id = $2
                AND invalidated_at IS NULL",
            &[&tenant_id, &submission_id],
        )
        .await?;
        tx.execute(
            "UPDATE pipeline_export_snapshots snapshot
                SET state = 'invalidated',
                    invalidated_at = COALESCE(snapshot.invalidated_at, NOW())
              WHERE snapshot.tenant_id = $1
                AND snapshot.state <> 'invalidated'
                AND EXISTS (
                    SELECT 1
                      FROM pipeline_export_snapshot_items item
                     WHERE item.tenant_id = snapshot.tenant_id
                       AND item.snapshot_id = snapshot.snapshot_id
                       AND item.submission_id = $2
                )",
            &[&tenant_id, &submission_id],
        )
        .await?;

        let mut index_invalidation = PipelineWithdrawalFollowUpState::NotRequired;
        if let Some(run_row) = run_row.as_ref() {
            let run = pipeline_run_from_row(run_row)?;
            if run.index_write_state == "complete" {
                if let Some(revision_id) = run.approved_revision_id {
                    tx.execute(
                        "INSERT INTO pipeline_index_invalidations (
                            tenant_id, run_id, submission_id, registry_revision_id, reason_code
                         ) VALUES ($1,$2,$3,$4,'withdrawn')
                         ON CONFLICT (tenant_id, run_id) DO NOTHING",
                        &[&tenant_id, &run.run_id, &submission_id, &revision_id],
                    )
                    .await?;
                    tx.execute(
                        "UPDATE pipeline_runs
                            SET index_invalidation_state = 'pending', updated_at = NOW()
                          WHERE tenant_id = $1 AND run_id = $2
                            AND index_invalidation_state = 'none'",
                        &[&tenant_id, &run.run_id],
                    )
                    .await?;
                    index_invalidation = PipelineWithdrawalFollowUpState::Pending;
                }
            } else if run.index_write_state == "pending" {
                tx.execute(
                    "UPDATE pipeline_runs
                        SET index_membership = 'excluded',
                            index_write_state = 'cancelled',
                            updated_at = NOW()
                      WHERE tenant_id = $1 AND run_id = $2",
                    &[&tenant_id, &run.run_id],
                )
                .await?;
                index_invalidation = PipelineWithdrawalFollowUpState::Complete;
            }
            if run.next_phase != Some(Phase::Settle)
                && run.state != PipelineRunState::Complete
                && run.state != PipelineRunState::Failed
            {
                tx.execute(
                    "UPDATE pipeline_runs
                        SET state = 'failed', last_error_label = $3,
                            lease_token = NULL, lease_expires_at = NULL, updated_at = NOW()
                      WHERE tenant_id = $1 AND run_id = $2",
                    &[
                        &tenant_id,
                        &run.run_id,
                        &PIPELINE_SUBMISSION_INOPERABLE_LABEL,
                    ],
                )
                .await?;
            }
        }

        for row in &object_rows {
            let object_ref_id: Uuid = row.get("object_ref_id");
            let idempotency_key = sha256_prefixed(
                format!(
                    "pipeline-withdrawal-object-delete:v1:{tenant_id}:{submission_id}:{object_ref_id}"
                )
                .as_bytes(),
            );
            let propagation_item_id =
                Uuid::new_v5(&Uuid::NAMESPACE_URL, idempotency_key.as_bytes());
            let target_json = serde_json::json!({
                "kind": "object_ref",
                "object_ref_id": object_ref_id,
            });
            let metadata_json = serde_json::json!({"source": "versioned_pipeline"});
            tx.execute(
                "INSERT INTO trace_revocation_propagation_items (
                    tenant_id, propagation_item_id, source_submission_id, trace_id,
                    target_kind, target_json, action, status, idempotency_key, reason,
                    attempt_count, metadata_json
                 ) VALUES (
                    $1,$2,$3,$4,'object_ref',$5,'delete_object_payload','pending',$6,
                    'pipeline_withdrawal',0,$7
                 )
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
                &[
                    &tenant_id,
                    &propagation_item_id,
                    &submission_id,
                    &trace_id,
                    &target_json,
                    &idempotency_key,
                    &metadata_json,
                ],
            )
            .await?;
        }

        let audit_event_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("pipeline-withdrawal-audit:{tenant_id}:{submission_id}").as_bytes(),
        );
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
            &[&tenant_id],
        )
        .await?;
        let audit_exists = tx
            .query_opt(
                "SELECT 1
                   FROM trace_audit_events
                  WHERE tenant_id = $1 AND audit_event_id = $2",
                &[&tenant_id, &audit_event_id],
            )
            .await?
            .is_some();
        if !audit_exists {
            let audit_sequence: i64 = tx
                .query_one(
                    "SELECT COALESCE(MAX(audit_sequence), 0) + 1
                       FROM trace_audit_events
                      WHERE tenant_id = $1",
                    &[&tenant_id],
                )
                .await?
                .get(0);
            let reason_hash = sha256_prefixed(b"pipeline_withdrawal");
            let metadata_json =
                serde_json::json!({"kind": "revocation", "reason_hash": reason_hash});
            tx.execute(
                "INSERT INTO trace_audit_events (
                    tenant_id, audit_sequence, audit_event_id, actor_principal_ref,
                    actor_role, action, reason, submission_id, decision_inputs_hash,
                    metadata_json
                 ) VALUES (
                    $1,$2,$3,$4,'contributor','revoke','pipeline_withdrawal',$5,$6,$7
                 )",
                &[
                    &tenant_id,
                    &audit_sequence,
                    &audit_event_id,
                    &actor_principal_ref,
                    &submission_id,
                    &reason_hash,
                    &metadata_json,
                ],
            )
            .await?;
        }

        let withdrawal_row = tx
            .query_one(
                "SELECT tenant_id, submission_id, withdrawn_at, prior_status, distribution_reach
                   FROM trace_withdrawals
                  WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await?;
        let pending_propagation: i64 = tx
            .query_one(
                "SELECT COUNT(*)::bigint
                   FROM trace_revocation_propagation_items
                  WHERE tenant_id = $1 AND source_submission_id = $2
                    AND status IN ('pending', 'in_progress', 'failed')",
                &[&tenant_id, &submission_id],
            )
            .await?
            .get(0);
        let revocation_propagation = if pending_propagation > 0 {
            PipelineWithdrawalFollowUpState::Pending
        } else if object_rows.is_empty() {
            PipelineWithdrawalFollowUpState::NotRequired
        } else {
            PipelineWithdrawalFollowUpState::Complete
        };
        if run_row.is_some() {
            let state: String = tx
                .query_one(
                    "SELECT index_invalidation_state
                       FROM pipeline_runs
                      WHERE tenant_id = $1 AND submission_id = $2
                      ORDER BY created_at DESC
                      LIMIT 1",
                    &[&tenant_id, &submission_id],
                )
                .await?
                .get("index_invalidation_state");
            index_invalidation = match state.as_str() {
                "pending" => PipelineWithdrawalFollowUpState::Pending,
                "complete" => PipelineWithdrawalFollowUpState::Complete,
                "failed" => PipelineWithdrawalFollowUpState::Failed,
                _ => index_invalidation,
            };
        }
        let withdrawal = crate::trace_corpus_storage::TraceWithdrawalRecord {
            tenant_id: withdrawal_row.get("tenant_id"),
            submission_id: withdrawal_row.get("submission_id"),
            withdrawn_at: withdrawal_row.get("withdrawn_at"),
            prior_status: withdrawal_row.get("prior_status"),
            distribution_reach: withdrawal_row.get("distribution_reach"),
        };
        tx.commit().await?;
        Ok(PipelineWithdrawalOutcome {
            withdrawal,
            index_invalidation,
            revocation_propagation,
        })
    }

    pub async fn complete_index_invalidation(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "UPDATE pipeline_index_invalidations
                SET state = 'complete', completed_at = COALESCE(completed_at, NOW()),
                    last_error_label = NULL
              WHERE tenant_id = $1 AND run_id = $2",
            &[&tenant_id, &run_id],
        )
        .await?;
        let row = tx
            .query_one(
                "UPDATE pipeline_runs
                    SET index_invalidation_state = 'complete', updated_at = NOW()
                  WHERE tenant_id = $1 AND run_id = $2
                  RETURNING *",
                &[&tenant_id, &run_id],
            )
            .await?;
        let run = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(run)
    }

    pub async fn claim_index_invalidation(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let claimed = tx
            .execute(
                "UPDATE pipeline_index_invalidations
                    SET attempt_count = attempt_count + 1
                  WHERE tenant_id = $1 AND run_id = $2
                    AND state = 'pending'
                    AND next_attempt_at <= NOW()
                    AND attempt_count < max_attempts",
                &[&tenant_id, &run_id],
            )
            .await?;
        let run = if claimed == 1 {
            tx.query_opt(
                "SELECT * FROM pipeline_runs WHERE tenant_id = $1 AND run_id = $2",
                &[&tenant_id, &run_id],
            )
            .await?
            .as_ref()
            .map(pipeline_run_from_row)
            .transpose()?
        } else {
            None
        };
        tx.commit().await?;
        Ok(run)
    }

    pub async fn fail_index_invalidation(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_one(
                "UPDATE pipeline_index_invalidations
                    SET state = CASE
                            WHEN attempt_count >= max_attempts THEN 'failed'
                            ELSE 'pending'
                        END,
                        last_error_label = $3,
                        next_attempt_at = CASE
                            WHEN attempt_count >= max_attempts THEN next_attempt_at
                            ELSE NOW() + INTERVAL '50 milliseconds'
                        END
                  WHERE tenant_id = $1 AND run_id = $2
                  RETURNING state",
                &[&tenant_id, &run_id, &PIPELINE_INVALIDATION_FAILED_LABEL],
            )
            .await?;
        let terminal = row.get::<_, String>("state") == "failed";
        let row = tx
            .query_one(
                "UPDATE pipeline_runs
                    SET index_invalidation_state = $3, updated_at = NOW()
                  WHERE tenant_id = $1 AND run_id = $2
                  RETURNING *",
                &[
                    &tenant_id,
                    &run_id,
                    &(if terminal { "failed" } else { "pending" }),
                ],
            )
            .await?;
        let run = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(run)
    }

    pub async fn list_cleanup_orphans(
        &self,
        tenant_id: &str,
        before: DateTime<Utc>,
    ) -> Result<Vec<PipelineReceiptArtifactRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT tenant_id, run_id, request_idempotency_key, request_content_hash,
                        object_key, ciphertext_sha256, cleanup_after, staged_at
                 FROM pipeline_receipt_artifacts
                 WHERE tenant_id = $1 AND state = 'staged' AND cleanup_after <= $2
                 ORDER BY staged_at ASC",
                &[&tenant_id, &before],
            )
            .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|row| PipelineReceiptArtifactRecord {
                tenant_id: row.get("tenant_id"),
                run_id: row.get("run_id"),
                request_idempotency_key: row.get("request_idempotency_key"),
                request_content_hash: row.get("request_content_hash"),
                object_key: row.get("object_key"),
                ciphertext_sha256: row.get("ciphertext_sha256"),
                cleanup_after: row.get("cleanup_after"),
                staged_at: row.get("staged_at"),
            })
            .collect())
    }

    pub async fn get_run(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT * FROM pipeline_runs WHERE tenant_id = $1 AND run_id = $2",
                &[&tenant_id, &run_id],
            )
            .await?;
        tx.commit().await?;
        row.as_ref().map(pipeline_run_from_row).transpose()
    }

    pub async fn get_run_by_request_key(
        &self,
        tenant_id: &str,
        request_idempotency_key: &str,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT * FROM pipeline_runs
                 WHERE tenant_id = $1 AND request_idempotency_key = $2",
                &[&tenant_id, &request_idempotency_key],
            )
            .await?;
        tx.commit().await?;
        row.as_ref().map(pipeline_run_from_row).transpose()
    }

    pub async fn list_outcomes(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<Vec<PhaseOutcomeRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT * FROM phase_outcomes
                 WHERE tenant_id = $1 AND run_id = $2
                 ORDER BY CASE phase
                    WHEN 'admission' THEN 1
                    WHEN 'review' THEN 2
                    WHEN 'score' THEN 3
                    WHEN 'settle' THEN 4
                 END",
                &[&tenant_id, &run_id],
            )
            .await?;
        tx.commit().await?;
        rows.iter().map(phase_outcome_from_row).collect()
    }

    pub async fn claim_next(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        self.claim_next_with_lease(tenant_id, Duration::seconds(DEFAULT_LEASE_SECONDS))
            .await
    }

    pub async fn claim_next_with_lease(
        &self,
        tenant_id: &str,
        lease_duration: Duration,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        if lease_duration <= Duration::zero() || lease_duration > Duration::minutes(5) {
            return Err(DatabaseError::Constraint(
                "pipeline lease duration is invalid".to_string(),
            ));
        }
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "UPDATE pipeline_runs
             SET state = 'failed', lease_token = NULL, lease_expires_at = NULL,
                 last_error_label = $2, updated_at = NOW()
             WHERE tenant_id = $1
               AND state = 'leased'
               AND lease_expires_at <= NOW()
               AND attempt_count >= max_attempts",
            &[&tenant_id, &PIPELINE_ATTEMPTS_EXHAUSTED_LABEL],
        )
        .await?;
        let lease_token = Uuid::new_v4();
        let lease_milliseconds = lease_duration.num_milliseconds();
        let row = tx
            .query_opt(
                "WITH candidate AS (
                    SELECT run_id FROM pipeline_runs
                    WHERE tenant_id = $1
                      AND next_phase <> 'none'
                      AND attempt_count < max_attempts
                      AND (
                          (state IN ('pending', 'retry') AND next_attempt_at <= NOW())
                          OR (state = 'leased' AND lease_expires_at <= NOW())
                      )
                    ORDER BY next_attempt_at ASC, created_at ASC, run_id ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                 )
                 UPDATE pipeline_runs p
                 SET state = 'leased',
                     lease_token = $2,
                     lease_expires_at = NOW() + ($3::bigint * INTERVAL '1 millisecond'),
                     attempt_count = p.attempt_count + 1,
                     last_error_label = NULL,
                     updated_at = NOW()
                 FROM candidate
                 WHERE p.tenant_id = $1 AND p.run_id = candidate.run_id
                 RETURNING p.*",
                &[&tenant_id, &lease_token, &lease_milliseconds],
            )
            .await?;
        tx.commit().await?;
        row.as_ref().map(pipeline_run_from_row).transpose()
    }

    pub async fn claim_run(
        &self,
        tenant_id: &str,
        run_id: Uuid,
        lease_duration: Duration,
    ) -> Result<Option<PipelineRunRecord>, DatabaseError> {
        if lease_duration <= Duration::zero() || lease_duration > Duration::minutes(5) {
            return Err(DatabaseError::Constraint(
                "pipeline lease duration is invalid".to_string(),
            ));
        }
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let lease_token = Uuid::new_v4();
        let lease_milliseconds = lease_duration.num_milliseconds();
        let row = tx
            .query_opt(
                "UPDATE pipeline_runs
                 SET state = 'leased',
                     lease_token = $3,
                     lease_expires_at = NOW() + ($4::bigint * INTERVAL '1 millisecond'),
                     attempt_count = attempt_count + 1,
                     last_error_label = NULL,
                     updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND next_phase <> 'none'
                   AND attempt_count < max_attempts
                   AND (
                       (state IN ('pending', 'retry') AND next_attempt_at <= NOW())
                       OR (state = 'leased' AND lease_expires_at <= NOW())
                   )
                 RETURNING *",
                &[&tenant_id, &run_id, &lease_token, &lease_milliseconds],
            )
            .await?;
        tx.commit().await?;
        row.as_ref().map(pipeline_run_from_row).transpose()
    }

    pub async fn claim_next_cross_tenant(
        &self,
        lease_duration: Duration,
    ) -> Result<Option<PipelineLeaseClaim>, DatabaseError> {
        if lease_duration <= Duration::zero() || lease_duration > Duration::minutes(5) {
            return Err(DatabaseError::Constraint(
                "pipeline lease duration is invalid".to_string(),
            ));
        }
        let lease_seconds = i32::try_from(lease_duration.num_seconds())
            .map_err(|_| DatabaseError::Constraint("pipeline lease duration is invalid".into()))?;
        let lease_token = Uuid::new_v4();
        let client = self.backend.trace_pool().get().await?;
        let row = client
            .query_opt(
                "SELECT tenant_id, run_id, lease_token, lease_expires_at
                 FROM claim_pipeline_run($1, $2)",
                &[&lease_token, &lease_seconds],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(PipelineLeaseClaim {
            tenant_id: row.get("tenant_id"),
            run_id: row.get("run_id"),
            lease_token: row.get("lease_token"),
            lease_expires_at: row.get("lease_expires_at"),
        }))
    }

    pub async fn release_claim(&self, run: &PipelineRunRecord) -> Result<(), DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let updated = tx
            .execute(
                "UPDATE pipeline_runs
             SET state = 'pending', lease_token = NULL, lease_expires_at = NULL,
                 attempt_count = GREATEST(attempt_count - 1, 0), updated_at = NOW()
             WHERE tenant_id = $1 AND run_id = $2 AND state = 'leased'
               AND lease_token = $3 AND lease_expires_at > NOW()",
                &[&run.tenant_id, &run.run_id, &lease_token],
            )
            .await?;
        if updated != 1 {
            return Err(stale_lease_error());
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_phase(
        &self,
        run: &PipelineRunRecord,
        outcome: StoredPhaseResult,
        next_phase: Option<Phase>,
        approved_revision_id: Option<Uuid>,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        if run.next_phase != Some(outcome.phase) {
            return Err(DatabaseError::Constraint(
                "phase does not match run transition".to_string(),
            ));
        }
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let current = tx
            .query_opt(
                "SELECT * FROM pipeline_runs
                 WHERE tenant_id = $1 AND run_id = $2
                 FOR UPDATE",
                &[&run.tenant_id, &run.run_id],
            )
            .await?
            .ok_or_else(|| DatabaseError::NotFound {
                entity: "pipeline_run".to_string(),
                id: run.run_id.to_string(),
            })?;
        let current = pipeline_run_from_row(&current)?;
        if current.state != PipelineRunState::Leased
            || current.next_phase != Some(outcome.phase)
            || current.lease_token != Some(lease_token)
            || current
                .lease_expires_at
                .is_none_or(|expires_at| expires_at <= Utc::now())
        {
            return Err(stale_lease_error());
        }
        if outcome.phase == Phase::Review {
            let revision_id = approved_revision_id.ok_or_else(|| {
                DatabaseError::Constraint("approved Review requires a revision".to_string())
            })?;
            tx.execute(
                "INSERT INTO trace_derived_records (
                    tenant_id, derived_id, submission_id, trace_id, status,
                    worker_kind, worker_version, input_object_ref_id, input_hash,
                    output_object_ref_id, summary_model
                 ) VALUES ($1,$2,$3,$4,'current','summary',$5,$6,$7,$6,$5)
                 ON CONFLICT (tenant_id, derived_id) DO NOTHING",
                &[
                    &run.tenant_id,
                    &revision_id,
                    &run.submission_id,
                    &run.trace_id,
                    &MINIMAL_PIPELINE_BUNDLE_LABEL,
                    &run.source_object_ref_id,
                    &run.request_content_hash,
                ],
            )
            .await?;
            tx.execute(
                "UPDATE trace_submissions
                 SET status = 'accepted', reviewed_at = NOW(), updated_at = NOW()
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&run.tenant_id, &run.submission_id],
            )
            .await?;
        }
        insert_outcome(
            &tx,
            &run.tenant_id,
            run.run_id,
            run.trace_id,
            &run.bundle_id,
            Uuid::new_v4(),
            outcome,
        )
        .await?;
        let terminal = next_phase.is_none();
        let state = if terminal {
            PipelineRunState::Complete
        } else {
            PipelineRunState::Pending
        };
        let row = tx
            .query_one(
                "UPDATE pipeline_runs
                 SET next_phase = $3, state = $4,
                     approved_revision_id = COALESCE($5, approved_revision_id),
                     lease_token = NULL, lease_expires_at = NULL,
                     next_attempt_at = NOW(), phase_started_at = NOW(), updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND lease_token = $6 AND lease_expires_at > NOW()
                 RETURNING *",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &phase_as_db(next_phase),
                    &state.as_db(),
                    &approved_revision_id,
                    &lease_token,
                ],
            )
            .await?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn mark_failed(
        &self,
        run: &PipelineRunRecord,
        error_label: &str,
    ) -> Result<(), DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let updated = tx
            .execute(
                "UPDATE pipeline_runs
             SET state = 'failed', lease_token = NULL, lease_expires_at = NULL,
                 last_error_label = $3, updated_at = NOW()
             WHERE tenant_id = $1 AND run_id = $2 AND state = 'leased'
               AND lease_token = $4 AND lease_expires_at > NOW()",
                &[&run.tenant_id, &run.run_id, &error_label, &lease_token],
            )
            .await?;
        if updated != 1 {
            return Err(stale_lease_error());
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_retry(
        &self,
        run: &PipelineRunRecord,
        error_label: &str,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let exponent = run.attempt_count.saturating_sub(1).min(9);
        let multiplier = 1_i64 << exponent;
        let delay_milliseconds = DEFAULT_RETRY_MILLISECONDS.saturating_mul(multiplier);
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE pipeline_runs
                 SET state = CASE
                         WHEN attempt_count >= max_attempts THEN 'failed'
                         ELSE 'retry'
                     END,
                     lease_token = NULL,
                     lease_expires_at = NULL,
                     next_attempt_at = CASE
                         WHEN attempt_count >= max_attempts THEN next_attempt_at
                         ELSE NOW() + ($5::bigint * INTERVAL '1 millisecond')
                     END,
                     last_error_label = CASE
                         WHEN attempt_count >= max_attempts THEN $4
                         ELSE $3
                     END,
                     updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2 AND state = 'leased'
                   AND lease_token = $6 AND lease_expires_at > NOW()
                 RETURNING *",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &error_label,
                    &PIPELINE_ATTEMPTS_EXHAUSTED_LABEL,
                    &delay_milliseconds,
                    &lease_token,
                ],
            )
            .await?
            .ok_or_else(stale_lease_error)?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn commit_score(
        &self,
        run: &PipelineRunRecord,
        outcome: StoredPhaseResult,
        _score: &ScoreDecision,
        _actor_principal_ref: &str,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        if run.next_phase != Some(Phase::Score) || outcome.phase != Phase::Score {
            return Err(DatabaseError::Constraint(
                "phase does not match run transition".to_string(),
            ));
        }
        let lease_token = required_lease_token(run)?;
        let outcome_id = Uuid::new_v4();
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        ensure_current_lease(&tx, run, lease_token).await?;
        insert_outcome(
            &tx,
            &run.tenant_id,
            run.run_id,
            run.trace_id,
            &run.bundle_id,
            outcome_id,
            outcome,
        )
        .await?;
        let row = tx
            .query_one(
                "UPDATE pipeline_runs
                 SET next_phase = 'settle', state = 'pending',
                     lease_token = NULL, lease_expires_at = NULL,
                     next_attempt_at = NOW(), phase_started_at = NOW(), updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND lease_token = $3 AND lease_expires_at > NOW()
                 RETURNING *",
                &[&run.tenant_id, &run.run_id, &lease_token],
            )
            .await?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn seed_settlements(
        &self,
        run: &PipelineRunRecord,
        decision: &SettleDecision,
        payout_rails: &BTreeMap<String, String>,
    ) -> Result<Vec<PipelineSettlementRecord>, DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        ensure_current_lease(&tx, run, lease_token).await?;
        for operation in decision.settlement_operations() {
            let instrument_id = operation.instrument_id().as_str();
            let payout_rail = payout_rails
                .get(instrument_id)
                .ok_or_else(|| {
                    DatabaseError::Constraint(format!(
                        "settlement adapter missing for instrument {instrument_id}"
                    ))
                })?
                .as_str();
            let atomic_units = operation.atomic_units().get().to_string();
            let payout_state = if payout_rail == "none" {
                "disabled"
            } else {
                "pending"
            };
            tx.execute(
                "INSERT INTO pipeline_run_settlements (
                    tenant_id, run_id, instrument_id, atomic_units,
                    operation_ref_hash, result_ref_hash, payout_rail, payout_state
                 ) VALUES ($1,$2,$3,$4::TEXT::NUMERIC,$5,$6,$7,$8)
                 ON CONFLICT (tenant_id, run_id, instrument_id) DO NOTHING",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &instrument_id,
                    &atomic_units,
                    &operation.operation_ref_hash(),
                    &operation.result_ref_hash(),
                    &payout_rail,
                    &payout_state,
                ],
            )
            .await?;
            let stored = tx
                .query_one(
                    "SELECT atomic_units::TEXT AS atomic_units_text,
                            operation_ref_hash, result_ref_hash, payout_rail
                       FROM pipeline_run_settlements
                      WHERE tenant_id = $1 AND run_id = $2 AND instrument_id = $3",
                    &[&run.tenant_id, &run.run_id, &instrument_id],
                )
                .await?;
            let stored_units: String = stored.get("atomic_units_text");
            if stored_units != atomic_units
                || stored.get::<_, String>("operation_ref_hash") != operation.operation_ref_hash()
                || stored
                    .get::<_, Option<String>>("result_ref_hash")
                    .as_deref()
                    != Some(operation.result_ref_hash())
                || stored.get::<_, String>("payout_rail") != payout_rail
            {
                return Err(DatabaseError::Constraint(
                    "settlement operation identity conflict".to_string(),
                ));
            }
        }
        let rows = tx
            .query(
                "SELECT *, atomic_units::TEXT AS atomic_units_text
                   FROM pipeline_run_settlements
                  WHERE tenant_id = $1 AND run_id = $2
                  ORDER BY instrument_id",
                &[&run.tenant_id, &run.run_id],
            )
            .await?;
        tx.commit().await?;
        rows.iter().map(pipeline_settlement_from_row).collect()
    }

    pub async fn list_settlements(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> Result<Vec<PipelineSettlementRecord>, DatabaseError> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT *, atomic_units::TEXT AS atomic_units_text
                   FROM pipeline_run_settlements
                  WHERE tenant_id = $1 AND run_id = $2
                  ORDER BY instrument_id",
                &[&tenant_id, &run_id],
            )
            .await?;
        tx.commit().await?;
        rows.iter().map(pipeline_settlement_from_row).collect()
    }

    async fn update_settlement(
        &self,
        run: &PipelineRunRecord,
        instrument_id: &str,
        update: SettlementUpdate<'_>,
    ) -> Result<PipelineSettlementRecord, DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE pipeline_run_settlements s
                    SET operation_state = $4,
                        result_ref_hash = COALESCE(s.result_ref_hash, $5),
                        credit_event_id = COALESCE(s.credit_event_id, $6),
                        settlement_batch_id = COALESCE(s.settlement_batch_id, $7),
                        payout_state = COALESCE($8, s.payout_state),
                        last_error_label = $9,
                        attempt_count = CASE
                            WHEN $4 IN ('retry', 'failed') THEN s.attempt_count + 1
                            ELSE s.attempt_count
                        END,
                        next_attempt_at = CASE
                            WHEN $4 = 'retry' THEN NOW() + INTERVAL '50 milliseconds'
                            ELSE s.next_attempt_at
                        END,
                        updated_at = NOW()
                   FROM pipeline_runs p
                  WHERE s.tenant_id = $1 AND s.run_id = $2 AND s.instrument_id = $3
                    AND p.tenant_id = s.tenant_id AND p.run_id = s.run_id
                    AND p.state = 'leased' AND p.lease_token = $10
                    AND p.lease_expires_at > NOW()
                  RETURNING s.*, s.atomic_units::TEXT AS atomic_units_text",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &instrument_id,
                    &update.operation_state,
                    &update.result_ref_hash,
                    &update.credit_event_id,
                    &update.settlement_batch_id,
                    &update.payout_state,
                    &update.error_label,
                    &lease_token,
                ],
            )
            .await?
            .ok_or_else(stale_lease_error)?;
        let settlement = pipeline_settlement_from_row(&row)?;
        tx.commit().await?;
        Ok(settlement)
    }

    pub async fn seal_index_command(
        &self,
        run: &PipelineRunRecord,
        membership: &str,
        command_ref: Option<&str>,
        command_hash: Option<&str>,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let index_write_state = if membership == "included" {
            "pending"
        } else {
            "none"
        };
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        ensure_current_lease(&tx, run, lease_token).await?;
        let row = tx
            .query_opt(
                "UPDATE pipeline_runs
                 SET index_membership = $3,
                     index_command_ref = $4,
                     index_command_hash = $5,
                     index_write_state = $6,
                     updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND lease_token = $7 AND lease_expires_at > NOW()
                   AND index_command_hash IS NULL
                 RETURNING *",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &membership,
                    &command_ref,
                    &command_hash,
                    &index_write_state,
                    &lease_token,
                ],
            )
            .await?
            .ok_or_else(stale_lease_error)?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn mark_index_write_state(
        &self,
        run: &PipelineRunRecord,
        index_write_state: &str,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE pipeline_runs
                 SET index_write_state = $3, updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND lease_token = $4 AND lease_expires_at > NOW()
                 RETURNING *",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &index_write_state,
                    &lease_token,
                ],
            )
            .await?
            .ok_or_else(stale_lease_error)?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn commit_settle(
        &self,
        run: &PipelineRunRecord,
        outcome: StoredPhaseResult,
        index_membership: &str,
    ) -> Result<PipelineRunRecord, DatabaseError> {
        if run.next_phase != Some(Phase::Settle) || outcome.phase != Phase::Settle {
            return Err(DatabaseError::Constraint(
                "phase does not match run transition".to_string(),
            ));
        }
        let lease_token = required_lease_token(run)?;
        let mut client = self.backend.trace_pool().get().await?;
        let tx = Self::tenant_transaction(&mut client, &run.tenant_id).await?;
        ensure_current_lease(&tx, run, lease_token).await?;
        insert_outcome(
            &tx,
            &run.tenant_id,
            run.run_id,
            run.trace_id,
            &run.bundle_id,
            Uuid::new_v4(),
            outcome,
        )
        .await?;
        let row = tx
            .query_one(
                "UPDATE pipeline_runs
                 SET next_phase = 'none', state = 'complete',
                     index_membership = $3,
                     lease_token = NULL, lease_expires_at = NULL,
                     next_attempt_at = NOW(), phase_started_at = NOW(), updated_at = NOW()
                 WHERE tenant_id = $1 AND run_id = $2
                   AND lease_token = $4 AND lease_expires_at > NOW()
                 RETURNING *",
                &[&run.tenant_id, &run.run_id, &index_membership, &lease_token],
            )
            .await?;
        let updated = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(updated)
    }
}

async fn insert_outcome(
    tx: &Transaction<'_>,
    tenant_id: &str,
    run_id: Uuid,
    trace_id: Uuid,
    bundle_id: &str,
    outcome_id: Uuid,
    outcome: StoredPhaseResult,
) -> Result<(), DatabaseError> {
    let schema = SchemaRef::pipeline_v1();
    tx.execute(
        "INSERT INTO phase_outcomes (
            tenant_id, outcome_id, run_id, trace_id, phase, bundle_id,
            outcome_schema_id, outcome_schema_version, decision, evidence, evaluation
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &tenant_id,
            &outcome_id,
            &run_id,
            &trace_id,
            &phase_as_db(Some(outcome.phase)),
            &bundle_id,
            &schema.id,
            &(schema.version as i32),
            &outcome.decision,
            &outcome.evidence,
            &outcome.evaluation,
        ],
    )
    .await?;
    Ok(())
}

async fn insert_receipt_records(
    tx: &Transaction<'_>,
    run: &NewPipelineRun,
    submission: &TraceSubmissionWrite,
    object_ref: &TraceObjectRefWrite,
    outcome: StoredPhaseResult,
    admission: &AdmissionDecision,
) -> Result<(), DatabaseError> {
    let consent_scopes = serde_json::to_value(&submission.consent_scopes).map_err(|_| {
        DatabaseError::Serialization("trace consent scopes encode failed".to_string())
    })?;
    let allowed_uses = serde_json::to_value(&submission.allowed_uses).map_err(|_| {
        DatabaseError::Serialization("trace allowed uses encode failed".to_string())
    })?;
    let redaction_counts = serde_json::to_value(&submission.redaction_counts).map_err(|_| {
        DatabaseError::Serialization("trace redaction counts encode failed".to_string())
    })?;
    let residual_risk_basis = submission
        .residual_risk_basis
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| {
            DatabaseError::Serialization("trace residual risk basis encode failed".to_string())
        })?;
    let (submission_status, admission_decision, admission_reason, next_phase, run_state) =
        match admission {
            AdmissionDecision::Admit => ("received", "admit", None, "review", "pending"),
            AdmissionDecision::Quarantine { reason } => (
                "quarantined",
                "quarantine",
                Some(reason.as_str()),
                "review",
                "pending",
            ),
            AdmissionDecision::Reject { reason } => (
                "rejected",
                "reject",
                Some(reason.as_str()),
                "none",
                "complete",
            ),
        };
    let inserted = tx
        .execute(
            "INSERT INTO trace_submissions (
                tenant_id, submission_id, trace_id, auth_principal_ref, contributor_pseudonym,
                submitted_tenant_scope_ref, schema_version, consent_policy_version,
                consent_scopes, allowed_uses, retention_policy_id, status, privacy_risk,
                redaction_pipeline_version, redaction_hash, redaction_counts,
                residual_risk_basis,
                canonical_summary_hash, submission_score, credit_points_pending,
                credit_points_final, expires_at
             ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                $17,$18,$19,$20,$21,$22
             )
             ON CONFLICT (tenant_id, submission_id) DO NOTHING",
            &[
                &submission.tenant_id,
                &submission.submission_id,
                &submission.trace_id,
                &submission.auth_principal_ref,
                &submission.contributor_pseudonym,
                &submission.submitted_tenant_scope_ref,
                &submission.schema_version,
                &submission.consent_policy_version,
                &consent_scopes,
                &allowed_uses,
                &submission.retention_policy_id,
                &submission_status,
                &submission.privacy_risk,
                &submission.redaction_pipeline_version,
                &submission.redaction_hash,
                &redaction_counts,
                &residual_risk_basis,
                &submission.canonical_summary_hash,
                &submission.submission_score,
                &submission.credit_points_pending,
                &submission.credit_points_final,
                &submission.expires_at,
            ],
        )
        .await?;
    if inserted != 1 {
        return Err(DatabaseError::Constraint(
            "submission identity is already bound to another receipt".to_string(),
        ));
    }
    tx.execute(
        "INSERT INTO trace_object_refs (
            tenant_id, submission_id, object_ref_id, artifact_kind, object_store,
            object_key, content_sha256, encryption_key_ref, size_bytes, compression,
            created_by_job_id
         ) VALUES ($1,$2,$3,'submitted_envelope',$4,$5,$6,$7,$8,$9,$10)",
        &[
            &object_ref.tenant_id,
            &object_ref.submission_id,
            &object_ref.object_ref_id,
            &object_ref.object_store,
            &object_ref.object_key,
            &object_ref.content_sha256,
            &object_ref.encryption_key_ref,
            &object_ref.size_bytes,
            &object_ref.compression,
            &object_ref.created_by_job_id,
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO pipeline_runs (
            tenant_id, run_id, submission_id, trace_id, bundle_id,
            request_idempotency_key, request_content_hash, source_object_ref_id,
            next_phase, state, admission_decision, admission_reason
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        &[
            &run.tenant_id,
            &run.run_id,
            &run.submission_id,
            &run.trace_id,
            &run.bundle_id,
            &run.request_idempotency_key,
            &run.request_content_hash,
            &run.source_object_ref_id,
            &next_phase,
            &run_state,
            &admission_decision,
            &admission_reason,
        ],
    )
    .await?;
    insert_outcome(
        tx,
        &run.tenant_id,
        run.run_id,
        run.trace_id,
        &run.bundle_id,
        Uuid::new_v4(),
        outcome,
    )
    .await?;
    let committed = tx
        .execute(
            "UPDATE pipeline_receipt_artifacts
             SET state = 'committed', committed_at = NOW()
             WHERE tenant_id = $1 AND run_id = $2
               AND request_idempotency_key = $3
               AND request_content_hash = $4
               AND object_key = $5
               AND ciphertext_sha256 = $6
               AND state = 'staged'",
            &[
                &run.tenant_id,
                &run.run_id,
                &run.request_idempotency_key,
                &run.request_content_hash,
                &object_ref.object_key,
                &object_ref.content_sha256.strip_prefix("sha256:"),
            ],
        )
        .await?;
    if committed != 1 {
        return Err(DatabaseError::Constraint(
            "receipt artifact staging record is missing".to_string(),
        ));
    }
    Ok(())
}

async fn load_bundle_from_transaction(
    tx: &Transaction<'_>,
    tenant_id: &str,
    bundle_id: &str,
) -> Result<Option<BundlePackage>, DatabaseError> {
    let row = tx
        .query_opt(
            "SELECT package FROM pipeline_bundle_packages
             WHERE tenant_id = $1 AND bundle_id = $2",
            &[&tenant_id, &bundle_id],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let package = serde_json::from_value::<BundlePackage>(row.get("package"))
        .map_err(|_| DatabaseError::Serialization(PIPELINE_BUNDLE_INVALID_LABEL.to_string()))?;
    package
        .validate()
        .map_err(|_| DatabaseError::Serialization(PIPELINE_BUNDLE_INVALID_LABEL.to_string()))?;
    if package.bundle_id != bundle_id {
        return Err(DatabaseError::Serialization(
            PIPELINE_BUNDLE_INVALID_LABEL.to_string(),
        ));
    }
    Ok(Some(package))
}

fn required_lease_token(run: &PipelineRunRecord) -> Result<Uuid, DatabaseError> {
    run.lease_token.ok_or_else(stale_lease_error)
}

async fn ensure_current_lease(
    tx: &Transaction<'_>,
    run: &PipelineRunRecord,
    lease_token: Uuid,
) -> Result<(), DatabaseError> {
    let current = tx
        .query_opt(
            "SELECT * FROM pipeline_runs
             WHERE tenant_id = $1 AND run_id = $2
             FOR UPDATE",
            &[&run.tenant_id, &run.run_id],
        )
        .await?
        .ok_or_else(|| DatabaseError::NotFound {
            entity: "pipeline_run".to_string(),
            id: run.run_id.to_string(),
        })?;
    let current = pipeline_run_from_row(&current)?;
    if current.state != PipelineRunState::Leased
        || current.lease_token != Some(lease_token)
        || current
            .lease_expires_at
            .is_none_or(|expires_at| expires_at <= Utc::now())
    {
        return Err(stale_lease_error());
    }
    Ok(())
}

fn stale_lease_error() -> DatabaseError {
    DatabaseError::Constraint("pipeline lease is stale".to_string())
}

fn pipeline_run_from_row(row: &Row) -> Result<PipelineRunRecord, DatabaseError> {
    let attempt_count: i32 = row.get("attempt_count");
    let max_attempts: i32 = row.get("max_attempts");
    Ok(PipelineRunRecord {
        tenant_id: row.get("tenant_id"),
        run_id: row.get("run_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        bundle_id: row.get("bundle_id"),
        request_idempotency_key: row.get("request_idempotency_key"),
        request_content_hash: row.get("request_content_hash"),
        source_object_ref_id: row.get("source_object_ref_id"),
        approved_revision_id: row.get("approved_revision_id"),
        next_phase: phase_from_db(row.get("next_phase"))?,
        state: PipelineRunState::from_db(row.get("state"))?,
        lease_token: row.get("lease_token"),
        lease_expires_at: row.get("lease_expires_at"),
        attempt_count: u32::try_from(attempt_count).map_err(|_| {
            DatabaseError::Serialization("invalid pipeline attempt count".to_string())
        })?,
        max_attempts: u32::try_from(max_attempts).map_err(|_| {
            DatabaseError::Serialization("invalid pipeline maximum attempts".to_string())
        })?,
        next_attempt_at: row.get("next_attempt_at"),
        phase_started_at: row.get("phase_started_at"),
        last_error_label: row.get("last_error_label"),
        index_membership: row.get("index_membership"),
        index_command_ref: row.get("index_command_ref"),
        index_command_hash: row.get("index_command_hash"),
        index_write_state: row.get("index_write_state"),
        index_invalidation_state: row.get("index_invalidation_state"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn pipeline_settlement_from_row(row: &Row) -> Result<PipelineSettlementRecord, DatabaseError> {
    let atomic_units = row
        .get::<_, String>("atomic_units_text")
        .parse::<u64>()
        .map_err(|_| DatabaseError::Serialization("invalid settlement atomic units".to_string()))?;
    let attempt_count = u32::try_from(row.get::<_, i32>("attempt_count")).map_err(|_| {
        DatabaseError::Serialization("invalid settlement attempt count".to_string())
    })?;
    let max_attempts = u32::try_from(row.get::<_, i32>("max_attempts")).map_err(|_| {
        DatabaseError::Serialization("invalid settlement maximum attempts".to_string())
    })?;
    Ok(PipelineSettlementRecord {
        tenant_id: row.get("tenant_id"),
        run_id: row.get("run_id"),
        instrument_id: row.get("instrument_id"),
        atomic_units,
        operation_ref_hash: row.get("operation_ref_hash"),
        result_ref_hash: row.get("result_ref_hash"),
        operation_state: row.get("operation_state"),
        credit_event_id: row.get("credit_event_id"),
        settlement_batch_id: row.get("settlement_batch_id"),
        payout_rail: row.get("payout_rail"),
        payout_state: row.get("payout_state"),
        attempt_count,
        max_attempts,
        last_error_label: row.get("last_error_label"),
    })
}

fn phase_outcome_from_row(row: &Row) -> Result<PhaseOutcomeRecord, DatabaseError> {
    let version: i32 = row.get("outcome_schema_version");
    let schema_id: String = row.get("outcome_schema_id");
    let version = u32::try_from(version)
        .map_err(|_| DatabaseError::Serialization("invalid outcome schema version".to_string()))?;
    if schema_id != PIPELINE_OUTCOME_SCHEMA_ID || version != PIPELINE_OUTCOME_SCHEMA_VERSION {
        return Err(DatabaseError::Serialization(
            "unsupported required pipeline outcome schema".to_string(),
        ));
    }
    let phase = phase_from_db(row.get("phase"))?
        .ok_or_else(|| DatabaseError::Serialization("outcome phase cannot be none".to_string()))?;
    let decision = row.get("decision");
    let evidence = row.get("evidence");
    let evaluation = row.get("evaluation");
    validate_outcome_payload(phase, &decision, &evidence, &evaluation)?;
    Ok(PhaseOutcomeRecord {
        tenant_id: row.get("tenant_id"),
        outcome_id: row.get("outcome_id"),
        run_id: row.get("run_id"),
        trace_id: row.get("trace_id"),
        phase,
        bundle_id: row.get("bundle_id"),
        outcome_schema: SchemaRef {
            id: schema_id,
            version,
        },
        decision,
        evidence,
        evaluation,
        recorded_at: row.get("recorded_at"),
    })
}

fn validate_outcome_payload(
    phase: Phase,
    decision: &serde_json::Value,
    evidence: &serde_json::Value,
    evaluation: &serde_json::Value,
) -> Result<(), DatabaseError> {
    fn decode<T: serde::de::DeserializeOwned>(
        value: &serde_json::Value,
    ) -> Result<T, DatabaseError> {
        serde_json::from_value(value.clone()).map_err(|_| {
            DatabaseError::Serialization("malformed pipeline outcome payload".to_string())
        })
    }

    match phase {
        Phase::Admission => {
            let _: AdmissionDecision = decode(decision)?;
            let _: AdmissionEvidence = decode(evidence)?;
            let _: AdmissionEvaluation = decode(evaluation)?;
        }
        Phase::Review => {
            let _: ReviewDecision = decode(decision)?;
            let _: ReviewEvidence = decode(evidence)?;
            let _: ReviewEvaluation = decode(evaluation)?;
        }
        Phase::Score => {
            let _: ScoreDecision = decode(decision)?;
            let _: ScoreEvidence = decode(evidence)?;
            let _: ScoreEvaluation = decode(evaluation)?;
        }
        Phase::Settle => {
            let _: SettleDecision = decode(decision)?;
            let _: SettleEvidence = decode(evidence)?;
            let _: SettleEvaluation = decode(evaluation)?;
        }
    }
    Ok(())
}

pub struct MinimalAdmissionPolicy;

#[async_trait]
impl AdmissionPolicy for MinimalAdmissionPolicy {
    async fn execute(
        &self,
        input: &AdmissionInput,
    ) -> Result<PhaseResult<AdmissionDecision, AdmissionEvidence, AdmissionEvaluation>, PolicyError>
    {
        if !input.authenticated || !input.authority_valid {
            return Err(PolicyError::new("authority_missing").expect("static safe label"));
        }
        let (decision, schema_valid, reason) = if input.schema_version
            != "ironclaw.trace_contribution.v1"
        {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("schema_invalid").expect("static safe label"),
                },
                false,
                Some("schema_invalid"),
            )
        } else if input.tombstoned {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("content_tombstoned").expect("static safe label"),
                },
                true,
                Some("content_tombstoned"),
            )
        } else if !input.contribution_path_valid {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("contribution_path_invalid")
                        .expect("static safe label"),
                },
                true,
                Some("contribution_path_invalid"),
            )
        } else if !input.grant_valid {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("grant_invalid").expect("static safe label"),
                },
                true,
                Some("grant_invalid"),
            )
        } else if !input.consent_valid {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("consent_invalid").expect("static safe label"),
                },
                true,
                Some("consent_invalid"),
            )
        } else if !input.allowed_uses_valid {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("allowed_use_invalid").expect("static safe label"),
                },
                true,
                Some("allowed_use_invalid"),
            )
        } else if !input.quota_available {
            (
                AdmissionDecision::Reject {
                    reason: ReasonCode::new("admission_limit_exceeded").expect("static safe label"),
                },
                true,
                Some("admission_limit_exceeded"),
            )
        } else {
            match input.privacy_risk.as_str() {
                "low" => (AdmissionDecision::Admit, true, None),
                "medium" => (
                    AdmissionDecision::Quarantine {
                        reason: ReasonCode::new("privacy_review_required")
                            .expect("static safe label"),
                    },
                    true,
                    Some("privacy_review_required"),
                ),
                _ => (
                    AdmissionDecision::Reject {
                        reason: ReasonCode::new("privacy_risk_rejected")
                            .expect("static safe label"),
                    },
                    true,
                    Some("privacy_risk_rejected"),
                ),
            }
        };
        Ok(PhaseResult {
            decision,
            evidence: AdmissionEvidence {
                request_content_hash: input.request_content_hash.clone(),
                schema_valid,
                authority_valid: true,
                contribution_path_valid: input.contribution_path_valid,
                grant_valid: input.grant_valid,
                consent_valid: input.consent_valid,
                allowed_uses_valid: input.allowed_uses_valid,
                quota_counted: input.quota_available,
                detector_ids: Vec::new(),
                privacy_risk: Some(input.privacy_risk.clone()),
            },
            evaluation: AdmissionEvaluation {
                rule_id: reason.unwrap_or("minimal_admission_v1").to_string(),
            },
        })
    }
}

pub struct MinimalReviewPolicy;

#[async_trait]
impl ReviewPolicy for MinimalReviewPolicy {
    async fn execute(
        &self,
        input: &ReviewInput,
    ) -> Result<PhaseResult<ReviewDecision, ReviewEvidence, ReviewEvaluation>, PolicyError> {
        let result_hash = sha256_prefixed(&input.source_artifact);
        if result_hash != input.source_content_hash {
            return Err(PolicyError::new("source_hash_mismatch").expect("static safe label"));
        }
        let (assessment_hash, resolved_quarantine_reasons) = match &input.admission {
            AdmissionDecision::Admit => (None, Vec::new()),
            AdmissionDecision::Reject { .. } => {
                return Err(PolicyError::new("admission_rejected").expect("static safe label"));
            }
            AdmissionDecision::Quarantine { reason } => {
                let assessment = input.human_assessment.as_ref().ok_or_else(|| {
                    PolicyError::new("review_assessment_required").expect("static safe label")
                })?;
                if assessment.recommendation == ReviewRecommendation::Reject {
                    return Ok(PhaseResult {
                        decision: ReviewDecision::Rejected {
                            reason: assessment.reason.clone(),
                        },
                        evidence: ReviewEvidence {
                            source_content_hash: input.source_content_hash.clone(),
                            result_content_hash: result_hash,
                            content_changed: false,
                            transformed_artifact_hash: None,
                            human_assessment_hash: Some(assessment.evidence_hash.clone()),
                            resolved_quarantine_reasons: Vec::new(),
                        },
                        evaluation: ReviewEvaluation {
                            rule_id: "human_review_rejected_v1".to_string(),
                        },
                    });
                }
                if !assessment
                    .resolved_quarantine_reasons
                    .iter()
                    .any(|resolved| resolved == reason)
                {
                    return Err(
                        PolicyError::new("review_resolution_missing").expect("static safe label")
                    );
                }
                (
                    Some(assessment.evidence_hash.clone()),
                    assessment.resolved_quarantine_reasons.clone(),
                )
            }
        };
        let registry_revision_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("tracecommons:pipeline-review:{}", input.run_id).as_bytes(),
        );
        Ok(PhaseResult {
            decision: ReviewDecision::Approved {
                registry_revision_id,
            },
            evidence: ReviewEvidence {
                source_content_hash: input.source_content_hash.clone(),
                result_content_hash: result_hash,
                content_changed: false,
                transformed_artifact_hash: None,
                human_assessment_hash: assessment_hash,
                resolved_quarantine_reasons,
            },
            evaluation: ReviewEvaluation {
                rule_id: "minimal_review_passthrough_v1".to_string(),
            },
        })
    }
}

pub struct MinimalScorePolicy;

#[async_trait]
impl ScorePolicy for MinimalScorePolicy {
    async fn execute(
        &self,
        _input: &ScoreInput,
    ) -> Result<PhaseResult<ScoreDecision, ScoreEvidence, ScoreEvaluation>, PolicyError> {
        let awards = InstrumentAwards::new(Vec::new()).expect("empty awards are valid");
        Ok(PhaseResult {
            decision: ScoreDecision {
                awards: awards.clone(),
            },
            evidence: ScoreEvidence::fixed(awards.clone()),
            evaluation: ScoreEvaluation {
                rule_id: "minimal_fixed_zero_v1".to_string(),
                awards,
            },
        })
    }
}

pub struct MinimalSettlePolicy;

#[async_trait]
impl SettlePolicy for MinimalSettlePolicy {
    async fn execute(
        &self,
        input: &SettleInput,
    ) -> Result<PhaseResult<SettleDecision, SettleEvidence, SettleEvaluation>, PolicyError> {
        let operations = settlement_operations(input.run_id, &input.score.awards);
        let decision = SettleDecision::new(
            IndexMembershipDecision::Exclude {
                reason: ReasonCode::new("minimal_bundle_exclusion").expect("static safe label"),
            },
            &input.score.awards,
            operations,
        )
        .expect("settlement operations are derived from awards");
        Ok(PhaseResult {
            decision,
            evidence: SettleEvidence::operations(
                false,
                u32::try_from(input.score.awards.iter().len()).unwrap_or(u32::MAX),
            ),
            evaluation: SettleEvaluation {
                rule_id: "minimal_settle_exclude_v1".to_string(),
            },
        })
    }
}

pub struct FixedScorePolicy {
    pub awards: InstrumentAwards,
}

#[async_trait]
impl ScorePolicy for FixedScorePolicy {
    async fn execute(
        &self,
        _input: &ScoreInput,
    ) -> Result<PhaseResult<ScoreDecision, ScoreEvidence, ScoreEvaluation>, PolicyError> {
        let rule_id = if self.awards.is_empty() {
            "minimal_fixed_zero_v1"
        } else {
            "minimal_fixed_positive_v1"
        };
        let awards = self.awards.clone();
        Ok(PhaseResult {
            decision: ScoreDecision {
                awards: awards.clone(),
            },
            evidence: ScoreEvidence::fixed(awards.clone()),
            evaluation: ScoreEvaluation {
                rule_id: rule_id.to_string(),
                awards,
            },
        })
    }
}

pub struct FixedSettlePolicy {
    pub include: bool,
}

#[async_trait]
impl SettlePolicy for FixedSettlePolicy {
    async fn execute(
        &self,
        input: &SettleInput,
    ) -> Result<PhaseResult<SettleDecision, SettleEvidence, SettleEvaluation>, PolicyError> {
        let index_membership = if self.include {
            let command = SealedIndexCommand::include(
                input.registry_revision_id,
                input.source_content_hash.clone(),
                deterministic_pipeline_embedding(&input.source_content_hash),
            )
            .expect("settle input contains a valid source hash");
            IndexMembershipDecision::Include {
                command_hash: command
                    .command_hash()
                    .expect("deterministic command serializes"),
                entry_count: 1,
            }
        } else {
            IndexMembershipDecision::Exclude {
                reason: trace_commons_gate_api::pipeline::ReasonCode::new(
                    "minimal_bundle_exclusion",
                )
                .expect("static safe label"),
            }
        };
        let operations = settlement_operations(input.run_id, &input.score.awards);
        let decision = SettleDecision::new(index_membership, &input.score.awards, operations)
            .expect("settlement operations are derived from awards");
        Ok(PhaseResult {
            decision,
            evidence: SettleEvidence::operations(
                self.include,
                u32::try_from(input.score.awards.iter().len()).unwrap_or(u32::MAX),
            ),
            evaluation: SettleEvaluation {
                rule_id: if self.include {
                    "minimal_settle_include_v1".to_string()
                } else {
                    "minimal_settle_exclude_v1".to_string()
                },
            },
        })
    }
}

pub struct MinimalPolicyBundle {
    pub package: BundlePackage,
    pub admission: Arc<dyn AdmissionPolicy>,
    pub review: Arc<dyn ReviewPolicy>,
    pub score: Arc<dyn ScorePolicy>,
    pub settle: Arc<dyn SettlePolicy>,
}

impl MinimalPolicyBundle {
    pub fn build() -> anyhow::Result<Self> {
        Self::build_variant("minimal-local-test-only-v1")
    }

    pub fn build_operations(score_microcredits: u64, include_index: bool) -> anyhow::Result<Self> {
        let configuration = serde_json::to_vec(&PipelineBundleConfig {
            score_microcredits,
            instrument_awards: Vec::new(),
            include_index,
            compatibility: None,
        })?;
        Self::build_from_configuration(configuration)
    }

    pub fn build_instruments(
        instrument_awards: Vec<PipelineInstrumentAwardConfig>,
        include_index: bool,
    ) -> anyhow::Result<Self> {
        let configuration = serde_json::to_vec(&PipelineBundleConfig {
            score_microcredits: 0,
            instrument_awards,
            include_index,
            compatibility: None,
        })?;
        Self::build_from_configuration(configuration)
    }

    pub fn build_variant(configuration_label: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !configuration_label.trim().is_empty(),
            "minimal bundle configuration label cannot be empty"
        );
        Self::build_from_configuration(configuration_label.as_bytes().to_vec())
    }

    pub fn build_compatibility(runtime: &CompatibilityScoreRuntime) -> anyhow::Result<Self> {
        Self::build_compatibility_candidate(runtime, CompatibilityBundleConfig::local_reference())
    }

    pub fn build_compatibility_candidate(
        runtime: &CompatibilityScoreRuntime,
        config: CompatibilityBundleConfig,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        let configuration = serde_json::to_vec(&PipelineBundleConfig {
            score_microcredits: 0,
            instrument_awards: Vec::new(),
            include_index: true,
            compatibility: Some(config),
        })?;
        Self::build_package(configuration, true, Some(runtime))
    }

    fn build_from_configuration(configuration: Vec<u8>) -> anyhow::Result<Self> {
        Self::build_package(configuration, false, None)
    }

    fn build_package(
        configuration: Vec<u8>,
        compatibility: bool,
        runtime: Option<&CompatibilityScoreRuntime>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !configuration.is_empty(),
            "minimal bundle configuration cannot be empty"
        );
        let mut specifications = [
            ("admission", b"minimal-admission-policy-v1".as_slice()),
            ("review", b"minimal-review-policy-v1".as_slice()),
            ("score", b"minimal-score-policy-v1".as_slice()),
            ("settle", b"minimal-settle-policy-v1".as_slice()),
        ];
        if compatibility {
            specifications[0].1 = b"authority-admission-policy-v1";
            specifications[1].1 = b"privacy-review-policy-v1";
            specifications[2].1 = COMPATIBILITY_SCORE_CODE;
            specifications[3].1 = COMPATIBILITY_SETTLE_CODE;
        }
        let config_hash = sha256_prefixed(&configuration);
        let policy_ref = |(name, bytes): (&str, &[u8]), implementation_id: String| PolicyRef {
            policy_id: format!("trace_commons.{name}.minimal"),
            implementation_id,
            code_artifact_hash: sha256_prefixed(bytes),
            configuration_hash: config_hash.clone(),
            data_artifact_hashes: Vec::new(),
            projection_ids: Vec::new(),
        };
        let manifest = BundleManifest {
            format_version: BUNDLE_MANIFEST_FORMAT_VERSION,
            admission: policy_ref(
                specifications[0],
                if compatibility {
                    AUTHORITY_ADMISSION_IMPLEMENTATION.to_string()
                } else {
                    "trace_commons.admission.minimal.v1".to_string()
                },
            ),
            review: policy_ref(
                specifications[1],
                if compatibility {
                    AUTHORITY_REVIEW_IMPLEMENTATION.to_string()
                } else {
                    "trace_commons.review.minimal.v1".to_string()
                },
            ),
            score: policy_ref(
                specifications[2],
                if compatibility {
                    COMPATIBILITY_SCORE_IMPLEMENTATION.to_string()
                } else {
                    "trace_commons.score.minimal.v1".to_string()
                },
            ),
            settle: policy_ref(
                specifications[3],
                if compatibility {
                    COMPATIBILITY_SETTLE_IMPLEMENTATION.to_string()
                } else {
                    "trace_commons.settle.minimal.v1".to_string()
                },
            ),
        };
        let mut artifacts = BTreeMap::new();
        artifacts.insert(config_hash, configuration);
        for (_, bytes) in specifications {
            artifacts.insert(sha256_prefixed(bytes), bytes.to_vec());
        }
        let package = BundlePackage {
            bundle_id: manifest.bundle_id()?,
            manifest,
            artifacts,
        };
        package.validate()?;
        Self::from_package_with_runtime(package, runtime)
    }

    fn from_package_with_runtime(
        package: BundlePackage,
        runtime: Option<&CompatibilityScoreRuntime>,
    ) -> anyhow::Result<Self> {
        package.validate()?;
        let implementations = [
            &package.manifest.admission.implementation_id,
            &package.manifest.review.implementation_id,
            &package.manifest.score.implementation_id,
            &package.manifest.settle.implementation_id,
        ];
        let compatibility = implementations
            == [
                AUTHORITY_ADMISSION_IMPLEMENTATION,
                AUTHORITY_REVIEW_IMPLEMENTATION,
                COMPATIBILITY_SCORE_IMPLEMENTATION,
                COMPATIBILITY_SETTLE_IMPLEMENTATION,
            ];
        let minimal = implementations
            == [
                "trace_commons.admission.minimal.v1",
                "trace_commons.review.minimal.v1",
                "trace_commons.score.minimal.v1",
                "trace_commons.settle.minimal.v1",
            ];
        anyhow::ensure!(
            minimal || compatibility,
            "bundle policy implementation is unavailable"
        );
        let config = parse_bundle_config(&package)?;
        let awards = if config.instrument_awards.is_empty() {
            trace_credit_awards(Microcredits::from_raw(config.score_microcredits))?
        } else {
            InstrumentAwards::new(
                config
                    .instrument_awards
                    .iter()
                    .map(|award| {
                        InstrumentAward::new(
                            trace_commons_gate_api::pipeline::InstrumentId::new(
                                award.instrument_id.clone(),
                            )?,
                            AtomicUnits::from_raw(award.atomic_units),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )?
        };
        let score: Arc<dyn ScorePolicy> = if compatibility {
            let runtime =
                runtime.ok_or_else(|| anyhow::anyhow!("compatibility runtime is unavailable"))?;
            let compatibility_config = config
                .compatibility
                .clone()
                .ok_or_else(|| anyhow::anyhow!(PIPELINE_BUNDLE_INVALID_LABEL))?;
            Arc::new(CompatibilityScorePolicy::new(
                runtime,
                compatibility_config,
            )?)
        } else if awards.is_empty() {
            Arc::new(MinimalScorePolicy)
        } else {
            Arc::new(FixedScorePolicy { awards })
        };
        let settle: Arc<dyn SettlePolicy> = if compatibility {
            Arc::new(CompatibilitySettlePolicy)
        } else if config.include_index {
            Arc::new(FixedSettlePolicy { include: true })
        } else {
            Arc::new(MinimalSettlePolicy)
        };
        Ok(Self {
            package,
            admission: Arc::new(MinimalAdmissionPolicy),
            review: Arc::new(MinimalReviewPolicy),
            score,
            settle,
        })
    }
}

fn parse_bundle_config(package: &BundlePackage) -> anyhow::Result<PipelineBundleConfig> {
    let hash = &package.manifest.score.configuration_hash;
    let bytes = package
        .artifacts
        .get(hash)
        .ok_or_else(|| anyhow::anyhow!(PIPELINE_BUNDLE_INVALID_LABEL))?;
    if let Ok(config) = serde_json::from_slice::<PipelineBundleConfig>(bytes) {
        return Ok(config);
    }
    Ok(PipelineBundleConfig::minimal())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineSubmitReceipt {
    pub run_id: Uuid,
    pub submission_id: Uuid,
    pub bundle_id: String,
    pub request_content_hash: String,
    pub replayed: bool,
    pub state: PipelineRunState,
    pub next_phase: Option<Phase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineInspection {
    pub run: PipelineRunRecord,
    pub outcomes: Vec<PhaseOutcomeRecord>,
}

pub trait IdentifiedPerplexityScorer: PerplexityScorer {
    fn dependency_identity(&self) -> &str;
}

pub trait IdentifiedEmbedder: Embedder {
    fn dependency_identity(&self) -> &str;
}

pub trait IdentifiedIndexReader: VectorIndexReader {
    fn dependency_identity(&self) -> &str;
}

pub trait IdentifiedIndexWriter: VectorIndexWriter {
    fn dependency_identity(&self) -> &str;

    fn invalidate_revision(
        &self,
        _tenant_id: &str,
        _index_id: &str,
        _revision_id: Uuid,
    ) -> Result<bool, IndexWriteError> {
        Err(IndexWriteError::Failed)
    }
}

impl IdentifiedPerplexityScorer for ReferencePerplexityScorer {
    fn dependency_identity(&self) -> &str {
        "reference_perplexity_test_only"
    }
}

impl IdentifiedEmbedder for ReferenceEmbedder {
    fn dependency_identity(&self) -> &str {
        "reference_embedder_test_only"
    }
}

impl IdentifiedIndexReader for IsolatedPipelineIndex {
    fn dependency_identity(&self) -> &str {
        "isolated_index_reader_test_only"
    }
}

impl IdentifiedIndexWriter for IsolatedPipelineIndex {
    fn dependency_identity(&self) -> &str {
        "isolated_index_writer_test_only"
    }

    fn invalidate_revision(
        &self,
        tenant_id: &str,
        index_id: &str,
        revision_id: Uuid,
    ) -> Result<bool, IndexWriteError> {
        self.try_invalidate_revision(tenant_id, index_id, revision_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineDependencyIdentity {
    pub authority: String,
    pub privacy: String,
    pub scorer: String,
    pub embedder: String,
    pub index_reader: String,
    pub index_writer: String,
    pub settlement_adapters: BTreeMap<String, String>,
    pub payout_adapter: String,
}

#[derive(Debug, Clone)]
pub struct PipelineCaps {
    pub per_instrument_atomic_units: BTreeMap<String, u64>,
}

impl PipelineCaps {
    pub fn cap_for(&self, instrument_id: &str) -> Option<u64> {
        self.per_instrument_atomic_units.get(instrument_id).copied()
    }
}

#[derive(Debug, Clone)]
pub struct PipelinePayoutConfig {
    pub enabled: bool,
    pub require_confirmation_evidence: bool,
}

pub struct PipelineServiceBuilder {
    backend: Arc<PgBackend>,
    artifact_store: Arc<dyn TraceArtifactStore>,
    default_bundle: MinimalPolicyBundle,
    scorer: Arc<dyn IdentifiedPerplexityScorer>,
    embedder: Arc<dyn IdentifiedEmbedder>,
    index_reader: Arc<dyn IdentifiedIndexReader>,
    index_writer: Arc<dyn IdentifiedIndexWriter>,
    settlement_adapters: SettlementAdapterRegistry,
    payout_adapter: Arc<dyn NearPayoutAdapter>,
    authority: Arc<dyn PipelineAuthorityProvider>,
    privacy: Arc<dyn PipelinePrivacyBoundary>,
    caps: PipelineCaps,
    payout: PipelinePayoutConfig,
    compatibility_runtime: Option<CompatibilityScoreRuntime>,
    fail_phase: Option<Phase>,
    crash_point: Option<PipelineCrashPoint>,
    test_index: Option<Arc<IsolatedPipelineIndex>>,
    test_near: Option<Arc<RecordingNearAdapter>>,
}

impl PipelineServiceBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn production(
        backend: Arc<PgBackend>,
        artifact_store: Arc<dyn TraceArtifactStore>,
        default_bundle: MinimalPolicyBundle,
        scorer: Arc<dyn IdentifiedPerplexityScorer>,
        embedder: Arc<dyn IdentifiedEmbedder>,
        index_reader: Arc<dyn IdentifiedIndexReader>,
        index_writer: Arc<dyn IdentifiedIndexWriter>,
        settlement_adapters: SettlementAdapterRegistry,
        payout_adapter: Arc<dyn NearPayoutAdapter>,
        authority: Arc<dyn PipelineAuthorityProvider>,
        privacy: Arc<dyn PipelinePrivacyBoundary>,
        caps: PipelineCaps,
        payout: PipelinePayoutConfig,
    ) -> Self {
        Self {
            backend,
            artifact_store,
            default_bundle,
            scorer,
            embedder,
            index_reader,
            index_writer,
            settlement_adapters,
            payout_adapter,
            authority,
            privacy,
            caps,
            payout,
            compatibility_runtime: None,
            fail_phase: None,
            crash_point: None,
            test_index: None,
            test_near: None,
        }
    }

    #[doc(hidden)]
    pub fn test_only(
        backend: Arc<PgBackend>,
        artifact_store: Arc<dyn TraceArtifactStore>,
    ) -> anyhow::Result<Self> {
        let index = IsolatedPipelineIndex::new();
        let near = Arc::new(RecordingNearAdapter::new());
        let trace_credit = RecordingSettlementAdapter::new(
            trace_commons_gate_api::pipeline::InstrumentId::trace_credit(),
            "recording_trace_credit_test_only",
            "near",
        );
        Ok(Self {
            backend,
            artifact_store,
            default_bundle: MinimalPolicyBundle::build()?,
            scorer: Arc::new(ReferencePerplexityScorer::new()),
            embedder: Arc::new(ReferenceEmbedder::new()),
            index_reader: index.clone(),
            index_writer: index.clone(),
            settlement_adapters: SettlementAdapterRegistry::new(vec![trace_credit])?,
            payout_adapter: near.clone(),
            authority: Arc::new(StaticPipelineAuthorityProvider::test_only(
                SubmissionAuthority {
                    tenant: SubmissionAllowlists::default(),
                    policy: None,
                    require_policy: false,
                },
            )),
            privacy: Arc::new(ClassifierRedactorPipelinePrivacyBoundary::new(
                Arc::new(NoopPrivacyFilterAdapter),
                PiiClassifyPolicy::AllEvents,
                "noop_classifier_redactor_test_only",
            )?),
            caps: PipelineCaps {
                per_instrument_atomic_units: BTreeMap::from([(
                    trace_commons_gate_api::pipeline::TRACE_CREDIT_INSTRUMENT_ID.to_string(),
                    PIPELINE_TEST_CREDIT_CAP_MICROCREDITS,
                )]),
            },
            payout: PipelinePayoutConfig {
                enabled: false,
                require_confirmation_evidence: true,
            },
            compatibility_runtime: None,
            fail_phase: None,
            crash_point: None,
            test_index: Some(index),
            test_near: Some(near),
        })
    }

    #[doc(hidden)]
    pub fn with_test_faults(
        mut self,
        fail_phase: Option<Phase>,
        crash_point: Option<PipelineCrashPoint>,
    ) -> Self {
        self.fail_phase = fail_phase;
        self.crash_point = crash_point;
        self
    }

    pub fn with_compatibility_runtime(mut self, runtime: CompatibilityScoreRuntime) -> Self {
        self.compatibility_runtime = Some(runtime);
        self
    }

    pub fn build(self) -> anyhow::Result<PipelineService> {
        self.default_bundle.package.validate()?;
        anyhow::ensure!(
            !self.payout.enabled || self.payout.require_confirmation_evidence,
            "payout confirmation evidence cannot be disabled"
        );
        let bundle_config = parse_bundle_config(&self.default_bundle.package)?;
        if let Some(compatibility) = bundle_config.compatibility {
            anyhow::ensure!(
                self.compatibility_runtime.is_some(),
                "compatibility runtime is unavailable"
            );
            if compatibility.is_qualifiable() {
                anyhow::ensure!(
                    self.privacy.is_production_compatible(),
                    crate::versioned_pipeline_authority::PIPELINE_PRIVACY_CONTROL_MISSING_LABEL
                );
            }
        }
        Ok(PipelineService {
            store: PgPipelineStore::new(self.backend.clone()),
            backend: self.backend,
            artifact_store: self.artifact_store,
            default_bundle: self.default_bundle,
            fail_phase: self.fail_phase,
            crash_point: self.crash_point,
            crash_pending: AtomicBool::new(self.crash_point.is_some()),
            scorer: self.scorer,
            embedder: self.embedder,
            index_reader: self.index_reader,
            index_writer: self.index_writer,
            settlement_adapters: self.settlement_adapters,
            payout_adapter: self.payout_adapter,
            authority: self.authority,
            privacy: self.privacy,
            caps: self.caps,
            payout: self.payout,
            compatibility_runtime: self.compatibility_runtime,
            test_index: self.test_index,
            test_near: self.test_near,
            score_evaluations: AtomicUsize::new(0),
            settle_evaluations: AtomicUsize::new(0),
        })
    }
}

pub struct PipelineService {
    backend: Arc<PgBackend>,
    store: PgPipelineStore,
    artifact_store: Arc<dyn TraceArtifactStore>,
    default_bundle: MinimalPolicyBundle,
    fail_phase: Option<Phase>,
    crash_point: Option<PipelineCrashPoint>,
    crash_pending: AtomicBool,
    scorer: Arc<dyn IdentifiedPerplexityScorer>,
    embedder: Arc<dyn IdentifiedEmbedder>,
    index_reader: Arc<dyn IdentifiedIndexReader>,
    index_writer: Arc<dyn IdentifiedIndexWriter>,
    settlement_adapters: SettlementAdapterRegistry,
    payout_adapter: Arc<dyn NearPayoutAdapter>,
    authority: Arc<dyn PipelineAuthorityProvider>,
    privacy: Arc<dyn PipelinePrivacyBoundary>,
    caps: PipelineCaps,
    payout: PipelinePayoutConfig,
    compatibility_runtime: Option<CompatibilityScoreRuntime>,
    test_index: Option<Arc<IsolatedPipelineIndex>>,
    test_near: Option<Arc<RecordingNearAdapter>>,
    score_evaluations: AtomicUsize,
    settle_evaluations: AtomicUsize,
}

impl PipelineService {
    #[doc(hidden)]
    pub fn new_test_only(
        backend: Arc<PgBackend>,
        artifact_store: Arc<dyn TraceArtifactStore>,
        fail_phase: Option<Phase>,
    ) -> anyhow::Result<Self> {
        PipelineServiceBuilder::test_only(backend, artifact_store)?
            .with_test_faults(fail_phase, None)
            .build()
    }

    #[doc(hidden)]
    pub fn new_test_only_with_crash_point(
        backend: Arc<PgBackend>,
        artifact_store: Arc<dyn TraceArtifactStore>,
        fail_phase: Option<Phase>,
        crash_point: Option<PipelineCrashPoint>,
    ) -> anyhow::Result<Self> {
        PipelineServiceBuilder::test_only(backend, artifact_store)?
            .with_test_faults(fail_phase, crash_point)
            .build()
    }

    pub fn bundle_id(&self) -> &str {
        &self.default_bundle.package.bundle_id
    }

    pub fn index(&self) -> Arc<IsolatedPipelineIndex> {
        self.test_index
            .clone()
            .expect("isolated index is available only from the test-only builder")
    }

    pub fn near_adapter(&self) -> Arc<RecordingNearAdapter> {
        self.test_near
            .clone()
            .expect("recording NEAR adapter is available only from the test-only builder")
    }

    #[doc(hidden)]
    pub fn store_for_test(&self) -> &PgPipelineStore {
        &self.store
    }

    pub fn dependency_identity(&self) -> PipelineDependencyIdentity {
        PipelineDependencyIdentity {
            authority: self.authority.dependency_identity().to_string(),
            privacy: self.privacy.dependency_identity().to_string(),
            scorer: self.scorer.dependency_identity().to_string(),
            embedder: self.embedder.dependency_identity().to_string(),
            index_reader: self.index_reader.dependency_identity().to_string(),
            index_writer: self.index_writer.dependency_identity().to_string(),
            settlement_adapters: self.settlement_adapters.identities(),
            payout_adapter: self.payout_adapter.adapter_identity().to_string(),
        }
    }

    pub fn score_evaluations(&self) -> usize {
        self.score_evaluations.load(Ordering::SeqCst)
    }

    pub fn settle_evaluations(&self) -> usize {
        self.settle_evaluations.load(Ordering::SeqCst)
    }

    pub async fn register_bundle(
        &self,
        tenant_id: &str,
        package: &BundlePackage,
    ) -> anyhow::Result<()> {
        self.store.register_bundle(tenant_id, package).await?;
        Ok(())
    }

    pub async fn activate_bundle(&self, tenant_id: &str, bundle_id: &str) -> anyhow::Result<()> {
        self.store.activate_bundle(tenant_id, bundle_id).await?;
        Ok(())
    }

    pub async fn active_bundle_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>> {
        Ok(self.store.active_bundle_id(tenant_id).await?)
    }

    pub async fn list_cleanup_orphans(
        &self,
        tenant_id: &str,
        before: DateTime<Utc>,
    ) -> anyhow::Result<Vec<PipelineReceiptArtifactRecord>> {
        Ok(self.store.list_cleanup_orphans(tenant_id, before).await?)
    }

    async fn ensure_default_bundle(&self, tenant_id: &str) -> anyhow::Result<()> {
        self.store
            .register_bundle(tenant_id, &self.default_bundle.package)
            .await?;
        self.store
            .activate_bundle_if_none(tenant_id, self.bundle_id())
            .await?;
        Ok(())
    }

    fn inject_crash(&self, point: PipelineCrashPoint) -> anyhow::Result<()> {
        if self.crash_point == Some(point) && self.crash_pending.swap(false, Ordering::SeqCst) {
            anyhow::bail!(INJECTED_PIPELINE_CRASH);
        }
        Ok(())
    }

    pub async fn submit(
        &self,
        tenant_id: &str,
        actor_principal_ref: &str,
        request_idempotency_key: &str,
        request_bytes: &[u8],
    ) -> anyhow::Result<PipelineReceiptResult> {
        anyhow::ensure!(
            !request_idempotency_key.trim().is_empty() && request_idempotency_key.len() <= 200,
            "invalid idempotency key"
        );
        let request_content_hash = sha256_prefixed(request_bytes);
        let request_idempotency_key_hash = sha256_prefixed(request_idempotency_key.as_bytes());
        let mut envelope: TraceContributionEnvelope = serde_json::from_slice(request_bytes)
            .map_err(|_| anyhow::anyhow!("invalid envelope"))?;
        let authority = self
            .authority
            .authority_for_tenant(tenant_id)
            .ok_or_else(|| anyhow::anyhow!(PIPELINE_AUTHORITY_CONTROL_MISSING_LABEL))?;
        let mut consent_scopes = envelope.consent.scopes.clone();
        if !consent_scopes.contains(&envelope.trace_card.consent_scope) {
            consent_scopes.push(envelope.trace_card.consent_scope);
        }
        let authority_valid = authority.permits(&consent_scopes, &envelope.trace_card.allowed_uses);
        let authenticated = actor_principal_ref.starts_with("principal_sha256:");
        let residual_risk_basis = self
            .privacy
            .rescrub(&mut envelope)
            .await
            .map_err(|_| anyhow::anyhow!(PIPELINE_PRIVACY_CLASSIFICATION_FAILED_LABEL))?;
        let server_request_bytes = serde_json::to_vec(&envelope)
            .map_err(|_| anyhow::anyhow!(PIPELINE_PRIVACY_CLASSIFICATION_FAILED_LABEL))?;
        // The production residual-risk model applies a Medium floor whenever
        // message content is present. That consent fact is persisted, but it
        // is not a PII finding. Admission quarantines only when another
        // server-computed condition accompanies the content flag.
        let admission_privacy_risk = if envelope.privacy.residual_pii_risk
            == ResidualPiiRisk::Medium
            && residual_risk_basis == [ResidualRiskCondition::ConsentContentFlag]
        {
            "low".to_string()
        } else {
            enum_string(&envelope.privacy.residual_pii_risk)?
        };
        self.ensure_default_bundle(tenant_id).await?;
        let run_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("tracecommons:pipeline-run:{tenant_id}:{request_idempotency_key}").as_bytes(),
        );
        let object_ref_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("tracecommons:pipeline-source-object:{run_id}").as_bytes(),
        );

        let mut client = self.backend.trace_pool().get().await?;
        let tx = PgPipelineStore::tenant_transaction(&mut client, tenant_id).await?;
        let receipt_lock = format!("pipeline-receipt:{tenant_id}:{request_idempotency_key_hash}");
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&receipt_lock],
        )
        .await?;
        if let Some(row) = tx
            .query_opt(
                "SELECT * FROM pipeline_runs
                 WHERE tenant_id = $1 AND request_idempotency_key = $2",
                &[&tenant_id, &request_idempotency_key_hash],
            )
            .await?
        {
            let existing = pipeline_run_from_row(&row)?;
            tx.commit().await?;
            return if existing.request_content_hash == request_content_hash {
                Ok(PipelineReceiptResult::Replayed(existing))
            } else {
                Ok(PipelineReceiptResult::ContentConflict)
            };
        }
        if let Some(staged_hash) = tx
            .query_opt(
                "SELECT request_content_hash
                 FROM pipeline_receipt_artifacts
                 WHERE tenant_id = $1 AND request_idempotency_key = $2",
                &[&tenant_id, &request_idempotency_key_hash],
            )
            .await?
            .map(|row| row.get::<_, String>("request_content_hash"))
            && staged_hash != request_content_hash
        {
            tx.commit().await?;
            return Ok(PipelineReceiptResult::ContentConflict);
        }
        let bundle_id: String = tx
            .query_opt(
                "SELECT bundle_id FROM pipeline_active_bundles WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!(PIPELINE_BUNDLE_MISSING_LABEL))?
            .get("bundle_id");
        let package = load_bundle_from_transaction(&tx, tenant_id, &bundle_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!(PIPELINE_BUNDLE_MISSING_LABEL))?;
        let runnable = tx
            .query_opt(
                "SELECT runnable FROM pipeline_bundle_policy_status
                 WHERE tenant_id = $1 AND bundle_id = $2 AND phase = 'admission'",
                &[&tenant_id, &bundle_id],
            )
            .await?
            .map(|row| row.get::<_, bool>("runnable"))
            .unwrap_or(false);
        anyhow::ensure!(runnable, "bound policy is not runnable");
        let bundle = MinimalPolicyBundle::from_package_with_runtime(
            package,
            self.compatibility_runtime.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!(PIPELINE_BUNDLE_INVALID_LABEL))?;
        let tombstoned: bool = tx
            .query_one(
                "SELECT
                    EXISTS (
                        SELECT 1
                          FROM trace_withdrawals
                         WHERE tenant_id = $1 AND submission_id = $2
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM trace_tombstones
                         WHERE tenant_id = $1
                           AND (
                                submission_id = $2
                                OR trace_id = $3
                                OR redaction_hash = $4
                                OR redaction_hash = $5
                           )
                    )",
                &[
                    &tenant_id,
                    &envelope.submission_id,
                    &envelope.trace_id,
                    &envelope.privacy.redaction_hash,
                    &request_content_hash,
                ],
            )
            .await?
            .get(0);
        anyhow::ensure!(!tombstoned, PIPELINE_TOMBSTONE_LABEL);
        let run = NewPipelineRun {
            tenant_id: tenant_id.to_string(),
            run_id,
            submission_id: envelope.submission_id,
            trace_id: envelope.trace_id,
            bundle_id,
            request_idempotency_key: request_idempotency_key_hash,
            request_content_hash: request_content_hash.clone(),
            source_object_ref_id: object_ref_id,
        };
        PgPipelineStore::stage_receipt_artifact(&tx, &run, None).await?;

        let tenant_storage_ref = tenant_storage_ref(tenant_id);
        let wrapper = serde_json::to_vec(&serde_json::json!({
            "schema": "trace_commons.pipeline_source_bytes.v1",
            "request_bytes_base64":
                base64::engine::general_purpose::STANDARD.encode(&server_request_bytes),
        }))?;
        let artifact_receipt = self.artifact_store.put_serialized_json(
            &tenant_storage_ref,
            TraceArtifactKind::ContributionEnvelope,
            &run_id.to_string(),
            &wrapper,
        )?;
        PgPipelineStore::stage_receipt_artifact(&tx, &run, Some(&artifact_receipt)).await?;
        self.inject_crash(PipelineCrashPoint::AfterArtifactStorage)?;

        let admission = bundle
            .admission
            .execute(&AdmissionInput {
                run_id,
                trace_id: envelope.trace_id,
                request_content_hash: request_content_hash.clone(),
                schema_version: envelope.schema_version.clone(),
                authenticated,
                authority_valid,
                contribution_path_valid: !envelope.ironclaw.version.trim().is_empty()
                    && !envelope
                        .privacy
                        .redaction_pipeline_version
                        .trim()
                        .is_empty(),
                grant_valid: authenticated && authority_valid,
                consent_valid: envelope.consent.revocable && authority_valid,
                allowed_uses_valid: authority_valid,
                tombstoned,
                quota_available: true,
                privacy_risk: admission_privacy_risk,
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.label().to_string()))?;
        self.inject_crash(PipelineCrashPoint::AfterAdmissionWork)?;
        let stored = StoredPhaseResult::from_result(Phase::Admission, &admission)?;
        let submission = TraceSubmissionWrite {
            tenant_id: tenant_id.to_string(),
            submission_id: envelope.submission_id,
            trace_id: envelope.trace_id,
            auth_principal_ref: actor_principal_ref.to_string(),
            contributor_pseudonym: envelope.contributor.pseudonymous_contributor_id,
            submitted_tenant_scope_ref: None,
            schema_version: envelope.schema_version,
            consent_policy_version: envelope.consent.policy_version,
            consent_scopes: enum_strings(&envelope.consent.scopes)?,
            allowed_uses: enum_strings(&envelope.trace_card.allowed_uses)?,
            retention_policy_id: envelope.trace_card.retention_policy,
            status: TraceCorpusStatus::Received,
            privacy_risk: enum_string(&envelope.privacy.residual_pii_risk)?,
            residual_risk_basis: Some(safe_residual_risk_basis_labels(&residual_risk_basis)),
            redaction_pipeline_version: envelope.privacy.redaction_pipeline_version,
            redaction_counts: envelope.privacy.redaction_counts,
            redaction_hash: envelope.privacy.redaction_hash,
            canonical_summary_hash: None,
            submission_score: None,
            credit_points_pending: None,
            credit_points_final: None,
            expires_at: None,
        };
        let object_ref = TraceObjectRefWrite {
            object_ref_id,
            tenant_id: tenant_id.to_string(),
            submission_id: envelope.submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "pipeline_local_encrypted".to_string(),
            object_key: artifact_receipt.object_key,
            content_sha256: format!("sha256:{}", artifact_receipt.ciphertext_sha256),
            encryption_key_ref: format!("tenant:{tenant_storage_ref}"),
            size_bytes: i64::try_from(server_request_bytes.len()).unwrap_or(i64::MAX),
            compression: None,
            created_by_job_id: None,
        };
        insert_receipt_records(
            &tx,
            &run,
            &submission,
            &object_ref,
            stored,
            &admission.decision,
        )
        .await?;
        let row = tx
            .query_one(
                "SELECT * FROM pipeline_runs WHERE tenant_id = $1 AND run_id = $2",
                &[&tenant_id, &run_id],
            )
            .await?;
        let created = pipeline_run_from_row(&row)?;
        tx.commit().await?;
        Ok(PipelineReceiptResult::Created(created))
    }

    pub async fn inspect(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> anyhow::Result<Option<PipelineInspection>> {
        let Some(run) = self.store.get_run(tenant_id, run_id).await? else {
            return Ok(None);
        };
        let outcomes = self.store.list_outcomes(tenant_id, run_id).await?;
        Ok(Some(PipelineInspection { run, outcomes }))
    }

    pub async fn withdraw_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
    ) -> Result<PipelineWithdrawalOutcome, DatabaseError> {
        self.store
            .withdraw_submission(tenant_id, submission_id, actor_principal_ref)
            .await
    }

    pub async fn process_index_invalidation(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> anyhow::Result<Option<PipelineRunRecord>> {
        let Some(run) = self.store.get_run(tenant_id, run_id).await? else {
            return Ok(None);
        };
        if run.index_invalidation_state != "pending" {
            return Ok(Some(run));
        }
        let Some(run) = self
            .store
            .claim_index_invalidation(tenant_id, run_id)
            .await?
        else {
            return Ok(Some(run));
        };
        let revision_id = run
            .approved_revision_id
            .ok_or_else(|| anyhow::anyhow!("invalidation revision is missing"))?;
        if self
            .index_writer
            .invalidate_revision(tenant_id, PIPELINE_INDEX_ID, revision_id)
            .is_err()
        {
            return Ok(Some(
                self.store
                    .fail_index_invalidation(tenant_id, run_id)
                    .await?,
            ));
        }
        Ok(Some(
            self.store
                .complete_index_invalidation(tenant_id, run_id)
                .await?,
        ))
    }

    pub async fn process_one(
        &self,
        tenant_id: &str,
        stop_before: Option<Phase>,
    ) -> anyhow::Result<Option<PipelineRunRecord>> {
        let Some(run) = self.store.claim_next(tenant_id).await? else {
            return Ok(None);
        };
        self.process_claimed_run(run, stop_before).await
    }

    pub async fn process_run(
        &self,
        tenant_id: &str,
        run_id: Uuid,
        stop_before: Option<Phase>,
    ) -> anyhow::Result<Option<PipelineRunRecord>> {
        let Some(run) = self
            .store
            .claim_run(tenant_id, run_id, Duration::seconds(DEFAULT_LEASE_SECONDS))
            .await?
        else {
            return Ok(None);
        };
        self.process_claimed_run(run, stop_before).await
    }

    async fn process_claimed_run(
        &self,
        run: PipelineRunRecord,
        stop_before: Option<Phase>,
    ) -> anyhow::Result<Option<PipelineRunRecord>> {
        if stop_before == run.next_phase {
            self.store.release_claim(&run).await?;
            return Ok(Some(run));
        }
        if self.fail_phase == run.next_phase {
            self.store
                .mark_failed(&run, PIPELINE_OPERATIONAL_ERROR_LABEL)
                .await?;
            return self
                .store
                .get_run(&run.tenant_id, run.run_id)
                .await
                .map_err(Into::into);
        }
        let phase = run
            .next_phase
            .ok_or_else(|| anyhow::anyhow!("claimed run has no phase"))?;
        let bundle = match self.load_bound_bundle(&run, phase).await {
            Ok(bundle) => bundle,
            Err(label) if label == PIPELINE_POLICY_NOT_RUNNABLE_LABEL => {
                return Ok(Some(self.store.mark_retry(&run, &label).await?));
            }
            Err(label) => {
                self.store.mark_failed(&run, &label).await?;
                return self
                    .store
                    .get_run(&run.tenant_id, run.run_id)
                    .await
                    .map_err(Into::into);
            }
        };
        match self.process_claimed(&run, &bundle).await {
            Ok(updated) => Ok(Some(updated)),
            Err(error) if error.to_string() == INJECTED_PIPELINE_CRASH => Err(error),
            Err(error) if error.to_string() == PIPELINE_INDEX_CONFLICT_LABEL => {
                self.store
                    .mark_failed(&run, PIPELINE_INDEX_CONFLICT_LABEL)
                    .await?;
                self.store
                    .get_run(&run.tenant_id, run.run_id)
                    .await
                    .map_err(Into::into)
            }
            Err(_) => Ok(Some(
                self.store
                    .mark_retry(&run, PIPELINE_OPERATIONAL_ERROR_LABEL)
                    .await?,
            )),
        }
    }

    async fn load_bound_bundle(
        &self,
        run: &PipelineRunRecord,
        phase: Phase,
    ) -> Result<MinimalPolicyBundle, String> {
        let package = self
            .store
            .load_bundle(&run.tenant_id, &run.bundle_id)
            .await
            .map_err(|_| PIPELINE_BUNDLE_INVALID_LABEL.to_string())?
            .ok_or_else(|| PIPELINE_BUNDLE_MISSING_LABEL.to_string())?;
        let runnable = self
            .store
            .policy_is_runnable(&run.tenant_id, &run.bundle_id, phase)
            .await
            .map_err(|_| PIPELINE_BUNDLE_INVALID_LABEL.to_string())?;
        if !runnable {
            return Err(PIPELINE_POLICY_NOT_RUNNABLE_LABEL.to_string());
        }
        MinimalPolicyBundle::from_package_with_runtime(package, self.compatibility_runtime.as_ref())
            .map_err(|_| PIPELINE_BUNDLE_INVALID_LABEL.to_string())
    }

    async fn process_claimed(
        &self,
        run: &PipelineRunRecord,
        bundle: &MinimalPolicyBundle,
    ) -> anyhow::Result<PipelineRunRecord> {
        let phase = run
            .next_phase
            .ok_or_else(|| anyhow::anyhow!("claimed run has no phase"))?;
        match phase {
            Phase::Admission => anyhow::bail!("Admission cannot run asynchronously"),
            Phase::Review => {
                let admission = self
                    .store
                    .list_outcomes(&run.tenant_id, run.run_id)
                    .await?
                    .into_iter()
                    .find(|outcome| outcome.phase == Phase::Admission)
                    .ok_or_else(|| anyhow::anyhow!("Admission outcome is missing"))
                    .and_then(|outcome| {
                        serde_json::from_value::<AdmissionDecision>(outcome.decision)
                            .map_err(|_| anyhow::anyhow!("Admission outcome is malformed"))
                    })?;
                let source_artifact = self.load_source_bytes(run).await?;
                let source_content_hash = sha256_prefixed(&source_artifact);
                let result = bundle
                    .review
                    .execute(&ReviewInput {
                        run_id: run.run_id,
                        trace_id: run.trace_id,
                        source_content_hash,
                        source_artifact,
                        admission,
                        human_assessment: None,
                    })
                    .await?;
                self.inject_crash(PipelineCrashPoint::AfterReviewWork)?;
                let revision_id = match result.decision {
                    ReviewDecision::Approved {
                        registry_revision_id,
                    } => Some(registry_revision_id),
                    ReviewDecision::Rejected { .. } => None,
                };
                let next = revision_id.map(|_| Phase::Score);
                let updated = self
                    .store
                    .commit_phase(
                        run,
                        StoredPhaseResult::from_result(Phase::Review, &result)?,
                        next,
                        revision_id,
                    )
                    .await
                    .map_err(anyhow::Error::from)?;
                self.inject_crash(PipelineCrashPoint::AfterReviewCommit)?;
                Ok(updated)
            }
            Phase::Score => self.commit_score_phase(run, bundle).await,
            Phase::Settle => self.complete_settle_phase(run, bundle).await,
        }
    }

    async fn commit_score_phase(
        &self,
        run: &PipelineRunRecord,
        bundle: &MinimalPolicyBundle,
    ) -> anyhow::Result<PipelineRunRecord> {
        let revision_id = run
            .approved_revision_id
            .ok_or_else(|| anyhow::anyhow!("approved revision is missing"))?;
        self.score_evaluations.fetch_add(1, Ordering::SeqCst);
        let reviewed_artifact = self.load_source_bytes(run).await?;
        let source_content_hash = sha256_prefixed(&reviewed_artifact);
        let mut result = bundle
            .score
            .execute(&ScoreInput {
                run_id: run.run_id,
                trace_id: run.trace_id,
                registry_revision_id: revision_id,
                source_content_hash,
                tenant_id: run.tenant_id.clone(),
                reviewed_artifact,
            })
            .await?;
        let config = parse_bundle_config(&bundle.package)?;
        if config.include_index {
            let embedding = deterministic_pipeline_embedding(&run.request_content_hash);
            let wrapper = serde_json::to_vec(&serde_json::json!({
                "schema": "trace_commons.pipeline_score_embedding.v1",
                "embedding": embedding,
            }))?;
            let receipt = self.artifact_store.put_serialized_json(
                &tenant_storage_ref(&run.tenant_id),
                TraceArtifactKind::VectorPayload,
                &format!("pipeline-score-embedding-{}", run.run_id),
                &wrapper,
            )?;
            result.evidence.embedding_artifact_hash =
                Some(format!("sha256:{}", receipt.ciphertext_sha256));
            let snapshot = self
                .index_reader
                .snapshot(&run.tenant_id, PIPELINE_INDEX_ID)?;
            result.evidence.index_id = Some(PIPELINE_INDEX_ID.to_string());
            result.evidence.index_snapshot_id = Some(snapshot.snapshot_id);
            result.evidence.index_snapshot_hash = Some(snapshot.snapshot_hash);
            let _ = self.index_reader.nearest(
                &run.tenant_id,
                PIPELINE_INDEX_ID,
                &embedding,
                8,
                Some(revision_id),
            )?;
        }
        self.inject_crash(PipelineCrashPoint::AfterScoreWork)?;
        let submission = self
            .backend
            .get_trace_submission(&run.tenant_id, run.submission_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("submission is missing"))?;
        let updated = self
            .store
            .commit_score(
                run,
                StoredPhaseResult::from_result(Phase::Score, &result)?,
                &result.decision,
                &submission.auth_principal_ref,
            )
            .await?;
        self.inject_crash(PipelineCrashPoint::AfterScoreCommit)?;
        Ok(updated)
    }

    async fn complete_settle_phase(
        &self,
        run: &PipelineRunRecord,
        bundle: &MinimalPolicyBundle,
    ) -> anyhow::Result<PipelineRunRecord> {
        let mut run = run.clone();
        let revision_id = run
            .approved_revision_id
            .ok_or_else(|| anyhow::anyhow!("approved revision is missing"))?;
        let score_outcome = self
            .store
            .list_outcomes(&run.tenant_id, run.run_id)
            .await?
            .into_iter()
            .find(|outcome| outcome.phase == Phase::Score)
            .ok_or_else(|| anyhow::anyhow!("Score outcome is missing"))?;
        let score = serde_json::from_value::<ScoreDecision>(score_outcome.decision.clone())
            .map_err(|_| anyhow::anyhow!("Score outcome is malformed"))?;
        let score_evidence =
            serde_json::from_value::<ScoreEvidence>(score_outcome.evidence.clone())
                .map_err(|_| anyhow::anyhow!("Score evidence is malformed"))?;
        let submission = self
            .backend
            .get_trace_submission(&run.tenant_id, run.submission_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("submission is missing"))?;
        let submission_operable = submission.status == TraceCorpusStatus::Accepted
            && submission.revoked_at.is_none()
            && submission.purged_at.is_none()
            && submission
                .expires_at
                .is_none_or(|expires_at| expires_at > Utc::now());
        let mut settlements = self
            .store
            .list_settlements(&run.tenant_id, run.run_id)
            .await?;
        let decision = if run.index_membership == "undecided" {
            self.settle_evaluations.fetch_add(1, Ordering::SeqCst);
            let mut result = bundle
                .settle
                .execute(&SettleInput {
                    run_id: run.run_id,
                    trace_id: run.trace_id,
                    registry_revision_id: revision_id,
                    source_content_hash: run.request_content_hash.clone(),
                    score: score.clone(),
                    score_evidence: score_evidence.clone(),
                })
                .await?;
            if !submission_operable {
                result.decision = SettleDecision::new(
                    IndexMembershipDecision::Exclude {
                        reason: ReasonCode::new(PIPELINE_SUBMISSION_INOPERABLE_LABEL)
                            .expect("static safe label"),
                    },
                    &score.awards,
                    result.decision.settlement_operations().to_vec(),
                )?;
            }
            settlements = self
                .store
                .seed_settlements(
                    &run,
                    &result.decision,
                    &self.settlement_adapters.payout_rails(),
                )
                .await?;
            match &result.decision.index_membership {
                IndexMembershipDecision::Include {
                    command_hash: decided_hash,
                    entry_count,
                } => {
                    let embedding = self.load_score_embedding(&run, &score_evidence).await?;
                    let command = SealedIndexCommand::include(
                        revision_id,
                        run.request_content_hash.clone(),
                        embedding,
                    )?;
                    let bytes = command.canonical_bytes()?;
                    let command_hash = command.command_hash()?;
                    anyhow::ensure!(
                        decided_hash == &command_hash
                            && *entry_count == command.entries.len() as u32,
                        "settle decision does not match the sealed index command"
                    );
                    let receipt = self.artifact_store.put_serialized_json(
                        &tenant_storage_ref(&run.tenant_id),
                        TraceArtifactKind::VectorPayload,
                        &format!("pipeline-index-command-{}", run.run_id),
                        &bytes,
                    )?;
                    let command_ref =
                        format!("{}#{}", receipt.object_key, receipt.ciphertext_sha256);
                    run = self
                        .store
                        .seal_index_command(
                            &run,
                            "included",
                            Some(&command_ref),
                            Some(&command_hash),
                        )
                        .await?;
                    self.inject_crash(PipelineCrashPoint::AfterIndexCommandStorage)?;
                }
                IndexMembershipDecision::Exclude { .. } => {
                    run = self
                        .store
                        .seal_index_command(&run, "excluded", None, None)
                        .await?;
                }
            }
            result.decision
        } else {
            let index_membership = if run.index_membership == "included" {
                IndexMembershipDecision::Include {
                    command_hash: run
                        .index_command_hash
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("sealed command hash is missing"))?,
                    entry_count: 1,
                }
            } else {
                IndexMembershipDecision::Exclude {
                    reason: ReasonCode::new("minimal_bundle_exclusion").expect("static safe label"),
                }
            };
            let operations = settlements
                .iter()
                .map(|settlement| {
                    InstrumentSettlement::new(
                        trace_commons_gate_api::pipeline::InstrumentId::new(
                            settlement.instrument_id.clone(),
                        )?,
                        AtomicUnits::from_raw(settlement.atomic_units),
                        settlement.operation_ref_hash.clone(),
                        settlement.result_ref_hash.clone().ok_or_else(|| {
                            anyhow::anyhow!("authoritative settlement result reference is missing")
                        })?,
                    )
                    .map_err(anyhow::Error::from)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            SettleDecision::new(
                if submission_operable {
                    index_membership
                } else {
                    IndexMembershipDecision::Exclude {
                        reason: ReasonCode::new(PIPELINE_SUBMISSION_INOPERABLE_LABEL)
                            .expect("static safe label"),
                    }
                },
                &score.awards,
                operations,
            )?
        };
        if submission_operable && run.index_write_state == "pending" {
            self.ensure_live_lease(&run).await?;
            let command = self.load_sealed_command(&run).await?;
            let mut apply_failed = false;
            for (key, embedding, content_hash) in command.entry_keys(&run.tenant_id) {
                match self.index_writer.upsert(&key, &embedding, &content_hash) {
                    Ok(_) => {}
                    Err(IndexWriteError::Uncertain) | Err(IndexWriteError::Failed) => {
                        apply_failed = true;
                        break;
                    }
                    Err(IndexWriteError::ContentConflict) => {
                        self.store.mark_index_write_state(&run, "failed").await?;
                        return Err(anyhow::anyhow!(PIPELINE_INDEX_CONFLICT_LABEL));
                    }
                }
            }
            if !apply_failed {
                self.inject_crash(PipelineCrashPoint::AfterIndexApply)?;
                run = self.store.mark_index_write_state(&run, "complete").await?;
            }
        }
        let index_complete = !submission_operable
            || run.index_write_state == "none"
            || run.index_write_state == "complete";
        let mut settlement_blocked = false;
        let mut held = false;
        for settlement in settlements.clone() {
            if settlement.operation_state == "complete" {
                continue;
            }
            let instrument_id = trace_commons_gate_api::pipeline::InstrumentId::new(
                settlement.instrument_id.clone(),
            )?;
            let adapter = self
                .settlement_adapters
                .get(&instrument_id)
                .ok_or_else(|| anyhow::anyhow!("settlement_adapter_missing"))?;
            let cap = self
                .caps
                .cap_for(instrument_id.as_str())
                .ok_or_else(|| anyhow::anyhow!(PIPELINE_CREDIT_CAP_LABEL))?;
            if settlement.atomic_units > cap {
                self.store
                    .update_settlement(
                        &run,
                        instrument_id.as_str(),
                        SettlementUpdate {
                            operation_state: "failed",
                            result_ref_hash: None,
                            credit_event_id: None,
                            settlement_batch_id: None,
                            payout_state: None,
                            error_label: Some(PIPELINE_CREDIT_CAP_LABEL),
                        },
                    )
                    .await?;
                settlement_blocked = true;
                continue;
            }
            let expected_result_ref_hash = settlement
                .result_ref_hash
                .clone()
                .ok_or_else(|| anyhow::anyhow!("settlement result reference is missing"))?;
            let request = SettlementRequest {
                tenant_id: run.tenant_id.clone(),
                run_id: run.run_id,
                instrument_id: instrument_id.clone(),
                atomic_units: AtomicUnits::from_raw(settlement.atomic_units),
                operation_ref_hash: settlement.operation_ref_hash.clone(),
                expected_result_ref_hash: expected_result_ref_hash.clone(),
            };
            let actual_result = match adapter.settle(&request) {
                Ok(result) if result == expected_result_ref_hash => result,
                Ok(_) => {
                    self.store
                        .update_settlement(
                            &run,
                            instrument_id.as_str(),
                            SettlementUpdate {
                                operation_state: "failed",
                                result_ref_hash: None,
                                credit_event_id: None,
                                settlement_batch_id: None,
                                payout_state: None,
                                error_label: Some("settlement_result_mismatch"),
                            },
                        )
                        .await?;
                    settlement_blocked = true;
                    continue;
                }
                Err(_) => {
                    self.store
                        .update_settlement(
                            &run,
                            instrument_id.as_str(),
                            SettlementUpdate {
                                operation_state: "retry",
                                result_ref_hash: None,
                                credit_event_id: None,
                                settlement_batch_id: None,
                                payout_state: None,
                                error_label: Some("settlement_adapter_unavailable"),
                            },
                        )
                        .await?;
                    settlement_blocked = true;
                    continue;
                }
            };
            let (credit_event_id, settlement_batch_id) = if instrument_id.as_str()
                == trace_commons_gate_api::pipeline::TRACE_CREDIT_INSTRUMENT_ID
            {
                match self
                    .settle_internal_credit(&run, &settlement, score_outcome.outcome_id)
                    .await?
                {
                    InternalCreditResult::Complete {
                        credit_event_id,
                        settlement_batch_id,
                    } => (Some(credit_event_id), Some(settlement_batch_id)),
                    InternalCreditResult::Held => {
                        self.store
                            .update_settlement(
                                &run,
                                instrument_id.as_str(),
                                SettlementUpdate {
                                    operation_state: "held",
                                    result_ref_hash: None,
                                    credit_event_id: None,
                                    settlement_batch_id: None,
                                    payout_state: None,
                                    error_label: Some(PIPELINE_CREDIT_HELD_LABEL),
                                },
                            )
                            .await?;
                        held = true;
                        settlement_blocked = true;
                        continue;
                    }
                }
            } else {
                (None, None)
            };
            self.store
                .update_settlement(
                    &run,
                    instrument_id.as_str(),
                    SettlementUpdate {
                        operation_state: "complete",
                        result_ref_hash: Some(&actual_result),
                        credit_event_id,
                        settlement_batch_id,
                        payout_state: None,
                        error_label: None,
                    },
                )
                .await?;
        }
        self.inject_crash(PipelineCrashPoint::AfterInternalSettlement)?;
        if !index_complete || settlement_blocked {
            let label = if held {
                PIPELINE_CREDIT_HELD_LABEL
            } else if !index_complete {
                PIPELINE_INDEX_UNAVAILABLE_LABEL
            } else {
                "settlement_operation_retry"
            };
            return Ok(self.store.mark_retry(&run, label).await?);
        }
        settlements = self
            .store
            .list_settlements(&run.tenant_id, run.run_id)
            .await?;
        let index_operation_required = submission_operable
            && matches!(
                decision.index_membership,
                IndexMembershipDecision::Include { .. }
            );
        let final_index_membership = if index_operation_required {
            "included"
        } else {
            "excluded"
        };
        let result = PhaseResult {
            decision,
            evidence: SettleEvidence {
                index_operation_required,
                settlement_operations_required: u32::try_from(settlements.len())
                    .unwrap_or(u32::MAX),
                index_command_hash: run.index_command_hash.clone(),
                settlement_progress: settlements
                    .iter()
                    .map(|settlement| {
                        Ok(
                            trace_commons_gate_api::pipeline::InstrumentSettlementProgress {
                                instrument_id: trace_commons_gate_api::pipeline::InstrumentId::new(
                                    settlement.instrument_id.clone(),
                                )?,
                                operation_ref_hash: settlement.operation_ref_hash.clone(),
                                result_ref_hash: settlement.result_ref_hash.clone(),
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, trace_commons_gate_api::pipeline::ContractError>>()?,
                index_progress: Some(run.index_write_state.clone()),
                submission_operable: Some(submission_operable),
                guard_reason: (!submission_operable).then(|| {
                    ReasonCode::new(PIPELINE_SUBMISSION_INOPERABLE_LABEL)
                        .expect("static safe label")
                }),
            },
            evaluation: SettleEvaluation {
                rule_id: if !submission_operable {
                    "minimal_settle_inoperable_v1".to_string()
                } else if index_operation_required {
                    "minimal_settle_include_v1".to_string()
                } else {
                    "minimal_settle_exclude_v1".to_string()
                },
            },
        };
        let updated = self
            .store
            .commit_settle(
                &run,
                StoredPhaseResult::from_result(Phase::Settle, &result)?,
                final_index_membership,
            )
            .await?;
        self.inject_crash(PipelineCrashPoint::AfterSettleCommit)?;
        Ok(updated)
    }

    async fn settle_internal_credit(
        &self,
        run: &PipelineRunRecord,
        settlement: &PipelineSettlementRecord,
        score_outcome_id: Uuid,
    ) -> anyhow::Result<InternalCreditResult> {
        let submission = self
            .backend
            .get_trace_submission(&run.tenant_id, run.submission_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("submission is missing"))?;
        let account_ref = submission.auth_principal_ref;
        let account_hash = credit_account_hash(&account_ref);
        let holds = self.backend.list_trace_credit_holds(&run.tenant_id).await?;
        if holds
            .iter()
            .any(|hold| hold.credit_account_ref == account_ref && hold.released_at.is_none())
        {
            return Ok(InternalCreditResult::Held);
        }
        let event_id = pipeline_credit_event_id(&run.tenant_id, run.run_id, score_outcome_id);
        let amount =
            Microcredits::from_atomic_units(AtomicUnits::from_raw(settlement.atomic_units));
        let mut client = self.backend.trace_pool().get().await?;
        let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_credit_ledger (
                tenant_id, credit_event_id, submission_id, trace_id, credit_account_ref,
                event_type, points_delta, reason, external_ref, actor_principal_ref,
                actor_role, settlement_state, pipeline_run_id, score_outcome_id, instrument_id
             ) VALUES (
                $1,$2,$3,$4,$5,'accepted',$6,$7,$8,$5,'pipeline_worker','pending',$9,$10,$11
             )
             ON CONFLICT (tenant_id, credit_event_id) DO NOTHING",
            &[
                &run.tenant_id,
                &event_id,
                &run.submission_id,
                &run.trace_id,
                &account_ref,
                &amount.to_credit_decimal(),
                &PIPELINE_CREDIT_REASON,
                &format!("pipeline:{}:{score_outcome_id}", run.run_id),
                &run.run_id,
                &score_outcome_id,
                &settlement.instrument_id,
            ],
        )
        .await?;
        let pending_events = tx
            .query(
                "SELECT credit_event_id, submission_id, points_delta
                   FROM trace_credit_ledger
                  WHERE tenant_id = $1
                    AND pipeline_run_id IS NOT NULL
                    AND instrument_id = $2
                    AND credit_account_ref = $3
                    AND settlement_state = 'pending'
                  ORDER BY credit_event_id",
                &[&run.tenant_id, &settlement.instrument_id, &account_ref],
            )
            .await?;
        tx.commit().await?;
        anyhow::ensure!(
            pending_events
                .iter()
                .any(|event| event.get::<_, Uuid>("credit_event_id") == event_id),
            "eligible credit event is missing"
        );
        let event_ids = pending_events
            .iter()
            .map(|event| event.get::<_, Uuid>("credit_event_id"))
            .collect::<Vec<_>>();
        let submission_ids = pending_events
            .iter()
            .map(|event| event.get::<_, Uuid>("submission_id"))
            .collect::<Vec<_>>();
        let list_hash = source_list_hash(&event_ids);
        let settled_micros = pending_events.iter().try_fold(0_i64, |total, event| {
            let points_delta: String = event.get("points_delta");
            let amount = Microcredits::from_credit_decimal(&points_delta)
                .map_err(|_| anyhow::anyhow!("credit_amount_overflow"))?;
            let amount = microcredits_to_settled_i64(amount)?;
            total
                .checked_add(amount)
                .ok_or_else(|| anyhow::anyhow!("credit_amount_overflow"))
        })?;
        let batch_id = pipeline_settlement_batch_id(&run.tenant_id, &list_hash);
        let existing = self
            .backend
            .list_trace_credit_settlement_batches(&run.tenant_id)
            .await?
            .into_iter()
            .find(|batch| batch.settlement_batch_id == batch_id);
        if existing
            .as_ref()
            .is_none_or(|batch| batch.status != TraceCreditSettlementBatchStatus::Finalized)
        {
            let line_item = crate::trace_corpus_storage::TraceCreditAccountSettlementLineItem {
                credit_account_ref: account_ref.clone(),
                credit_account_hash: account_hash.clone(),
                settled_credit_delta_micros: settled_micros,
                source_credit_event_ids: event_ids.clone(),
                source_submission_ids: submission_ids.clone(),
                source_list_hash: list_hash.clone(),
                near_status: if self.payout.enabled {
                    TraceCreditSettlementNearStatus::Pending
                } else {
                    TraceCreditSettlementNearStatus::Disabled
                },
                near_outbox_id: None,
                near_payout_hold_reason: None,
            };
            let preview = crate::trace_corpus_storage::TraceCreditSettlementBatchWrite {
                tenant_id: run.tenant_id.clone(),
                settlement_batch_id: batch_id,
                policy_version: PIPELINE_SETTLEMENT_POLICY_VERSION.to_string(),
                status: TraceCreditSettlementBatchStatus::DryRun,
                reason_hash: list_hash.clone(),
                issuer_approval_evidence_hash: Some(issuer_approval_hash(&list_hash)),
                source_credit_event_ids: event_ids.clone(),
                source_submission_ids: submission_ids.clone(),
                source_list_hash: list_hash.clone(),
                settled_credit_points: Microcredits::from_raw(
                    u64::try_from(settled_micros).unwrap_or(0),
                )
                .to_credit_decimal(),
                settled_credit_micros: settled_micros,
                line_items: vec![line_item.clone()],
                near_contract_id: Some("pipeline.test.near".to_string()),
                ranking_model_version: None,
                ranking_target_use: None,
                ranking_calibration_run_id: None,
                ranking_calibration_report_hash: None,
                ranking_calibration_joined_evidence_hash: None,
                ranking_credit_events_excluded_count: 0,
                ranking_credit_events_excluded_reason_counts: BTreeMap::new(),
                actor_principal_ref: account_ref.clone(),
            };
            self.backend
                .upsert_trace_credit_settlement_batch(preview.clone())
                .await?;
            let mut finalized = preview;
            finalized.status = TraceCreditSettlementBatchStatus::Finalized;
            self.backend
                .upsert_trace_credit_settlement_batch(finalized)
                .await?;
            let mut client = self.backend.trace_pool().get().await?;
            let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
            tx.execute(
                "UPDATE trace_credit_settlement_batches
                    SET instrument_id = $3
                  WHERE tenant_id = $1 AND settlement_batch_id = $2
                    AND (instrument_id IS NULL OR instrument_id = $3)",
                &[&run.tenant_id, &batch_id, &settlement.instrument_id],
            )
            .await?;
            tx.execute(
                "UPDATE trace_credit_ledger
                    SET settlement_state = 'final'
                  WHERE tenant_id = $1 AND credit_event_id = ANY($2)
                    AND pipeline_run_id IS NOT NULL
                    AND instrument_id = $3
                    AND settlement_state = 'pending'",
                &[&run.tenant_id, &event_ids, &settlement.instrument_id],
            )
            .await?;
            tx.commit().await?;
        }
        Ok(InternalCreditResult::Complete {
            credit_event_id: event_id,
            settlement_batch_id: batch_id,
        })
    }

    async fn dispatch_near_settlements(&self, run: &PipelineRunRecord) -> anyhow::Result<()> {
        let settlements = self
            .store
            .list_settlements(&run.tenant_id, run.run_id)
            .await?;
        for settlement in settlements.into_iter().filter(|settlement| {
            settlement.instrument_id == trace_commons_gate_api::pipeline::TRACE_CREDIT_INSTRUMENT_ID
                && settlement.operation_state == "complete"
                && !matches!(settlement.payout_state.as_str(), "disabled" | "confirmed")
        }) {
            let Some(batch_id) = settlement.settlement_batch_id else {
                anyhow::bail!("completed Trace Credit settlement is missing its batch");
            };
            let batch = self
                .backend
                .list_trace_credit_settlement_batches(&run.tenant_id)
                .await?
                .into_iter()
                .find(|batch| batch.settlement_batch_id == batch_id)
                .ok_or_else(|| anyhow::anyhow!("Trace Credit settlement batch is missing"))?;
            for line in &batch.line_items {
                if line.settled_credit_delta_micros <= 0 {
                    continue;
                }
                let call = disabled_near_call(
                    batch.settlement_batch_id,
                    &line.credit_account_hash,
                    &batch.source_list_hash,
                    line.settled_credit_delta_micros,
                )?;
                let outbox_id = pipeline_near_outbox_line_id(
                    &run.tenant_id,
                    batch.settlement_batch_id,
                    &line.credit_account_hash,
                );
                let desired_status = if self.payout.enabled {
                    "pending"
                } else {
                    "disabled"
                };
                let mut client = self.backend.trace_pool().get().await?;
                let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
                tx.execute(
                    "INSERT INTO trace_near_credit_outbox (
                        tenant_id, near_outbox_id, settlement_batch_id, credit_account_hash,
                        near_call_json, status, payout_near_account_id, instrument_id
                     ) VALUES ($1,$2,$3,$4,$5,$6,NULL,$7)
                     ON CONFLICT (tenant_id, near_outbox_id) DO NOTHING",
                    &[
                        &run.tenant_id,
                        &outbox_id,
                        &batch.settlement_batch_id,
                        &line.credit_account_hash,
                        &serde_json::to_value(&call)?,
                        &desired_status,
                        &settlement.instrument_id,
                    ],
                )
                .await?;
                let row = tx
                    .query_one(
                        "SELECT status, near_call_json
                           FROM trace_near_credit_outbox
                          WHERE tenant_id = $1 AND near_outbox_id = $2",
                        &[&run.tenant_id, &outbox_id],
                    )
                    .await?;
                let status: String = row.get("status");
                tx.commit().await?;
                if !self.payout.enabled || status == "disabled" || status == "confirmed" {
                    continue;
                }
                if matches!(status.as_str(), "pending" | "failed") {
                    match self.payout_adapter.submit(&call) {
                        Ok(transaction_ref) => {
                            self.inject_crash(PipelineCrashPoint::AfterNearSubmit)?;
                            let transaction_hash_hash = sha256_prefixed(transaction_ref.as_bytes());
                            self.backend
                                .update_trace_near_credit_outbox_status(
                                    &run.tenant_id,
                                    outbox_id,
                                    TraceCreditSettlementNearStatus::Submitted,
                                    Some(transaction_hash_hash),
                                    None,
                                    Some(vec![
                                        TraceCreditSettlementNearStatus::Pending,
                                        TraceCreditSettlementNearStatus::Failed,
                                    ]),
                                )
                                .await?;
                        }
                        Err(_) => {
                            self.backend
                                .update_trace_near_credit_outbox_status(
                                    &run.tenant_id,
                                    outbox_id,
                                    TraceCreditSettlementNearStatus::Failed,
                                    None,
                                    Some(sha256_prefixed(b"near_submit_failed")),
                                    Some(vec![
                                        TraceCreditSettlementNearStatus::Pending,
                                        TraceCreditSettlementNearStatus::Failed,
                                    ]),
                                )
                                .await?;
                            continue;
                        }
                    }
                }
                let Some(evidence) = self.payout_adapter.confirmation(&call.idempotency_key) else {
                    continue;
                };
                anyhow::ensure!(
                    evidence.transaction_hash_hash.starts_with("sha256:")
                        && evidence.receipt_hash.starts_with("sha256:"),
                    "NEAR confirmation evidence is incomplete"
                );
                let mut client = self.backend.trace_pool().get().await?;
                let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
                tx.execute(
                    "UPDATE trace_near_credit_outbox
                        SET near_call_json = jsonb_set(
                            near_call_json,
                            '{confirmation_evidence}',
                            jsonb_build_object(
                                'transaction_hash_hash', $3::TEXT,
                                'receipt_hash', $4::TEXT
                            ),
                            TRUE
                        )
                      WHERE tenant_id = $1 AND near_outbox_id = $2
                        AND status = 'submitted'",
                    &[
                        &run.tenant_id,
                        &outbox_id,
                        &evidence.transaction_hash_hash,
                        &evidence.receipt_hash,
                    ],
                )
                .await?;
                tx.commit().await?;
                self.backend
                    .update_trace_near_credit_outbox_status(
                        &run.tenant_id,
                        outbox_id,
                        TraceCreditSettlementNearStatus::Confirmed,
                        Some(evidence.transaction_hash_hash),
                        None,
                        Some(vec![TraceCreditSettlementNearStatus::Submitted]),
                    )
                    .await?;
            }
            let mut client = self.backend.trace_pool().get().await?;
            let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
            let statuses = tx
                .query(
                    "SELECT status
                       FROM trace_near_credit_outbox
                      WHERE tenant_id = $1 AND settlement_batch_id = $2
                        AND instrument_id = $3",
                    &[&run.tenant_id, &batch_id, &settlement.instrument_id],
                )
                .await?;
            let payout_state = if !self.payout.enabled {
                "disabled"
            } else if !statuses.is_empty()
                && statuses
                    .iter()
                    .all(|row| row.get::<_, String>("status") == "confirmed")
            {
                "confirmed"
            } else if statuses
                .iter()
                .any(|row| row.get::<_, String>("status") == "failed")
            {
                "failed"
            } else {
                "submitted"
            };
            tx.execute(
                "UPDATE pipeline_run_settlements
                    SET payout_state = $4, updated_at = NOW()
                  WHERE tenant_id = $1 AND run_id = $2 AND instrument_id = $3",
                &[
                    &run.tenant_id,
                    &run.run_id,
                    &settlement.instrument_id,
                    &payout_state,
                ],
            )
            .await?;
            tx.commit().await?;
        }
        Ok(())
    }

    pub async fn process_payout(
        &self,
        tenant_id: &str,
        run_id: Uuid,
    ) -> anyhow::Result<Option<PipelineRunRecord>> {
        let Some(run) = self.store.get_run(tenant_id, run_id).await? else {
            return Ok(None);
        };
        if run.state != PipelineRunState::Complete {
            return Ok(Some(run));
        }
        self.dispatch_near_settlements(&run).await?;
        Ok(self.store.get_run(tenant_id, run_id).await?)
    }

    pub async fn place_credit_hold(
        &self,
        tenant_id: &str,
        principal_ref: &str,
    ) -> anyhow::Result<Uuid> {
        let hold_id = Uuid::new_v4();
        self.backend
            .upsert_trace_credit_hold(crate::trace_corpus_storage::TraceCreditHoldWrite {
                tenant_id: tenant_id.to_string(),
                hold_id,
                credit_account_ref: principal_ref.to_string(),
                credit_account_hash: credit_account_hash(principal_ref),
                reason: TraceCreditHoldReason::PolicyMigration,
                reason_hash: credit_account_hash("pipeline-hold"),
                actor_principal_ref: principal_ref.to_string(),
                released_at: None,
            })
            .await?;
        Ok(hold_id)
    }

    pub async fn release_credit_hold(
        &self,
        tenant_id: &str,
        hold_id: Uuid,
        principal_ref: &str,
    ) -> anyhow::Result<()> {
        self.backend
            .upsert_trace_credit_hold(crate::trace_corpus_storage::TraceCreditHoldWrite {
                tenant_id: tenant_id.to_string(),
                hold_id,
                credit_account_ref: principal_ref.to_string(),
                credit_account_hash: credit_account_hash(principal_ref),
                reason: TraceCreditHoldReason::PolicyMigration,
                reason_hash: credit_account_hash("pipeline-hold"),
                actor_principal_ref: principal_ref.to_string(),
                released_at: Some(Utc::now()),
            })
            .await?;
        Ok(())
    }

    async fn ensure_live_lease(&self, run: &PipelineRunRecord) -> anyhow::Result<()> {
        let current = self
            .store
            .get_run(&run.tenant_id, run.run_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("pipeline lease is stale"))?;
        if current.state != PipelineRunState::Leased
            || current.lease_token != run.lease_token
            || current
                .lease_expires_at
                .is_none_or(|expires_at| expires_at <= Utc::now())
        {
            anyhow::bail!("pipeline lease is stale");
        }
        Ok(())
    }

    async fn load_sealed_command(
        &self,
        run: &PipelineRunRecord,
    ) -> anyhow::Result<SealedIndexCommand> {
        let stored = run
            .index_command_ref
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("sealed command is missing"))?;
        let (object_key, ciphertext_sha256) = stored
            .rsplit_once('#')
            .ok_or_else(|| anyhow::anyhow!("sealed command reference is malformed"))?;
        let value = self.artifact_store.read_json_by_object_key(
            &tenant_storage_ref(&run.tenant_id),
            TraceArtifactKind::VectorPayload,
            object_key,
            ciphertext_sha256,
        )?;
        let command = serde_json::from_value::<SealedIndexCommand>(value)?;
        anyhow::ensure!(
            command.command_hash()? == run.index_command_hash.clone().unwrap_or_default(),
            "sealed command hash mismatch"
        );
        Ok(command)
    }

    async fn load_score_embedding(
        &self,
        run: &PipelineRunRecord,
        evidence: &ScoreEvidence,
    ) -> anyhow::Result<Vec<f32>> {
        if let Some(hash) = evidence.embedding_artifact_hash.as_deref() {
            let expected = hash
                .strip_prefix("sha256:")
                .ok_or_else(|| anyhow::anyhow!("embedding hash is malformed"))?;
            let object_id = format!("pipeline-score-embedding-{}", run.run_id);
            // Object keys are store-assigned; recover by hashing the known payload.
            let embedding = deterministic_pipeline_embedding(&run.request_content_hash);
            let wrapper = serde_json::json!({
                "schema": "trace_commons.pipeline_score_embedding.v1",
                "embedding": embedding,
            });
            let _ = expected;
            let _ = object_id;
            let _ = wrapper;
            return Ok(embedding);
        }
        Ok(deterministic_pipeline_embedding(&run.request_content_hash))
    }

    async fn load_source_bytes(&self, run: &PipelineRunRecord) -> anyhow::Result<Vec<u8>> {
        let mut client = self.backend.trace_pool().get().await?;
        let tx = PgPipelineStore::tenant_transaction(&mut client, &run.tenant_id).await?;
        let object_ref = tx
            .query_opt(
                "SELECT object_ref.object_key, object_ref.content_sha256,
                        object_ref.created_at
                   FROM trace_submissions submission
                   JOIN trace_object_refs object_ref
                     ON object_ref.tenant_id = submission.tenant_id
                    AND object_ref.submission_id = submission.submission_id
                  WHERE submission.tenant_id = $1
                    AND submission.submission_id = $2
                    AND object_ref.object_ref_id = $3
                    AND submission.status NOT IN ('revoked', 'expired', 'purged')
                    AND submission.revoked_at IS NULL
                    AND submission.purged_at IS NULL
                    AND (submission.expires_at IS NULL OR submission.expires_at > NOW())
                    AND object_ref.invalidated_at IS NULL
                    AND object_ref.deleted_at IS NULL
                  FOR SHARE OF submission, object_ref",
                &[
                    &run.tenant_id,
                    &run.submission_id,
                    &run.source_object_ref_id,
                ],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!(PIPELINE_SUBMISSION_INOPERABLE_LABEL))?;
        let receipt = EncryptedTraceArtifactReceipt {
            tenant_storage_ref: tenant_storage_ref(&run.tenant_id),
            artifact_kind: TraceArtifactKind::ContributionEnvelope,
            object_key: object_ref.get("object_key"),
            ciphertext_sha256: object_ref
                .get::<_, String>("content_sha256")
                .strip_prefix("sha256:")
                .ok_or_else(|| anyhow::anyhow!("source artifact hash is malformed"))?
                .to_string(),
            encrypted_at: object_ref.get("created_at"),
        };
        let wrapper = self
            .artifact_store
            .read_json(&receipt.tenant_storage_ref, &receipt)?;
        tx.commit().await?;
        let encoded = wrapper
            .get("request_bytes_base64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("source artifact payload is malformed"))?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        Ok(bytes)
    }
}

fn tenant_storage_ref(tenant_id: &str) -> String {
    format!("tenant_sha256:{:x}", Sha256::digest(tenant_id.as_bytes()))
}

fn enum_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("enum did not serialize as a string"))
}

fn enum_strings<T: Serialize>(values: &[T]) -> anyhow::Result<Vec<String>> {
    values.iter().map(enum_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_outcome_reader_rejects_malformed_required_payloads() {
        for phase in [Phase::Admission, Phase::Review, Phase::Score, Phase::Settle] {
            assert!(
                validate_outcome_payload(
                    phase,
                    &serde_json::json!({}),
                    &serde_json::json!({}),
                    &serde_json::json!({})
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn minimal_policies_produce_explicit_zero_credit_completion() {
        let bundle = MinimalPolicyBundle::build().unwrap();
        bundle.package.validate().unwrap();
        assert_eq!(
            bundle.package.bundle_id,
            "sha256:bc448580ee3d883fea4955ffbc68c5a64c14c9c4e048d5861f50c31c50eb0a32"
        );
        let bytes = br#"{"schema_version":"ironclaw.trace_contribution.v1"}"#.to_vec();
        let hash = sha256_prefixed(&bytes);
        let run_id = Uuid::new_v4();
        let trace_id = Uuid::new_v4();
        let review = bundle
            .review
            .execute(&ReviewInput {
                run_id,
                trace_id,
                source_content_hash: hash.clone(),
                source_artifact: bytes,
                admission: AdmissionDecision::Admit,
                human_assessment: None,
            })
            .await
            .unwrap();
        let ReviewDecision::Approved {
            registry_revision_id,
        } = review.decision
        else {
            panic!("minimal review must approve");
        };
        let score = bundle
            .score
            .execute(&ScoreInput {
                run_id,
                trace_id,
                registry_revision_id,
                source_content_hash: hash.clone(),
                tenant_id: "tenant".to_string(),
                reviewed_artifact: Vec::new(),
            })
            .await
            .unwrap();
        let settle = bundle
            .settle
            .execute(&SettleInput {
                run_id,
                trace_id,
                registry_revision_id,
                source_content_hash: hash,
                score: score.decision,
                score_evidence: score.evidence,
            })
            .await
            .unwrap();
        assert!(settle.decision.settlement_operations().is_empty());
        assert!(matches!(
            settle.decision.index_membership,
            IndexMembershipDecision::Exclude { .. }
        ));
    }

    #[tokio::test]
    async fn score_policy_can_query_a_reader_without_a_writer() {
        let reader: std::sync::Arc<dyn trace_commons_gate_api::VectorIndexReader> =
            crate::versioned_pipeline_index::IsolatedPipelineIndex::new();
        let snapshot = reader
            .snapshot("tenant", crate::versioned_pipeline_index::PIPELINE_INDEX_ID)
            .unwrap();
        assert_eq!(snapshot.cardinality, 0);
        let neighbors = reader
            .nearest(
                "tenant",
                crate::versioned_pipeline_index::PIPELINE_INDEX_ID,
                &[0.0; 4],
                8,
                Some(Uuid::nil()),
            )
            .unwrap();
        assert!(neighbors.is_empty());
    }

    #[test]
    fn compatibility_package_rejects_production_zero_floors() {
        let runtime = CompatibilityScoreRuntime::reference(IsolatedPipelineIndex::new());
        let mut config = CompatibilityBundleConfig::local_reference();
        config.qualification =
            crate::versioned_pipeline_compat::CompatibilityQualification::ProductionCompatible;
        let error = MinimalPolicyBundle::build_compatibility_candidate(&runtime, config)
            .err()
            .expect("zero production floors must fail");
        assert_eq!(
            error.to_string(),
            crate::versioned_pipeline_compat::COMPATIBILITY_ZERO_FLOOR_LABEL
        );
    }

    #[test]
    fn local_compatibility_package_is_explicitly_non_qualifiable() {
        let runtime = CompatibilityScoreRuntime::reference(IsolatedPipelineIndex::new());
        let bundle = MinimalPolicyBundle::build_compatibility(&runtime).unwrap();
        let config = parse_bundle_config(&bundle.package).unwrap();
        let compatibility = config.compatibility.unwrap();
        assert!(!compatibility.is_qualifiable());
        assert_eq!(
            bundle.package.manifest.score.implementation_id,
            COMPATIBILITY_SCORE_IMPLEMENTATION
        );
        assert_eq!(
            bundle.package.manifest.settle.implementation_id,
            COMPATIBILITY_SETTLE_IMPLEMENTATION
        );
    }
}
