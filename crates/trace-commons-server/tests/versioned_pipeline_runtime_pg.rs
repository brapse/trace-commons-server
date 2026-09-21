// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair};
use secrecy::SecretString;
use trace_commons_gate_api::pipeline::{AdmissionDecision, InstrumentId, Phase};
use trace_commons_gate_api::{ReferenceEmbedder, ReferencePerplexityScorer};
use trace_commons_protocol::trace_contribution::{
    DeterministicTraceRedactor, NoopPrivacyFilterAdapter, PiiClassifyPolicy, RawTraceCaptureTurn,
    RawTraceContribution, RecordedTraceContributionOptions, ResidualPiiRisk,
    TraceContributionEnvelope, TraceRedactor,
};
use trace_commons_server::config::DatabaseConfig;
use trace_commons_server::db::{Database, postgres::PgBackend};
use trace_commons_server::secrets::SecretsCrypto;
use trace_commons_server::trace_artifact_store::{
    LocalEncryptedTraceArtifactStore, TraceArtifactStore,
};
use trace_commons_server::trace_authority::{SubmissionAllowlists, SubmissionAuthority};
use trace_commons_server::trace_corpus_storage::TraceCorpusStore;
use trace_commons_server::versioned_pipeline::{
    MinimalPolicyBundle, PipelineCaps, PipelineCrashPoint, PipelineInstrumentAwardConfig,
    PipelinePayoutConfig, PipelineReceiptResult, PipelineRunState, PipelineService,
    PipelineServiceBuilder, PipelineWithdrawalFollowUpState,
};
use trace_commons_server::versioned_pipeline_activation::{
    ACTIVATION_READINESS_FAILED_LABEL, ActivationReadiness, BOUND_POLICY_MUST_BE_SUSPENDED_LABEL,
    LEGACY_WRITER_PENDING_LABEL, PipelineActivationStore, ReceiptOwner, RoutingState,
    SwitchedReceipt,
};
use trace_commons_server::versioned_pipeline_authority::{
    ClassifierRedactorPipelinePrivacyBoundary, StaticPipelineAuthorityProvider,
};
use trace_commons_server::versioned_pipeline_compat::{
    COMPATIBILITY_SCORE_IMPLEMENTATION, CompatibilityBundleConfig, CompatibilityScoreRuntime,
};
use trace_commons_server::versioned_pipeline_credit::{
    RecordingNearAdapter, RecordingSettlementAdapter, SettlementAdapterRegistry,
    pipeline_ledger_source_key,
};
use trace_commons_server::versioned_pipeline_index::{
    IndexFault, IsolatedPipelineIndex, PIPELINE_INDEX_ID,
};
use trace_commons_server::versioned_pipeline_product::{
    PIPELINE_STATUS_BATCH_MAX, PipelineCreditStatus, PipelineProcessingStatus,
    PipelineProductStore, sha256_prefixed,
};
use trace_commons_server::versioned_pipeline_qualification::{
    BundlePackageSignature, BundlePackageTrustStore, BundleQualificationMetadata,
    PACKAGE_DEVELOPMENT_DEPENDENCY_LABEL, PACKAGE_SIGNATURE_ALGORITHM, PipelineQualificationStore,
    ProductionAdapterKind, ProductionDependencyProfile, ProductionInfrastructureProfile,
    PromotionDecision, SignedBundlePackage, TrustedBundleKey,
};
use uuid::Uuid;

static MIGRATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn backend(pool_size: usize) -> Option<Arc<PgBackend>> {
    let url = std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    let backend = match PgBackend::new(&DatabaseConfig::from_postgres_url(&url, pool_size)).await {
        Ok(backend) => Arc::new(backend),
        Err(error) => {
            eprintln!("skipping: database unavailable ({error})");
            return None;
        }
    };
    let _guard = MIGRATION_LOCK.lock().await;
    if std::env::var_os("TRACE_COMMONS_PIPELINE_SKIP_TEST_MIGRATIONS").is_none() {
        if let Err(error) = backend.run_migrations().await {
            eprintln!("skipping: migrations failed ({error})");
            return None;
        }
    }
    if std::env::var_os("TRACE_COMMONS_PIPELINE_REQUIRE_NOBYPASSRLS").is_some() {
        let client = backend.trace_pool_for_test().get().await.ok()?;
        let row = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .ok()?;
        assert!(!row.get::<_, bool>("rolsuper"), "runtime role is superuser");
        assert!(
            !row.get::<_, bool>("rolbypassrls"),
            "runtime role bypasses RLS"
        );
    }
    Some(backend)
}

fn artifact_store(root: &tempfile::TempDir) -> Arc<dyn TraceArtifactStore> {
    Arc::new(LocalEncryptedTraceArtifactStore::new(
        root.path(),
        SecretsCrypto::new(SecretString::from(
            "pipeline-runtime-test-master-key-32-bytes".to_string(),
        ))
        .unwrap(),
    ))
}

async fn envelope_bytes(submission_id: Uuid) -> Vec<u8> {
    let now = Utc::now();
    let raw = RawTraceContribution::from_capture_turns(
        &[RawTraceCaptureTurn {
            user_input: "Inspect the bounded runtime fixture.".to_string(),
            response: Some("Done.".to_string()),
            tool_calls: Vec::new(),
            started_at: now,
            completed_at: Some(now + chrono::Duration::seconds(1)),
            state: Some("complete".to_string()),
        }],
        RecordedTraceContributionOptions {
            include_message_text: true,
            ..RecordedTraceContributionOptions::default()
        },
    );
    let mut envelope = DeterministicTraceRedactor::try_default()
        .unwrap()
        .redact_trace(raw)
        .await
        .unwrap();
    envelope.submission_id = submission_id;
    envelope.privacy.residual_pii_risk = ResidualPiiRisk::Low;
    serde_json::to_vec(&envelope).unwrap()
}

async fn envelope_bytes_with_text(submission_id: Uuid, text: &str) -> Vec<u8> {
    let bytes = envelope_bytes(submission_id).await;
    let mut envelope: TraceContributionEnvelope = serde_json::from_slice(&bytes).unwrap();
    envelope.events[0].redacted_content = Some(text.to_string());
    envelope.privacy.residual_pii_risk = ResidualPiiRisk::Low;
    serde_json::to_vec(&envelope).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn production_service(
    backend: Arc<PgBackend>,
    store: Arc<dyn TraceArtifactStore>,
    bundle: MinimalPolicyBundle,
    adapters: Vec<Arc<dyn trace_commons_server::versioned_pipeline_credit::SettlementAdapter>>,
    caps: BTreeMap<String, u64>,
    near: Arc<RecordingNearAdapter>,
    payout_enabled: bool,
    crash_point: Option<PipelineCrashPoint>,
) -> PipelineService {
    let index = IsolatedPipelineIndex::new();
    PipelineServiceBuilder::production(
        backend,
        store,
        bundle,
        Arc::new(ReferencePerplexityScorer::new()),
        Arc::new(ReferenceEmbedder::new()),
        index.clone(),
        index,
        SettlementAdapterRegistry::new(adapters).unwrap(),
        near,
        Arc::new(StaticPipelineAuthorityProvider::test_only(
            SubmissionAuthority {
                tenant: SubmissionAllowlists::default(),
                policy: None,
                require_policy: false,
            },
        )),
        Arc::new(
            ClassifierRedactorPipelinePrivacyBoundary::new(
                Arc::new(NoopPrivacyFilterAdapter),
                PiiClassifyPolicy::AllEvents,
                "noop_classifier_redactor_test_only",
            )
            .unwrap(),
        ),
        PipelineCaps {
            per_instrument_atomic_units: caps,
        },
        PipelinePayoutConfig {
            enabled: payout_enabled,
            require_confirmation_evidence: true,
        },
    )
    .with_test_faults(None, crash_point)
    .build()
    .unwrap()
}

async fn finish_run(service: &PipelineService, tenant_id: &str, run_id: Uuid) {
    for _ in 0..20 {
        let inspection = service.inspect(tenant_id, run_id).await.unwrap().unwrap();
        if inspection.run.state == PipelineRunState::Complete {
            return;
        }
        if inspection.run.state == PipelineRunState::Failed {
            panic!("pipeline failed: {:?}", inspection.run.last_error_label);
        }
        if inspection.run.next_attempt_at > Utc::now() {
            let wait = (inspection.run.next_attempt_at - Utc::now())
                .to_std()
                .unwrap_or_default();
            tokio::time::sleep(wait + std::time::Duration::from_millis(10)).await;
        }
        service.process_run(tenant_id, run_id, None).await.unwrap();
    }
    panic!("pipeline did not complete");
}

async fn expire_run_lease(backend: &PgBackend, tenant_id: &str, run_id: Uuid) {
    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE pipeline_runs
            SET lease_expires_at = NOW() - INTERVAL '1 second'
          WHERE tenant_id = $1 AND run_id = $2",
        &[&tenant_id, &run_id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn pool_size_one_receipt_avoids_nested_checkout_and_saturation_is_bounded() {
    let Some(backend) = backend(1).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let service =
        PipelineService::new_test_only(backend.clone(), artifact_store(&root), None).unwrap();
    let tenant = format!("pipeline-pool-{}", Uuid::new_v4());
    let bytes = envelope_bytes(Uuid::new_v4()).await;

    let held = backend.trace_pool_for_test().get().await.unwrap();
    let started = std::time::Instant::now();
    let saturated = service
        .submit(&tenant, "principal_sha256:test", "saturated", &bytes)
        .await;
    assert!(saturated.is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(held);

    assert!(matches!(
        service
            .submit(&tenant, "principal_sha256:test", "pool-one", &bytes)
            .await
            .unwrap(),
        PipelineReceiptResult::Created(_)
    ));
}

#[tokio::test]
async fn server_privacy_boundary_avoids_prefix_false_positives_and_quarantines_pii() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let service =
        PipelineService::new_test_only(backend.clone(), artifact_store(&root), None).unwrap();
    let tenant = format!("pipeline-privacy-{}", Uuid::new_v4());

    for (index, text) in [
        "task-123",
        "risk-model",
        "disk-cache",
        "desk-layout",
        "mask-policy",
    ]
    .into_iter()
    .enumerate()
    {
        let PipelineReceiptResult::Created(run) = service
            .submit(
                &tenant,
                "principal_sha256:test",
                &format!("ordinary-{index}"),
                &envelope_bytes_with_text(Uuid::new_v4(), text).await,
            )
            .await
            .unwrap()
        else {
            panic!("ordinary fixture must create a run");
        };
        let inspection = service.inspect(&tenant, run.run_id).await.unwrap().unwrap();
        let admission: AdmissionDecision =
            serde_json::from_value(inspection.outcomes[0].decision.clone()).unwrap();
        assert_eq!(admission, AdmissionDecision::Admit, "{text}");
    }

    let submission_id = Uuid::new_v4();
    let PipelineReceiptResult::Created(run) = service
        .submit(
            &tenant,
            "principal_sha256:test",
            "pii",
            &envelope_bytes_with_text(submission_id, "Contact jane@example.com").await,
        )
        .await
        .unwrap()
    else {
        panic!("PII fixture must create a run");
    };
    let inspection = service.inspect(&tenant, run.run_id).await.unwrap().unwrap();
    let admission: AdmissionDecision =
        serde_json::from_value(inspection.outcomes[0].decision.clone()).unwrap();
    assert!(matches!(admission, AdmissionDecision::Quarantine { .. }));
    let stored = backend
        .get_trace_submission(&tenant, submission_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.privacy_risk, "medium");
    assert!(stored.redaction_counts.values().any(|count| *count > 0));
    assert!(
        stored
            .residual_risk_basis
            .as_ref()
            .is_some_and(|basis| basis.iter().any(|label| label == "found_and_removed"))
    );
}

#[tokio::test]
async fn compatibility_score_reads_and_settle_writes_the_index() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let index = IsolatedPipelineIndex::new();
    let runtime = CompatibilityScoreRuntime::reference(index.clone());
    let bundle = MinimalPolicyBundle::build_compatibility(&runtime).unwrap();
    let near = Arc::new(RecordingNearAdapter::new());
    let trace_credit = RecordingSettlementAdapter::new(
        InstrumentId::trace_credit(),
        "compatibility_trace_credit_test",
        "near",
    );
    let service = PipelineServiceBuilder::production(
        backend,
        artifact_store(&root),
        bundle,
        Arc::new(ReferencePerplexityScorer::new()),
        Arc::new(ReferenceEmbedder::new()),
        index.clone(),
        index.clone(),
        SettlementAdapterRegistry::new(vec![trace_credit]).unwrap(),
        near,
        Arc::new(StaticPipelineAuthorityProvider::test_only(
            SubmissionAuthority {
                tenant: SubmissionAllowlists::default(),
                policy: None,
                require_policy: false,
            },
        )),
        Arc::new(
            ClassifierRedactorPipelinePrivacyBoundary::new(
                Arc::new(NoopPrivacyFilterAdapter),
                PiiClassifyPolicy::AllEvents,
                "noop_classifier_redactor_test_only",
            )
            .unwrap(),
        ),
        PipelineCaps {
            per_instrument_atomic_units: BTreeMap::from([(
                InstrumentId::trace_credit().as_str().to_string(),
                u64::MAX,
            )]),
        },
        PipelinePayoutConfig {
            enabled: false,
            require_confirmation_evidence: true,
        },
    )
    .with_compatibility_runtime(runtime)
    .build()
    .unwrap();
    let tenant = format!("pipeline-compatibility-{}", Uuid::new_v4());
    let PipelineReceiptResult::Created(run) = service
        .submit(
            &tenant,
            "principal_sha256:test",
            "compatibility",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    else {
        panic!("compatibility fixture must create a run");
    };

    service
        .process_run(&tenant, run.run_id, None)
        .await
        .unwrap();
    service
        .process_run(&tenant, run.run_id, Some(Phase::Settle))
        .await
        .unwrap();
    assert_eq!(index.writer_calls(), 0, "Score must remain read-only");
    let inspection = service.inspect(&tenant, run.run_id).await.unwrap().unwrap();
    let score = inspection
        .outcomes
        .iter()
        .find(|outcome| outcome.phase == Phase::Score)
        .unwrap();
    assert_eq!(
        score.evaluation["rule_id"],
        "compatibility_quality_novelty_v1"
    );
    assert_eq!(
        inspection.run.next_phase,
        Some(Phase::Settle),
        "{COMPATIBILITY_SCORE_IMPLEMENTATION}"
    );

    finish_run(&service, &tenant, run.run_id).await;
    assert!(index.writer_calls() > 0, "Settle must own index writes");
    assert_eq!(index.entry_count(&tenant, PIPELINE_INDEX_ID), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_receipt_and_worker_retries_commit_once() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let service = PipelineService::new_test_only(backend, artifact_store(&root), None).unwrap();
    let tenant = format!("pipeline-concurrent-{}", Uuid::new_v4());
    let bytes = envelope_bytes(Uuid::new_v4()).await;
    let (left, right) = tokio::join!(
        service.submit(&tenant, "principal_sha256:test", "same", &bytes),
        service.submit(&tenant, "principal_sha256:test", "same", &bytes)
    );
    let results = [left.unwrap(), right.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PipelineReceiptResult::Created(_)))
            .count(),
        1
    );
    let run_id = results
        .iter()
        .find_map(|result| match result {
            PipelineReceiptResult::Created(run) | PipelineReceiptResult::Replayed(run) => {
                Some(run.run_id)
            }
            PipelineReceiptResult::ContentConflict | PipelineReceiptResult::LegacyOwned { .. } => {
                None
            }
        })
        .unwrap();
    for _ in 0..3 {
        let (left, right) = tokio::join!(
            service.process_run(&tenant, run_id, None),
            service.process_run(&tenant, run_id, None)
        );
        assert!(left.is_ok() && right.is_ok());
    }
    finish_run(&service, &tenant, run_id).await;
    let inspection = service.inspect(&tenant, run_id).await.unwrap().unwrap();
    assert_eq!(inspection.outcomes.len(), 4);
}

#[tokio::test]
async fn multi_instrument_failure_retry_and_crash_are_independent_and_authoritative() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let tenant = format!("pipeline-instruments-{}", Uuid::new_v4());
    let trace = RecordingSettlementAdapter::new(
        InstrumentId::trace_credit(),
        "trace-credit-adapter-v1",
        "near",
    );
    let rebate_id = InstrumentId::new("storage_rebate").unwrap();
    let rebate =
        RecordingSettlementAdapter::new(rebate_id.clone(), "storage-rebate-adapter-v1", "none");
    rebate.fail_next();
    let near = Arc::new(RecordingNearAdapter::new());
    let bundle = MinimalPolicyBundle::build_instruments(
        vec![
            PipelineInstrumentAwardConfig {
                instrument_id: "trace_credit".to_string(),
                atomic_units: 1_000_000,
            },
            PipelineInstrumentAwardConfig {
                instrument_id: "storage_rebate".to_string(),
                atomic_units: 7,
            },
        ],
        false,
    )
    .unwrap();
    let service = production_service(
        backend.clone(),
        artifact_store(&root),
        bundle,
        vec![trace.clone(), rebate.clone()],
        BTreeMap::from([
            ("trace_credit".to_string(), 2_000_000),
            ("storage_rebate".to_string(), 10),
        ]),
        near.clone(),
        false,
        None,
    );
    let identity = service.dependency_identity();
    assert_eq!(
        identity.settlement_adapters["storage_rebate"],
        "storage-rebate-adapter-v1"
    );
    assert_eq!(identity.index_reader, "isolated_index_reader_test_only");

    service
        .submit(
            &tenant,
            "principal_sha256:test",
            "activation-bootstrap",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap();
    let mut activation_client = backend.trace_pool_for_test().get().await.unwrap();
    let activation_tx = activation_client.transaction().await.unwrap();
    activation_tx
        .execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant],
        )
        .await
        .unwrap();
    activation_tx
        .execute(
            "INSERT INTO pipeline_tenant_routing (
                tenant_id, routing_state, selected_bundle_id, activation_record_id,
                actor_principal_ref, reason_code, evidence_hash
             ) VALUES ($1,'pipeline',$2,$3,$4,'activate_test',$5)",
            &[
                &tenant,
                &service.bundle_id(),
                &Uuid::new_v4(),
                &"operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                &sha256_prefixed(b"multi-instrument-activation"),
            ],
        )
        .await
        .unwrap();
    activation_tx.commit().await.unwrap();

    let PipelineReceiptResult::Created(created) = service
        .submit(
            &tenant,
            "principal_sha256:test",
            "multi",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    else {
        panic!("receipt must create");
    };
    service
        .process_run(&tenant, created.run_id, None)
        .await
        .unwrap();
    service
        .process_run(&tenant, created.run_id, None)
        .await
        .unwrap();

    let legacy_event = Uuid::new_v4();
    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO trace_credit_ledger (
            tenant_id, credit_event_id, submission_id, trace_id, credit_account_ref,
            event_type, points_delta, reason, actor_principal_ref, actor_role, settlement_state
         ) VALUES ($1,$2,$3,$4,$5,'accepted','9','legacy_pending',$5,'worker','pending')",
        &[
            &tenant,
            &legacy_event,
            &created.submission_id,
            &created.trace_id,
            &"principal_sha256:test",
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let first = service
        .process_run(&tenant, created.run_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.state, PipelineRunState::Retry);
    let settlements = service
        .store_for_test()
        .list_settlements(&tenant, created.run_id)
        .await
        .unwrap();
    assert_eq!(
        settlements
            .iter()
            .find(|row| row.instrument_id == "trace_credit")
            .unwrap()
            .operation_state,
        "complete"
    );
    assert_eq!(
        settlements
            .iter()
            .find(|row| row.instrument_id == "storage_rebate")
            .unwrap()
            .operation_state,
        "retry"
    );
    finish_run(&service, &tenant, created.run_id).await;
    assert_eq!(trace.requests().len(), 1);
    assert_eq!(rebate.requests().len(), 1);
    let status = PipelineProductStore::new(backend.clone())
        .contributor_statuses(&tenant, "principal_sha256:test", &[created.submission_id])
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(status.processing, PipelineProcessingStatus::Complete);
    assert_eq!(status.credit, PipelineCreditStatus::Finalized);
    assert_eq!(status.instruments.len(), 2);
    let trace_credit = status
        .instruments
        .iter()
        .find(|instrument| instrument.instrument_id == "trace_credit")
        .unwrap();
    assert_eq!(trace_credit.operation_state, "complete");
    assert_eq!(trace_credit.internal_settlement_state, "finalized");
    assert_eq!(trace_credit.payout_state, "pending");
    let rebate_status = status
        .instruments
        .iter()
        .find(|instrument| instrument.instrument_id == "storage_rebate")
        .unwrap();
    assert_eq!(rebate_status.operation_state, "complete");
    assert_eq!(rebate_status.internal_settlement_state, "not_applicable");
    assert_eq!(rebate_status.payout_state, "disabled");
    assert!(
        PipelineProductStore::new(backend.clone())
            .contributor_statuses(
                &format!("{tenant}-other"),
                "principal_sha256:test",
                &[created.submission_id],
            )
            .await
            .unwrap()
            .is_empty()
    );

    let inspection = service
        .inspect(&tenant, created.run_id)
        .await
        .unwrap()
        .unwrap();
    let settle = inspection
        .outcomes
        .iter()
        .find(|outcome| outcome.phase == Phase::Settle)
        .unwrap();
    assert_eq!(
        settle.decision["settlement_operations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    let legacy_state: String = tx
        .query_one(
            "SELECT settlement_state FROM trace_credit_ledger
              WHERE tenant_id = $1 AND credit_event_id = $2",
            &[&tenant, &legacy_event],
        )
        .await
        .unwrap()
        .get(0);
    tx.commit().await.unwrap();
    assert_eq!(legacy_state, "pending");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_activation_rollback_containment_and_writer_retirement() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let tenant = format!("pipeline-activation-{}", Uuid::new_v4());
    let service = PipelineService::new_test_only(backend.clone(), artifact_store(&root), None)
        .expect("pipeline service");
    let activation = PipelineActivationStore::new(backend.clone());
    let legacy_bytes = envelope_bytes(Uuid::new_v4()).await;
    let (first, second) = tokio::join!(
        activation.record_legacy_receipt(
            &tenant,
            "principal_sha256:test",
            "legacy-first",
            &legacy_bytes,
            true,
            1_000_000,
        ),
        activation.record_legacy_receipt(
            &tenant,
            "principal_sha256:test",
            "legacy-first",
            &legacy_bytes,
            true,
            1_000_000,
        )
    );
    let receipts = [first.unwrap(), second.unwrap()];
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(
                receipt,
                SwitchedReceipt::Legacy {
                    replayed: false,
                    ..
                }
            ))
            .count(),
        1
    );
    let legacy_owner = activation
        .ownership(&tenant, "legacy-first")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(legacy_owner.owner, ReceiptOwner::Legacy);
    assert_eq!(
        legacy_owner.ledger_source_key,
        pipeline_ledger_source_key(&tenant, &sha256_prefixed(b"legacy-first"))
    );
    let mut ledger_client = backend.trace_pool_for_test().get().await.unwrap();
    let ledger_tx = ledger_client.transaction().await.unwrap();
    ledger_tx
        .execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant],
        )
        .await
        .unwrap();
    let ledger_award_count: i64 = ledger_tx
        .query_one(
            "SELECT COUNT(*)::BIGINT
               FROM trace_credit_ledger
              WHERE tenant_id = $1 AND ledger_source_key = $2",
            &[&tenant, &legacy_owner.ledger_source_key],
        )
        .await
        .unwrap()
        .get(0);
    ledger_tx.commit().await.unwrap();
    assert_eq!(ledger_award_count, 1);
    let mut changed = legacy_bytes.clone();
    changed.push(b' ');
    assert!(matches!(
        activation
            .record_legacy_receipt(
                &tenant,
                "principal_sha256:test",
                "legacy-first",
                &changed,
                true,
                1_000_000,
            )
            .await
            .unwrap(),
        SwitchedReceipt::ContentConflict
    ));

    service
        .submit(
            &tenant,
            "principal_sha256:test",
            "activation-bootstrap",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap();
    let bundle_b = MinimalPolicyBundle::build_variant("activation-rollback-b").unwrap();
    service
        .register_bundle(&tenant, &bundle_b.package)
        .await
        .unwrap();
    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO pipeline_tenant_routing (
            tenant_id, routing_state, selected_bundle_id, activation_record_id,
            actor_principal_ref, reason_code, evidence_hash
         ) VALUES ($1,'pipeline',$2,$3,$4,'activate_test',$5)",
        &[
            &tenant,
            &service.bundle_id(),
            &Uuid::new_v4(),
            &"operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            &sha256_prefixed(b"activation-a"),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let first_pipeline = match activation
        .submit_switched(
            &service,
            &tenant,
            "principal_sha256:test",
            "pipeline-a",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    {
        SwitchedReceipt::Pipeline(receipt) => match *receipt {
            PipelineReceiptResult::Created(run) => run,
            other => panic!("expected created run, got {other:?}"),
        },
        other => panic!("expected pipeline receipt, got {other:?}"),
    };
    assert_eq!(first_pipeline.bundle_id, service.bundle_id());
    let refused = activation
        .switch_bound_run_bundle(&tenant, first_pipeline.run_id, &bundle_b.package.bundle_id)
        .await
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains(BOUND_POLICY_MUST_BE_SUSPENDED_LABEL)
    );
    service
        .intervene_policy(
            &tenant,
            service.bundle_id(),
            first_pipeline.next_phase.unwrap(),
            "suspend",
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "unsafe_bound_policy",
        )
        .await
        .unwrap();
    let suspended = service
        .process_run(&tenant, first_pipeline.run_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(suspended.state, PipelineRunState::Retry);
    assert_eq!(
        suspended.last_error_label.as_deref(),
        Some("bundle_policy_not_runnable")
    );
    service
        .intervene_policy(
            &tenant,
            service.bundle_id(),
            first_pipeline.next_phase.unwrap(),
            "resume",
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "resume_after_suspend",
        )
        .await
        .unwrap();

    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE pipeline_tenant_routing
            SET selected_bundle_id = $2, activation_record_id = $3,
                reason_code = 'rollback_test', evidence_hash = $4
          WHERE tenant_id = $1",
        &[
            &tenant,
            &bundle_b.package.bundle_id,
            &Uuid::new_v4(),
            &sha256_prefixed(b"activation-b"),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let later = match activation
        .submit_switched(
            &service,
            &tenant,
            "principal_sha256:test",
            "pipeline-b",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    {
        SwitchedReceipt::Pipeline(receipt) => match *receipt {
            PipelineReceiptResult::Created(run) => run,
            other => panic!("expected created run, got {other:?}"),
        },
        other => panic!("expected pipeline receipt, got {other:?}"),
    };
    assert_eq!(later.bundle_id, bundle_b.package.bundle_id);
    assert_eq!(
        service
            .inspect(&tenant, first_pipeline.run_id)
            .await
            .unwrap()
            .unwrap()
            .run
            .bundle_id,
        service.bundle_id()
    );

    let mut failed_readiness = ActivationReadiness::passing(Utc::now());
    failed_readiness.max_work_age_seconds = 301;
    let dependencies = ProductionDependencyProfile::from_runtime(
        &service,
        ProductionInfrastructureProfile {
            authoritative_metadata: ProductionAdapterKind::Production,
            artifact_store: ProductionAdapterKind::Production,
            key_wrapper: ProductionAdapterKind::Production,
            authentication: ProductionAdapterKind::Production,
            plaintext_fallback: false,
            best_effort_database_mirror: false,
            static_bearer_authentication: false,
            hs256_bridge_authentication: false,
            unversioned_policy_dependencies: false,
            live_external_payout_enabled: false,
        },
    );
    let expansion = activation
        .expand_activation(
            &tenant,
            &format!("{tenant}-expanded"),
            &bundle_b.package.bundle_id,
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "expand_cohort",
            &PromotionDecision {
                ready: true,
                evaluated_at: Utc::now(),
                evidence_hash: sha256_prefixed(b"expansion-evidence"),
                safe_blockers: Vec::new(),
            },
            &failed_readiness,
            &sha256_prefixed(b"runtime-code"),
            &dependencies,
        )
        .await
        .unwrap_err();
    assert!(
        expansion
            .to_string()
            .contains(ACTIVATION_READINESS_FAILED_LABEL)
    );

    let retirement = activation
        .retire_legacy_writer(
            &tenant,
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "retire_legacy_writer",
        )
        .await
        .unwrap_err();
    assert!(retirement.to_string().contains(LEGACY_WRITER_PENDING_LABEL));
    assert!(matches!(
        activation
            .record_legacy_receipt(
                &tenant,
                "principal_sha256:test",
                "legacy-after-drain",
                &envelope_bytes(Uuid::new_v4()).await,
                true,
                0,
            )
            .await
            .unwrap(),
        SwitchedReceipt::WriterDisabled
    ));
    assert!(matches!(
        activation
            .record_legacy_receipt(
                &tenant,
                "principal_sha256:test",
                "legacy-first",
                &legacy_bytes,
                true,
                0,
            )
            .await
            .unwrap(),
        SwitchedReceipt::Legacy { replayed: true, .. }
    ));
    activation
        .complete_legacy_work(&tenant, "legacy-first")
        .await
        .unwrap();
    activation
        .retire_legacy_writer(
            &tenant,
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "retire_legacy_writer",
        )
        .await
        .unwrap();
    activation
        .contain_pipeline(
            &tenant,
            "operator_sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "contain_first_rollout",
        )
        .await
        .unwrap();
    assert_eq!(
        activation
            .routing(&tenant)
            .await
            .unwrap()
            .unwrap()
            .routing_state,
        RoutingState::Contained
    );
    assert!(matches!(
        activation
            .submit_switched(
                &service,
                &tenant,
                "principal_sha256:test",
                "contained",
                &envelope_bytes(Uuid::new_v4()).await,
            )
            .await
            .unwrap(),
        SwitchedReceipt::Contained
    ));
}

#[tokio::test]
async fn crash_reuses_completed_operations_and_payout_waits_for_confirmation_evidence() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let tenant = format!("pipeline-crash-payout-{}", Uuid::new_v4());
    let trace = RecordingSettlementAdapter::new(
        InstrumentId::trace_credit(),
        "trace-credit-adapter-v1",
        "near",
    );
    let near = Arc::new(RecordingNearAdapter::new());
    let bundle = MinimalPolicyBundle::build_operations(1_000_000, false).unwrap();
    let crashing = production_service(
        backend.clone(),
        artifact_store(&root),
        bundle,
        vec![trace.clone()],
        BTreeMap::from([("trace_credit".to_string(), 2_000_000)]),
        near.clone(),
        true,
        Some(PipelineCrashPoint::AfterInternalSettlement),
    );
    let PipelineReceiptResult::Created(created) = crashing
        .submit(
            &tenant,
            "principal_sha256:test",
            "crash",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    else {
        panic!("receipt must create");
    };
    crashing
        .process_run(&tenant, created.run_id, None)
        .await
        .unwrap();
    crashing
        .process_run(&tenant, created.run_id, None)
        .await
        .unwrap();
    assert!(
        crashing
            .process_run(&tenant, created.run_id, None)
            .await
            .is_err()
    );
    assert_eq!(trace.requests().len(), 1);
    expire_run_lease(&backend, &tenant, created.run_id).await;

    let restarted = production_service(
        backend.clone(),
        artifact_store(&root),
        MinimalPolicyBundle::build_operations(1_000_000, false).unwrap(),
        vec![trace.clone()],
        BTreeMap::from([("trace_credit".to_string(), 2_000_000)]),
        near.clone(),
        true,
        None,
    );
    finish_run(&restarted, &tenant, created.run_id).await;
    assert_eq!(trace.requests().len(), 1);

    let settlement = restarted
        .store_for_test()
        .list_settlements(&tenant, created.run_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let batch_id = settlement.settlement_batch_id.unwrap();
    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE trace_credit_settlement_batches
            SET line_items_json = line_items_json || jsonb_build_array(
                (line_items_json -> 0) || jsonb_build_object(
                    'credit_account_ref', 'principal_sha256:second',
                    'credit_account_hash',
                    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
                )
            )
          WHERE tenant_id = $1 AND settlement_batch_id = $2",
        &[&tenant, &batch_id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    restarted
        .process_payout(&tenant, created.run_id)
        .await
        .unwrap();
    assert_eq!(near.requests().len(), 2);
    let settlement = restarted
        .store_for_test()
        .list_settlements(&tenant, created.run_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(settlement.payout_state, "submitted");

    for request in near.requests() {
        near.record_confirmation(
            &request.idempotency_key,
            trace_commons_server::versioned_pipeline_credit::issuer_approval_hash(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            trace_commons_server::versioned_pipeline_credit::issuer_approval_hash(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        )
        .unwrap();
    }
    restarted
        .process_payout(&tenant, created.run_id)
        .await
        .unwrap();
    let settlement = restarted
        .store_for_test()
        .list_settlements(&tenant, created.run_id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(settlement.payout_state, "confirmed");
}

#[tokio::test]
async fn contributor_status_pagination_is_bounded_and_stable() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let service =
        PipelineService::new_test_only(backend.clone(), artifact_store(&root), None).unwrap();
    let tenant = format!("pipeline-status-page-{}", Uuid::new_v4());
    let principal = "principal_sha256:status-page";
    for index in 0..3 {
        let result = service
            .submit(
                &tenant,
                principal,
                &format!("page-{index}"),
                &envelope_bytes(Uuid::new_v4()).await,
            )
            .await
            .unwrap();
        assert!(matches!(result, PipelineReceiptResult::Created(_)));
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    let product = PipelineProductStore::new(backend.clone());
    let first = product
        .own_contributor_statuses_page(&tenant, principal, None, 2)
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    assert!(
        product
            .own_contributor_statuses_page(&tenant, principal, None, 0)
            .await
            .is_err()
    );
    assert!(
        product
            .own_contributor_statuses_page(&tenant, principal, None, PIPELINE_STATUS_BATCH_MAX + 1,)
            .await
            .is_err()
    );

    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    let cursor = tx
        .query_one(
            "SELECT received_at, submission_id
               FROM trace_submissions
              WHERE tenant_id = $1 AND submission_id = $2",
            &[&tenant, &first[1].submission_id],
        )
        .await
        .unwrap();
    let after = Some((cursor.get("received_at"), cursor.get("submission_id")));
    tx.commit().await.unwrap();

    let second = product
        .own_contributor_statuses_page(&tenant, principal, after, 2)
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_ne!(second[0].submission_id, first[0].submission_id);
    assert_ne!(second[0].submission_id, first[1].submission_id);
}

#[tokio::test]
async fn withdrawal_commits_tombstone_propagation_audit_and_export_invalidation_atomically() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let service = production_service(
        backend.clone(),
        artifact_store(&root),
        MinimalPolicyBundle::build_operations(1_000_000, false).unwrap(),
        vec![RecordingSettlementAdapter::new(
            InstrumentId::trace_credit(),
            "withdrawal-trace-credit-test",
            "none",
        )],
        BTreeMap::from([("trace_credit".to_string(), 2_000_000)]),
        Arc::new(RecordingNearAdapter::new()),
        false,
        None,
    );
    let tenant = format!("pipeline-withdrawal-{}", Uuid::new_v4());
    let principal = "principal_sha256:withdrawal-owner";
    let submission_id = Uuid::new_v4();
    let mut envelope: TraceContributionEnvelope =
        serde_json::from_slice(&envelope_bytes(submission_id).await).unwrap();
    if !envelope
        .trace_card
        .allowed_uses
        .contains(&trace_commons_protocol::trace_contribution::TraceAllowedUse::Evaluation)
    {
        envelope
            .trace_card
            .allowed_uses
            .push(trace_commons_protocol::trace_contribution::TraceAllowedUse::Evaluation);
    }
    let bytes = serde_json::to_vec(&envelope).unwrap();
    let PipelineReceiptResult::Created(created) = service
        .submit(&tenant, principal, "withdrawal", &bytes)
        .await
        .unwrap()
    else {
        panic!("receipt must create a run");
    };
    finish_run(&service, &tenant, created.run_id).await;

    let product = PipelineProductStore::new(backend.clone());
    let snapshot = product
        .create_export_snapshot(
            &tenant,
            "exporter_sha256:managed",
            &sha256_prefixed(b"withdrawal-export-request"),
            "evaluation",
            &sha256_prefixed(b"withdrawal-export-purpose"),
            10,
        )
        .await
        .unwrap();
    assert_eq!(snapshot.items.len(), 1);
    let completed = product
        .complete_export_snapshot(&tenant, "exporter_sha256:managed", snapshot.snapshot_id)
        .await
        .unwrap();
    assert_eq!(completed.state, "complete");

    let before_events = backend.list_trace_credit_events(&tenant).await.unwrap();
    assert_eq!(before_events.len(), 1);
    let outcome = service
        .withdraw_submission(&tenant, created.submission_id, principal)
        .await
        .unwrap();
    assert_eq!(outcome.withdrawal.distribution_reach, "commons_distributed");
    assert_eq!(
        outcome.revocation_propagation,
        PipelineWithdrawalFollowUpState::Pending
    );
    assert!(matches!(
        outcome.index_invalidation,
        PipelineWithdrawalFollowUpState::Pending | PipelineWithdrawalFollowUpState::NotRequired
    ));

    let mut client = backend.trace_pool_for_test().get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant],
    )
    .await
    .unwrap();
    let evidence = tx
        .query_one(
            "SELECT
                (SELECT COUNT(*) FROM trace_withdrawals
                  WHERE tenant_id = $1 AND submission_id = $2) AS withdrawals,
                (SELECT COUNT(*) FROM trace_tombstones
                  WHERE tenant_id = $1 AND submission_id = $2) AS tombstones,
                (SELECT COUNT(*) FROM trace_revocation_propagation_items
                  WHERE tenant_id = $1 AND source_submission_id = $2
                    AND status = 'pending') AS propagation,
                (SELECT COUNT(*) FROM trace_audit_events
                  WHERE tenant_id = $1 AND submission_id = $2
                    AND action = 'revoke') AS audits,
                (SELECT COUNT(*) FROM pipeline_export_snapshots
                  WHERE tenant_id = $1 AND snapshot_id = $3
                    AND state = 'invalidated') AS invalidated_exports",
            &[&tenant, &created.submission_id, &snapshot.snapshot_id],
        )
        .await
        .unwrap();
    assert_eq!(evidence.get::<_, i64>("withdrawals"), 1);
    assert_eq!(evidence.get::<_, i64>("tombstones"), 1);
    assert!(evidence.get::<_, i64>("propagation") > 0);
    assert_eq!(evidence.get::<_, i64>("audits"), 1);
    assert_eq!(evidence.get::<_, i64>("invalidated_exports"), 1);
    let audit = tx
        .query_one(
            "SELECT reason, decision_inputs_hash, metadata_json, canonical_event_json
               FROM trace_audit_events
              WHERE tenant_id = $1 AND submission_id = $2 AND action = 'revoke'",
            &[&tenant, &created.submission_id],
        )
        .await
        .unwrap();
    assert_eq!(audit.get::<_, String>("reason"), "pipeline_withdrawal");
    assert!(
        audit
            .get::<_, String>("decision_inputs_hash")
            .starts_with("sha256:")
    );
    let metadata = audit.get::<_, serde_json::Value>("metadata_json");
    assert!(
        metadata["reason_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        audit
            .get::<_, Option<String>>("canonical_event_json")
            .is_none()
    );
    tx.commit().await.unwrap();

    let after_events = backend.list_trace_credit_events(&tenant).await.unwrap();
    assert_eq!(
        after_events, before_events,
        "withdrawal must not claw back credit"
    );
    let status = product
        .contributor_statuses(&tenant, principal, &[created.submission_id])
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(status.processing, PipelineProcessingStatus::Withdrawn);
    assert_eq!(status.credit, PipelineCreditStatus::Finalized);

    let replay = service
        .withdraw_submission(&tenant, created.submission_id, principal)
        .await
        .unwrap();
    assert_eq!(replay.withdrawal, outcome.withdrawal);
    let missing = service
        .withdraw_submission(&tenant, Uuid::new_v4(), principal)
        .await
        .unwrap_err();
    assert!(matches!(
        missing,
        trace_commons_server::error::DatabaseError::NotFound { .. }
    ));
}

#[tokio::test]
async fn durable_withdrawal_reports_index_propagation_failures_without_becoming_not_found() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let index = IsolatedPipelineIndex::new();
    let service = PipelineServiceBuilder::production(
        backend,
        artifact_store(&root),
        MinimalPolicyBundle::build_operations(0, true).unwrap(),
        Arc::new(ReferencePerplexityScorer::new()),
        Arc::new(ReferenceEmbedder::new()),
        index.clone(),
        index.clone(),
        SettlementAdapterRegistry::new(Vec::new()).unwrap(),
        Arc::new(RecordingNearAdapter::new()),
        Arc::new(StaticPipelineAuthorityProvider::test_only(
            SubmissionAuthority {
                tenant: SubmissionAllowlists::default(),
                policy: None,
                require_policy: false,
            },
        )),
        Arc::new(
            ClassifierRedactorPipelinePrivacyBoundary::new(
                Arc::new(NoopPrivacyFilterAdapter),
                PiiClassifyPolicy::AllEvents,
                "noop_classifier_redactor_test_only",
            )
            .unwrap(),
        ),
        PipelineCaps {
            per_instrument_atomic_units: BTreeMap::new(),
        },
        PipelinePayoutConfig {
            enabled: false,
            require_confirmation_evidence: true,
        },
    )
    .build()
    .unwrap();
    let tenant = format!("pipeline-invalidation-report-{}", Uuid::new_v4());
    let principal = "principal_sha256:invalidation-owner";
    let PipelineReceiptResult::Created(created) = service
        .submit(
            &tenant,
            principal,
            "invalidation-report",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    else {
        panic!("receipt must create");
    };
    finish_run(&service, &tenant, created.run_id).await;
    let withdrawal = service
        .withdraw_submission(&tenant, created.submission_id, principal)
        .await
        .unwrap();
    assert_eq!(
        withdrawal.index_invalidation,
        PipelineWithdrawalFollowUpState::Pending
    );

    for expected in ["pending", "pending", "pending", "pending", "failed"] {
        index.set_fault(IndexFault::FailInvalidation);
        let run = service
            .process_index_invalidation(&tenant, created.run_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.index_invalidation_state, expected);
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    }
    let replay = service
        .withdraw_submission(&tenant, created.submission_id, principal)
        .await
        .unwrap();
    assert_eq!(replay.withdrawal, withdrawal.withdrawal);
    assert_eq!(
        replay.index_invalidation,
        PipelineWithdrawalFollowUpState::Failed
    );
}

#[tokio::test]
async fn index_rebuild_uses_sealed_commands_without_new_credit_or_outcomes() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let tenant = format!("pipeline-index-rebuild-{}", Uuid::new_v4());
    let near = Arc::new(RecordingNearAdapter::new());
    let trace_credit = RecordingSettlementAdapter::new(
        InstrumentId::trace_credit(),
        "recording_trace_credit_test_only",
        "none",
    );
    let service = production_service(
        backend,
        artifact_store(&root),
        MinimalPolicyBundle::build_operations(100, true).unwrap(),
        vec![trace_credit],
        BTreeMap::from([(InstrumentId::trace_credit().as_str().to_string(), 1_000)]),
        near,
        false,
        None,
    );
    let PipelineReceiptResult::Created(run) = service
        .submit(
            &tenant,
            "principal_sha256:index_rebuild",
            "index-rebuild",
            &envelope_bytes(Uuid::new_v4()).await,
        )
        .await
        .unwrap()
    else {
        panic!("index rebuild fixture must create a run");
    };
    finish_run(&service, &tenant, run.run_id).await;
    let before = service.inspect(&tenant, run.run_id).await.unwrap().unwrap();

    let rebuilt = IsolatedPipelineIndex::new();
    let first = service
        .rebuild_index_from_authoritative_commands(&tenant, rebuilt.clone())
        .await
        .unwrap();
    assert_eq!(first.command_count, 1);
    assert!(first.entry_count > 0);
    assert_eq!(first.unchanged_entry_count, 0);
    let second = service
        .rebuild_index_from_authoritative_commands(&tenant, rebuilt)
        .await
        .unwrap();
    assert_eq!(second.command_set_hash, first.command_set_hash);
    assert_eq!(second.unchanged_entry_count, second.entry_count);

    let after = service.inspect(&tenant, run.run_id).await.unwrap().unwrap();
    assert_eq!(after.outcomes, before.outcomes);
    assert_eq!(after.run, before.run);
}

#[tokio::test]
async fn qualification_operational_summary_and_traceability_are_hash_only() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let tenant = format!("pipeline-operations-{}", Uuid::new_v4());
    let service =
        PipelineService::new_test_only(backend.clone(), artifact_store(&root), None).unwrap();
    let secret = "private_qualification_value_must_not_appear";
    let PipelineReceiptResult::Created(run) = service
        .submit(
            &tenant,
            "principal_sha256:operations",
            "operations",
            &envelope_bytes_with_text(Uuid::new_v4(), secret).await,
        )
        .await
        .unwrap()
    else {
        panic!("operations fixture must create a run");
    };
    finish_run(&service, &tenant, run.run_id).await;

    let product = PipelineProductStore::new(backend);
    let summary = product.operational_summary(&tenant).await.unwrap();
    assert!(summary.tenant_isolation_control_passed);
    assert!(summary.audit_immutability_control_passed);
    let trace = product
        .forensic_trace(&tenant, run.run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trace.phases.len(), 4);
    assert!(trace.phases.iter().all(|phase| {
        phase.decision_hash.starts_with("sha256:")
            && phase.evidence_hash.starts_with("sha256:")
            && phase.evaluation_hash.starts_with("sha256:")
    }));
    assert!(
        !serde_json::to_string(&(summary, trace))
            .unwrap()
            .contains(secret)
    );
}

#[tokio::test]
async fn signed_package_qualification_rejects_nonproduction_candidate() {
    let Some(backend) = backend(4).await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let index = IsolatedPipelineIndex::new();
    let runtime = CompatibilityScoreRuntime::reference(index.clone());
    let mut config = CompatibilityBundleConfig::local_reference();
    config.scorer_model_id = "production-scorer-v1".to_string();
    config.embedder_model_id = "production-embedder-v1".to_string();
    config.projection_id = "production-projection-v1".to_string();
    config.index_id = "production-index-v1".to_string();
    let bundle = MinimalPolicyBundle::build_compatibility_candidate(&runtime, config).unwrap();
    let package = bundle.package.clone();
    let near = Arc::new(RecordingNearAdapter::new());
    let adapter = RecordingSettlementAdapter::new(
        InstrumentId::trace_credit(),
        "production-settlement-v1",
        "none",
    );
    let service = PipelineServiceBuilder::production(
        backend.clone(),
        artifact_store(&root),
        bundle,
        Arc::new(ReferencePerplexityScorer::new()),
        Arc::new(ReferenceEmbedder::new()),
        index.clone(),
        index,
        SettlementAdapterRegistry::new(vec![adapter]).unwrap(),
        near,
        Arc::new(StaticPipelineAuthorityProvider::new(
            BTreeMap::new(),
            "production-authority-v1",
        )),
        Arc::new(
            ClassifierRedactorPipelinePrivacyBoundary::new(
                Arc::new(NoopPrivacyFilterAdapter),
                PiiClassifyPolicy::AllEvents,
                "production-privacy-v1",
            )
            .unwrap(),
        ),
        PipelineCaps {
            per_instrument_atomic_units: BTreeMap::from([(
                InstrumentId::trace_credit().as_str().to_string(),
                u64::MAX,
            )]),
        },
        PipelinePayoutConfig {
            enabled: false,
            require_confirmation_evidence: true,
        },
    )
    .with_compatibility_runtime(runtime)
    .build()
    .unwrap();
    let profile = ProductionDependencyProfile::from_runtime(
        &service,
        ProductionInfrastructureProfile {
            authoritative_metadata: ProductionAdapterKind::Production,
            artifact_store: ProductionAdapterKind::Production,
            key_wrapper: ProductionAdapterKind::Production,
            authentication: ProductionAdapterKind::Production,
            plaintext_fallback: false,
            best_effort_database_mirror: false,
            static_bearer_authentication: false,
            hs256_bridge_authentication: false,
            unversioned_policy_dependencies: false,
            live_external_payout_enabled: false,
        },
    );
    assert!(
        profile
            .blockers()
            .contains(&"runtime_scorer_not_production".to_string())
    );

    let random = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let package_hash = package.package_hash().unwrap();
    let signed = SignedBundlePackage {
        package,
        signature: BundlePackageSignature {
            algorithm: PACKAGE_SIGNATURE_ALGORITHM.to_string(),
            key_id: "qualification-release-key".to_string(),
            package_hash: package_hash.clone(),
            signature_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key_pair.sign(package_hash.as_bytes()).as_ref()),
        },
    };
    let trust = BundlePackageTrustStore::new([TrustedBundleKey {
        key_id: signed.signature.key_id.clone(),
        public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key_pair.public_key().as_ref()),
    }])
    .unwrap();
    let metadata = BundleQualificationMetadata {
        corpus_digest: sha256_prefixed(b"qualification-corpus"),
        input_digest: sha256_prefixed(b"qualification-input"),
        configuration_digest: sha256_prefixed(b"qualification-configuration"),
        code_revision_hash: sha256_prefixed(b"qualification-code"),
        runtime_dependency_digest: profile.runtime_identity_digest().unwrap(),
        evidence_hash: sha256_prefixed(b"qualification-evidence"),
    };
    let error = PipelineQualificationStore::new(backend)
        .qualify_bundle(
            &format!("pipeline-package-{}", Uuid::new_v4()),
            &signed,
            &trust,
            &metadata,
            &profile,
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(PACKAGE_DEVELOPMENT_DEPENDENCY_LABEL)
    );
}
