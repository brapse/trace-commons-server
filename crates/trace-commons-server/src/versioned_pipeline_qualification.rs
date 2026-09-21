// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Package trust and promotion qualification.
//!
//! Qualification evidence is deliberately separate from pipeline history.
//! The ingest database stores only the immutable fact that a package passed
//! qualification. Detailed reports and drill output stay in operator-owned
//! evidence storage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trace_commons_gate_api::pipeline::{BundlePackage, Phase};

use crate::db::postgres::PgBackend;
use crate::error::DatabaseError;
use crate::versioned_pipeline::{
    PgPipelineStore, PipelineDependencyIdentity, PipelineDependencyQualification, PipelineService,
};
use crate::versioned_pipeline_compat::{
    COMPATIBILITY_SCORE_IMPLEMENTATION, COMPATIBILITY_SETTLE_IMPLEMENTATION,
};

pub const PACKAGE_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const PACKAGE_SIGNATURE_INVALID_LABEL: &str = "bundle_package_signature_invalid";
pub const PACKAGE_SIGNER_UNTRUSTED_LABEL: &str = "bundle_package_signer_untrusted";
pub const PACKAGE_IMPLEMENTATION_UNKNOWN_LABEL: &str = "bundle_implementation_unknown";
pub const PACKAGE_DEVELOPMENT_DEPENDENCY_LABEL: &str = "bundle_development_dependency";
pub const PACKAGE_QUALIFICATION_MISSING_LABEL: &str = "bundle_qualification_missing";
pub const PACKAGE_RUNTIME_REVISION_MISMATCH_LABEL: &str = "bundle_runtime_revision_mismatch";
pub const QUALIFICATION_EVIDENCE_STALE_LABEL: &str = "qualification_evidence_stale";
pub const QUALIFICATION_EVIDENCE_MISSING_LABEL: &str = "qualification_evidence_missing";
pub const QUALIFICATION_EVIDENCE_FAILED_LABEL: &str = "qualification_evidence_failed";

pub const REQUIRED_PROMOTION_DRILLS: &[&str] = &[
    "tenant_isolation",
    "bundle_package_integrity",
    "bundle_activation_rollback",
    "phase_outcome_atomicity",
    "fenced_lease_recovery",
    "settle_command_recovery",
    "index_idempotency_conflict",
    "settlement_preview_approval",
    "near_outbox_recovery",
    "withdrawal_propagation",
    "key_rotation",
    "audit_chain_verification",
    "backup_restore",
    "hf_corpus_qualification",
];

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePackageSignature {
    pub algorithm: String,
    pub key_id: String,
    pub package_hash: String,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBundlePackage {
    pub package: BundlePackage,
    pub signature: BundlePackageSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedBundleKey {
    pub key_id: String,
    pub public_key_base64url: String,
}

#[derive(Debug, Clone, Default)]
pub struct BundlePackageTrustStore {
    keys: BTreeMap<String, Vec<u8>>,
}

impl BundlePackageTrustStore {
    pub fn new(keys: impl IntoIterator<Item = TrustedBundleKey>) -> Result<Self, String> {
        let mut trusted = BTreeMap::new();
        for key in keys {
            if !is_safe_identifier(&key.key_id) {
                return Err(PACKAGE_SIGNER_UNTRUSTED_LABEL.to_string());
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key.public_key_base64url)
                .map_err(|_| PACKAGE_SIGNER_UNTRUSTED_LABEL.to_string())?;
            if bytes.len() != 32 || trusted.insert(key.key_id, bytes).is_some() {
                return Err(PACKAGE_SIGNER_UNTRUSTED_LABEL.to_string());
            }
        }
        Ok(Self { keys: trusted })
    }

    pub fn verify(&self, signed: &SignedBundlePackage) -> Result<(), String> {
        signed
            .package
            .validate()
            .map_err(|_| PACKAGE_SIGNATURE_INVALID_LABEL.to_string())?;
        if signed.signature.algorithm != PACKAGE_SIGNATURE_ALGORITHM
            || !is_safe_identifier(&signed.signature.key_id)
        {
            return Err(PACKAGE_SIGNATURE_INVALID_LABEL.to_string());
        }
        let package_hash = signed
            .package
            .package_hash()
            .map_err(|_| PACKAGE_SIGNATURE_INVALID_LABEL.to_string())?;
        if signed.signature.package_hash != package_hash {
            return Err(PACKAGE_SIGNATURE_INVALID_LABEL.to_string());
        }
        let public_key = self
            .keys
            .get(&signed.signature.key_id)
            .ok_or_else(|| PACKAGE_SIGNER_UNTRUSTED_LABEL.to_string())?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signed.signature.signature_base64url)
            .map_err(|_| PACKAGE_SIGNATURE_INVALID_LABEL.to_string())?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(package_hash.as_bytes(), &signature)
            .map_err(|_| PACKAGE_SIGNATURE_INVALID_LABEL.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductionAdapterKind {
    Production,
    Development,
    Synthetic,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionDependencyProfile {
    runtime_identity: PipelineDependencyIdentity,
    runtime_qualification: PipelineDependencyQualification,
    pub authoritative_metadata: ProductionAdapterKind,
    pub artifact_store: ProductionAdapterKind,
    pub key_wrapper: ProductionAdapterKind,
    pub authentication: ProductionAdapterKind,
    pub plaintext_fallback: bool,
    pub best_effort_database_mirror: bool,
    pub static_bearer_authentication: bool,
    pub hs256_bridge_authentication: bool,
    pub unversioned_policy_dependencies: bool,
    pub live_external_payout_enabled: bool,
}

impl ProductionDependencyProfile {
    pub fn from_runtime(
        service: &PipelineService,
        infrastructure: ProductionInfrastructureProfile,
    ) -> Self {
        Self {
            runtime_identity: service.dependency_identity(),
            runtime_qualification: service.dependency_qualification(),
            authoritative_metadata: infrastructure.authoritative_metadata,
            artifact_store: infrastructure.artifact_store,
            key_wrapper: infrastructure.key_wrapper,
            authentication: infrastructure.authentication,
            plaintext_fallback: infrastructure.plaintext_fallback,
            best_effort_database_mirror: infrastructure.best_effort_database_mirror,
            static_bearer_authentication: infrastructure.static_bearer_authentication,
            hs256_bridge_authentication: infrastructure.hs256_bridge_authentication,
            unversioned_policy_dependencies: infrastructure.unversioned_policy_dependencies,
            live_external_payout_enabled: infrastructure.live_external_payout_enabled,
        }
    }

    pub fn runtime_identity_digest(&self) -> Result<String, String> {
        let encoded = serde_json::to_vec(&self.runtime_identity)
            .map_err(|_| "runtime_dependency_identity_invalid".to_string())?;
        Ok(sha256_prefixed(&encoded))
    }

    pub fn blockers(&self) -> Vec<String> {
        let adapters = [
            ("authoritative_metadata", &self.authoritative_metadata),
            ("artifact_store", &self.artifact_store),
            ("key_wrapper", &self.key_wrapper),
            ("authentication", &self.authentication),
        ];
        let mut blockers = adapters
            .into_iter()
            .filter(|(_, kind)| **kind != ProductionAdapterKind::Production)
            .map(|(name, _)| format!("{name}_not_production"))
            .collect::<Vec<_>>();
        for (qualified, label) in [
            (
                self.runtime_qualification.authority,
                "runtime_authority_not_production",
            ),
            (
                self.runtime_qualification.privacy,
                "runtime_privacy_not_production",
            ),
            (
                self.runtime_qualification.scorer,
                "runtime_scorer_not_production",
            ),
            (
                self.runtime_qualification.embedder,
                "runtime_embedder_not_production",
            ),
            (
                self.runtime_qualification.index_reader,
                "runtime_index_reader_not_production",
            ),
            (
                self.runtime_qualification.index_writer,
                "runtime_index_writer_not_production",
            ),
        ] {
            if !qualified {
                blockers.push(label.to_string());
            }
        }
        if self
            .runtime_qualification
            .settlement_adapters
            .values()
            .any(|qualified| !qualified)
        {
            blockers.push("runtime_settlement_not_production".to_string());
        }
        if self.live_external_payout_enabled && !self.runtime_qualification.payout_adapter {
            blockers.push("runtime_payout_not_production".to_string());
        }
        for (blocked, label) in [
            (self.plaintext_fallback, "plaintext_fallback_enabled"),
            (
                self.best_effort_database_mirror,
                "best_effort_database_mirror_enabled",
            ),
            (
                self.static_bearer_authentication,
                "static_bearer_authentication_enabled",
            ),
            (
                self.hs256_bridge_authentication,
                "hs256_bridge_authentication_enabled",
            ),
            (
                self.unversioned_policy_dependencies,
                "unversioned_policy_dependency",
            ),
            (
                self.live_external_payout_enabled,
                "live_external_payout_enabled",
            ),
        ] {
            if blocked {
                blockers.push(label.to_string());
            }
        }
        blockers
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionInfrastructureProfile {
    pub authoritative_metadata: ProductionAdapterKind,
    pub artifact_store: ProductionAdapterKind,
    pub key_wrapper: ProductionAdapterKind,
    pub authentication: ProductionAdapterKind,
    pub plaintext_fallback: bool,
    pub best_effort_database_mirror: bool,
    pub static_bearer_authentication: bool,
    pub hs256_bridge_authentication: bool,
    pub unversioned_policy_dependencies: bool,
    pub live_external_payout_enabled: bool,
}

impl ProductionInfrastructureProfile {
    pub fn local_test() -> Self {
        Self {
            authoritative_metadata: ProductionAdapterKind::Production,
            artifact_store: ProductionAdapterKind::Development,
            key_wrapper: ProductionAdapterKind::Development,
            authentication: ProductionAdapterKind::Development,
            plaintext_fallback: false,
            best_effort_database_mirror: false,
            static_bearer_authentication: true,
            hs256_bridge_authentication: false,
            unversioned_policy_dependencies: false,
            live_external_payout_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleQualificationMetadata {
    pub corpus_digest: String,
    pub input_digest: String,
    pub configuration_digest: String,
    pub code_revision_hash: String,
    pub runtime_dependency_digest: String,
    pub evidence_hash: String,
}

impl BundleQualificationMetadata {
    fn validate(&self) -> Result<(), String> {
        if [
            &self.corpus_digest,
            &self.input_digest,
            &self.configuration_digest,
            &self.code_revision_hash,
            &self.runtime_dependency_digest,
            &self.evidence_hash,
        ]
        .into_iter()
        .all(|value| is_sha256(value))
        {
            Ok(())
        } else {
            Err("bundle_qualification_metadata_invalid".to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleQualificationRecord {
    pub bundle_id: String,
    pub package_hash: String,
    pub signing_key_id: String,
    pub signature_hash: String,
    pub metadata: BundleQualificationMetadata,
    pub qualified_at: DateTime<Utc>,
}

fn validate_production_package(package: &BundlePackage) -> Result<(), String> {
    let implementations = [
        (
            Phase::Admission,
            package.manifest.admission.implementation_id.as_str(),
        ),
        (
            Phase::Review,
            package.manifest.review.implementation_id.as_str(),
        ),
        (
            Phase::Score,
            package.manifest.score.implementation_id.as_str(),
        ),
        (
            Phase::Settle,
            package.manifest.settle.implementation_id.as_str(),
        ),
    ];
    let known = implementations.iter().all(|(phase, implementation)| {
        matches!(
            (phase, *implementation),
            (
                Phase::Admission,
                "trace_commons.admission.authority_privacy.v1"
            ) | (Phase::Review, "trace_commons.review.authority_privacy.v1")
        ) || (*phase == Phase::Score && *implementation == COMPATIBILITY_SCORE_IMPLEMENTATION)
            || (*phase == Phase::Settle && *implementation == COMPATIBILITY_SETTLE_IMPLEMENTATION)
    });
    if !known {
        return Err(PACKAGE_IMPLEMENTATION_UNKNOWN_LABEL.to_string());
    }
    let has_development_dependency = package
        .manifest
        .score
        .projection_ids
        .iter()
        .chain(package.manifest.settle.projection_ids.iter())
        .any(|identity| identity.contains("test") || identity.contains("reference"))
        || package.artifacts.values().any(|artifact| {
            let text = String::from_utf8_lossy(artifact).to_ascii_lowercase();
            [
                "local_reference",
                "reference_",
                "pipeline-test",
                "mock_",
                "synthetic",
            ]
            .iter()
            .any(|marker| text.contains(marker))
        });
    if has_development_dependency {
        return Err(PACKAGE_DEVELOPMENT_DEPENDENCY_LABEL.to_string());
    }
    Ok(())
}

pub struct PipelineQualificationStore {
    backend: Arc<PgBackend>,
    packages: PgPipelineStore,
}

impl PipelineQualificationStore {
    pub fn new(backend: Arc<PgBackend>) -> Self {
        Self {
            packages: PgPipelineStore::new(backend.clone()),
            backend,
        }
    }

    pub async fn qualify_bundle(
        &self,
        tenant_id: &str,
        signed: &SignedBundlePackage,
        trust: &BundlePackageTrustStore,
        metadata: &BundleQualificationMetadata,
        dependencies: &ProductionDependencyProfile,
    ) -> Result<BundleQualificationRecord, DatabaseError> {
        trust.verify(signed).map_err(DatabaseError::Constraint)?;
        validate_production_package(&signed.package).map_err(DatabaseError::Constraint)?;
        metadata.validate().map_err(DatabaseError::Constraint)?;
        if metadata.runtime_dependency_digest
            != dependencies
                .runtime_identity_digest()
                .map_err(DatabaseError::Constraint)?
        {
            return Err(DatabaseError::Constraint(
                "runtime_dependency_identity_mismatch".to_string(),
            ));
        }
        let blockers = dependencies.blockers();
        if !blockers.is_empty() {
            return Err(DatabaseError::Constraint(blockers[0].clone()));
        }
        self.packages
            .register_bundle(tenant_id, &signed.package)
            .await?;
        let package_hash = signed
            .package
            .package_hash()
            .map_err(|_| DatabaseError::Serialization(PACKAGE_SIGNATURE_INVALID_LABEL.into()))?;
        let signature_hash = sha256_prefixed(signed.signature.signature_base64url.as_bytes());
        let mut client = self.backend.trace_pool().get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO pipeline_bundle_qualifications (
                tenant_id, bundle_id, package_hash, signing_key_id,
                signature_hash, corpus_digest, input_digest,
                configuration_digest, code_revision_hash,
                runtime_dependency_digest, evidence_hash
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (tenant_id, bundle_id) DO NOTHING",
            &[
                &tenant_id,
                &signed.package.bundle_id,
                &package_hash,
                &signed.signature.key_id,
                &signature_hash,
                &metadata.corpus_digest,
                &metadata.input_digest,
                &metadata.configuration_digest,
                &metadata.code_revision_hash,
                &metadata.runtime_dependency_digest,
                &metadata.evidence_hash,
            ],
        )
        .await?;
        let row = tx
            .query_one(
                "SELECT bundle_id, package_hash, signing_key_id, signature_hash,
                        corpus_digest, input_digest, configuration_digest,
                        code_revision_hash, runtime_dependency_digest,
                        evidence_hash, qualified_at
                   FROM pipeline_bundle_qualifications
                  WHERE tenant_id = $1 AND bundle_id = $2",
                &[&tenant_id, &signed.package.bundle_id],
            )
            .await?;
        let record = qualification_from_row(&row);
        if record.package_hash != package_hash
            || record.signing_key_id != signed.signature.key_id
            || record.signature_hash != signature_hash
            || record.metadata != *metadata
        {
            return Err(DatabaseError::Constraint(
                "bundle qualification identity conflict".to_string(),
            ));
        }
        tx.commit().await?;
        Ok(record)
    }

    pub async fn activate_qualified_bundle(
        &self,
        tenant_id: &str,
        bundle_id: &str,
        promotion: &PromotionDecision,
        runtime_code_revision_hash: &str,
        dependencies: &ProductionDependencyProfile,
    ) -> Result<(), DatabaseError> {
        let now = Utc::now();
        if !promotion.ready
            || !promotion.safe_blockers.is_empty()
            || !is_sha256(&promotion.evidence_hash)
            || promotion.evaluated_at > now
            || now - promotion.evaluated_at > Duration::minutes(15)
        {
            return Err(DatabaseError::Constraint(
                QUALIFICATION_EVIDENCE_FAILED_LABEL.to_string(),
            ));
        }
        if !is_sha256(runtime_code_revision_hash) {
            return Err(DatabaseError::Constraint(
                PACKAGE_RUNTIME_REVISION_MISMATCH_LABEL.to_string(),
            ));
        }
        if let Some(blocker) = dependencies.blockers().into_iter().next() {
            return Err(DatabaseError::Constraint(blocker));
        }
        let mut client = self.backend.trace_pool().get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
        let qualified_revision = tx
            .query_opt(
                "SELECT code_revision_hash, runtime_dependency_digest
                   FROM pipeline_bundle_qualifications
                  WHERE tenant_id = $1 AND bundle_id = $2",
                &[&tenant_id, &bundle_id],
            )
            .await?
            .map(|row| {
                (
                    row.get::<_, String>("code_revision_hash"),
                    row.get::<_, String>("runtime_dependency_digest"),
                )
            });
        match qualified_revision.as_ref() {
            None => {
                return Err(DatabaseError::Constraint(
                    PACKAGE_QUALIFICATION_MISSING_LABEL.to_string(),
                ));
            }
            Some((qualified, _)) if qualified != runtime_code_revision_hash => {
                return Err(DatabaseError::Constraint(
                    PACKAGE_RUNTIME_REVISION_MISMATCH_LABEL.to_string(),
                ));
            }
            Some((_, qualified_dependencies))
                if qualified_dependencies
                    != &dependencies
                        .runtime_identity_digest()
                        .map_err(DatabaseError::Constraint)? =>
            {
                return Err(DatabaseError::Constraint(
                    "runtime_dependency_identity_mismatch".to_string(),
                ));
            }
            Some(_) => {}
        }
        let changed = tx
            .execute(
                "INSERT INTO pipeline_active_bundles (tenant_id, bundle_id)
                 SELECT $1, q.bundle_id
                   FROM pipeline_bundle_qualifications q
                  WHERE q.tenant_id = $1 AND q.bundle_id = $2
                    AND 4 = (
                        SELECT COUNT(*) FROM pipeline_bundle_policy_status ps
                         WHERE ps.tenant_id = q.tenant_id
                           AND ps.bundle_id = q.bundle_id
                           AND ps.operational_status = 'runnable'
                    )
                 ON CONFLICT (tenant_id) DO UPDATE
                 SET bundle_id = EXCLUDED.bundle_id, selected_at = NOW()",
                &[&tenant_id, &bundle_id],
            )
            .await?;
        if changed == 0 {
            return Err(DatabaseError::Constraint(
                PACKAGE_QUALIFICATION_MISSING_LABEL.to_string(),
            ));
        }
        tx.commit().await?;
        Ok(())
    }
}

fn qualification_from_row(row: &tokio_postgres::Row) -> BundleQualificationRecord {
    BundleQualificationRecord {
        bundle_id: row.get("bundle_id"),
        package_hash: row.get("package_hash"),
        signing_key_id: row.get("signing_key_id"),
        signature_hash: row.get("signature_hash"),
        metadata: BundleQualificationMetadata {
            corpus_digest: row.get("corpus_digest"),
            input_digest: row.get("input_digest"),
            configuration_digest: row.get("configuration_digest"),
            code_revision_hash: row.get("code_revision_hash"),
            runtime_dependency_digest: row.get("runtime_dependency_digest"),
            evidence_hash: row.get("evidence_hash"),
        },
        qualified_at: row.get("qualified_at"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DrillStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrillEvidence {
    pub drill_id: String,
    pub status: DrillStatus,
    pub safe_blockers: Vec<String>,
    pub observed_at: DateTime<Utc>,
    pub maximum_age_seconds: u64,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionDecision {
    pub ready: bool,
    pub evaluated_at: DateTime<Utc>,
    pub evidence_hash: String,
    pub safe_blockers: Vec<String>,
}

pub fn evaluate_promotion(
    evidence: &[DrillEvidence],
    now: DateTime<Utc>,
) -> Result<PromotionDecision, String> {
    let mut by_id = BTreeMap::new();
    for item in evidence {
        if !REQUIRED_PROMOTION_DRILLS.contains(&item.drill_id.as_str())
            || !is_sha256(&item.evidence_hash)
            || item.maximum_age_seconds == 0
            || item
                .safe_blockers
                .iter()
                .any(|label| !is_safe_identifier(label))
        {
            return Err("qualification_evidence_invalid".to_string());
        }
        if by_id.insert(item.drill_id.as_str(), item).is_some() {
            return Err("qualification_evidence_duplicate".to_string());
        }
    }
    let mut blockers = Vec::new();
    for drill_id in REQUIRED_PROMOTION_DRILLS {
        let Some(item) = by_id.get(drill_id) else {
            blockers.push(format!("{QUALIFICATION_EVIDENCE_MISSING_LABEL}:{drill_id}"));
            continue;
        };
        if item.status != DrillStatus::Pass {
            blockers.push(format!("{QUALIFICATION_EVIDENCE_FAILED_LABEL}:{drill_id}"));
        }
        let maximum_age = i64::try_from(item.maximum_age_seconds)
            .map_err(|_| "qualification_evidence_invalid".to_string())?;
        if item.observed_at > now || now - item.observed_at > Duration::seconds(maximum_age) {
            blockers.push(format!("{QUALIFICATION_EVIDENCE_STALE_LABEL}:{drill_id}"));
        }
    }
    blockers.sort();
    let canonical = serde_json::to_vec(&(
        "trace_commons.pipeline_promotion.v1",
        now.timestamp(),
        &blockers,
        evidence
            .iter()
            .map(|item| (&item.drill_id, &item.evidence_hash))
            .collect::<BTreeSet<_>>(),
    ))
    .map_err(|_| "qualification_evidence_invalid".to_string())?;
    Ok(PromotionDecision {
        ready: blockers.is_empty(),
        evaluated_at: now,
        evidence_hash: sha256_prefixed(&canonical),
        safe_blockers: blockers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use crate::versioned_pipeline::MinimalPolicyBundle;
    use crate::versioned_pipeline_compat::CompatibilityScoreRuntime;
    use crate::versioned_pipeline_index::IsolatedPipelineIndex;

    fn compatibility_package() -> BundlePackage {
        MinimalPolicyBundle::build_compatibility(&CompatibilityScoreRuntime::reference(
            IsolatedPipelineIndex::new(),
        ))
        .unwrap()
        .package
    }

    fn signed_package() -> (SignedBundlePackage, BundlePackageTrustStore) {
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let package = compatibility_package();
        let package_hash = package.package_hash().unwrap();
        let signature = key_pair.sign(package_hash.as_bytes());
        let signed = SignedBundlePackage {
            package,
            signature: BundlePackageSignature {
                algorithm: PACKAGE_SIGNATURE_ALGORITHM.to_string(),
                key_id: "release-2026-09".to_string(),
                package_hash,
                signature_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.as_ref()),
            },
        };
        let trust = BundlePackageTrustStore::new([TrustedBundleKey {
            key_id: "release-2026-09".to_string(),
            public_key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key_pair.public_key().as_ref()),
        }])
        .unwrap();
        (signed, trust)
    }

    #[test]
    fn package_signature_binds_canonical_package_and_trusted_key() {
        let (mut signed, trust) = signed_package();
        trust.verify(&signed).unwrap();
        signed.signature.package_hash = sha256_prefixed(b"different");
        assert_eq!(
            trust.verify(&signed),
            Err(PACKAGE_SIGNATURE_INVALID_LABEL.to_string())
        );
    }

    #[test]
    fn package_trust_rejects_artifact_tampering_unknown_keys_and_algorithms() {
        let (signed, trust) = signed_package();

        let mut tampered = signed.clone();
        tampered
            .package
            .artifacts
            .values_mut()
            .next()
            .expect("package has policy artifacts")
            .push(0);
        assert_eq!(
            trust.verify(&tampered),
            Err(PACKAGE_SIGNATURE_INVALID_LABEL.to_string())
        );

        let empty_trust =
            BundlePackageTrustStore::new(std::iter::empty::<TrustedBundleKey>()).unwrap();
        assert_eq!(
            empty_trust.verify(&signed),
            Err(PACKAGE_SIGNER_UNTRUSTED_LABEL.to_string())
        );

        let mut wrong_algorithm = signed;
        wrong_algorithm.signature.algorithm = "HS256".to_string();
        assert_eq!(
            trust.verify(&wrong_algorithm),
            Err(PACKAGE_SIGNATURE_INVALID_LABEL.to_string())
        );
    }

    #[test]
    fn production_looking_labels_on_synthetic_adapters_cannot_qualify() {
        let mut package = compatibility_package();
        assert_eq!(
            validate_production_package(&package),
            Err(PACKAGE_DEVELOPMENT_DEPENDENCY_LABEL.to_string())
        );
        package.manifest.score.implementation_id = "trace_commons.score.unknown.v1".to_string();
        assert_eq!(
            validate_production_package(&package),
            Err(PACKAGE_IMPLEMENTATION_UNKNOWN_LABEL.to_string())
        );
        let runtime_identity = PipelineDependencyIdentity {
            authority: "production_authority".to_string(),
            privacy: "production_privacy".to_string(),
            scorer: "production_scorer".to_string(),
            embedder: "production_embedder".to_string(),
            index_reader: "production_index_reader".to_string(),
            index_writer: "production_index_writer".to_string(),
            settlement_adapters: BTreeMap::from([(
                "trace_credit".to_string(),
                "production_settlement".to_string(),
            )]),
            payout_adapter: "production_payout".to_string(),
        };
        let profile = ProductionDependencyProfile {
            runtime_identity,
            runtime_qualification: PipelineDependencyQualification {
                authority: false,
                privacy: false,
                scorer: false,
                embedder: false,
                index_reader: false,
                index_writer: false,
                settlement_adapters: BTreeMap::from([("trace_credit".to_string(), false)]),
                payout_adapter: false,
            },
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
        };
        let blockers = profile.blockers();
        assert!(blockers.contains(&"runtime_scorer_not_production".to_string()));
        assert!(blockers.contains(&"runtime_settlement_not_production".to_string()));
    }

    #[test]
    fn promotion_requires_current_passing_evidence_for_every_drill() {
        let now = Utc::now();
        let evidence = REQUIRED_PROMOTION_DRILLS
            .iter()
            .map(|drill_id| DrillEvidence {
                drill_id: (*drill_id).to_string(),
                status: DrillStatus::Pass,
                safe_blockers: Vec::new(),
                observed_at: now,
                maximum_age_seconds: 3_600,
                evidence_hash: sha256_prefixed(drill_id.as_bytes()),
            })
            .collect::<Vec<_>>();
        assert!(evaluate_promotion(&evidence, now).unwrap().ready);
        let stale = evaluate_promotion(&evidence, now + Duration::hours(2)).unwrap();
        assert!(!stale.ready);
        assert!(
            stale
                .safe_blockers
                .iter()
                .all(|label| label.starts_with(QUALIFICATION_EVIDENCE_STALE_LABEL))
        );
        assert!(!evaluate_promotion(&evidence[..1], now).unwrap().ready);
        let mut failed = evidence.clone();
        failed[0].status = DrillStatus::Fail;
        let failed_decision = evaluate_promotion(&failed, now).unwrap();
        assert!(!failed_decision.ready);
        assert!(
            failed_decision
                .safe_blockers
                .iter()
                .any(|label| { label.starts_with(QUALIFICATION_EVIDENCE_FAILED_LABEL) })
        );
        let mut duplicate = evidence.clone();
        duplicate.push(evidence[0].clone());
        assert_eq!(
            evaluate_promotion(&duplicate, now),
            Err("qualification_evidence_duplicate".to_string())
        );
    }
}
