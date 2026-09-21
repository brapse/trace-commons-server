// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
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
    PipelineServiceBuilder,
};
use trace_commons_server::versioned_pipeline_authority::{
    ClassifierRedactorPipelinePrivacyBoundary, StaticPipelineAuthorityProvider,
};
use trace_commons_server::versioned_pipeline_compat::{
    COMPATIBILITY_SCORE_IMPLEMENTATION, CompatibilityScoreRuntime,
};
use trace_commons_server::versioned_pipeline_credit::{
    RecordingNearAdapter, RecordingSettlementAdapter, SettlementAdapterRegistry,
};
use trace_commons_server::versioned_pipeline_index::{IsolatedPipelineIndex, PIPELINE_INDEX_ID};
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
    if let Err(error) = backend.run_migrations().await {
        eprintln!("skipping: migrations failed ({error})");
        return None;
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
            PipelineReceiptResult::ContentConflict => None,
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
