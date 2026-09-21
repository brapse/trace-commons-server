#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT="${ROOT}/.local/pipeline-qualification-report.json"
CATALOG="${ROOT}/.local/pipeline-lab-catalog.json"
INVENTORY="${ROOT}/.local/pipeline-interface-inventory.json"
CORPUS_REPORT="${ROOT}/.local/pipeline-compatibility-corpus-report.json"
RESTORE_REPORT="${ROOT}/.local/pipeline-restore-report.json"
MANIFEST="${ROOT}/docs/superpowers/specs/2026-09-11-versioned-pipeline-contract-test-manifest.json"

cd "${ROOT}"
mkdir -p "${ROOT}/.local"

run_filtered() {
  local filter="$1"
  shift
  scripts/operator/run-cargo-test-filter.sh "${filter}" "$@"
}

if [[ "${TRACE_COMMONS_QUALIFICATION_ZERO_FILTER_SELF_TEST:-0}" == "1" ]]; then
  if run_filtered qualification_filter_that_does_not_exist -p trace-commons-server --lib; then
    echo "zero-match qualification filter unexpectedly passed" >&2
    exit 1
  fi
  echo "ZeroFilterRejected"
  exit 0
fi

python3 scripts/operator/pipeline-deployment-inventory.py --check --output "${INVENTORY}"
RUSTFLAGS="-D warnings" cargo test -p trace-commons-gate-api --lib
run_filtered versioned_pipeline_qualification -p trace-commons-server --lib
run_filtered key_rotation_drill_records_passed_evidence_for_managed_key_rotation_window \
  -p trace-commons-server --bin trace-commons-ingest
run_filtered audit_chain_drill_records_passed_evidence_without_raw_failures \
  -p trace-commons-server --bin trace-commons-ingest
run_filtered managed_eddsa_signed_token_config_requires_issuer_audience_and_managed_keyset \
  -p trace-commons-server --bin trace-commons-ingest
run_filtered rejects_static_tenant_token_when_managed_eddsa_required \
  -p trace-commons-server --bin trace-commons-ingest
scripts/operator/run-pipeline-postgres-qualification.sh

scripts/operator/run-compatibility-pipeline-corpus.sh
scripts/operator/pipeline-backup-restore-smoke.sh

python3 - \
  "${REPORT}" "${INVENTORY}" "${CORPUS_REPORT}" "${RESTORE_REPORT}" "${MANIFEST}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

report_path, inventory_path, corpus_path, restore_path, manifest_path = map(
    pathlib.Path, sys.argv[1:]
)


def load(path):
    return json.loads(path.read_text())


def file_hash(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


inventory = load(inventory_path)
corpus = load(corpus_path)
restore = load(restore_path)
revision = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
base_revision_hash = "sha256:" + hashlib.sha256(revision.encode()).hexdigest()
repository_files = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    check=True,
    capture_output=True,
).stdout.split(b"\0")
tree = hashlib.sha256()
for raw_path in sorted(path for path in repository_files if path):
    path = pathlib.Path(raw_path.decode())
    if path.parts[0] in {".local", ".vscode", "target"} or not path.is_file():
        continue
    tree.update(len(raw_path).to_bytes(8, "big"))
    tree.update(raw_path)
    content = path.read_bytes()
    tree.update(len(content).to_bytes(8, "big"))
    tree.update(content)
revision_hash = "sha256:" + tree.hexdigest()
generated_at = datetime.now(timezone.utc).isoformat()

drill_sources = {
    "tenant_isolation": "versioned_pipeline_runtime_pg::concurrent_receipt_and_worker_retries_commit_once",
    "bundle_package_integrity": "versioned_pipeline_qualification::package_signature_binds_canonical_package_and_trusted_key",
    "bundle_activation_rollback": "versioned_pipeline_runtime_pg::pipeline_activation_rollback_containment_and_writer_retirement",
    "phase_outcome_atomicity": "versioned_pipeline_runtime_pg::concurrent_receipt_and_worker_retries_commit_once",
    "fenced_lease_recovery": "versioned_pipeline_runtime_pg::crash_reuses_completed_operations_and_payout_waits_for_confirmation_evidence",
    "settle_command_recovery": "versioned_pipeline_runtime_pg::multi_instrument_failure_retry_and_crash_are_independent_and_authoritative",
    "index_idempotency_conflict": "versioned_pipeline_runtime_pg::index_rebuild_uses_sealed_commands_without_new_credit_or_outcomes",
    "settlement_preview_approval": "versioned_pipeline_runtime_pg::multi_instrument_failure_retry_and_crash_are_independent_and_authoritative",
    "near_outbox_recovery": "versioned_pipeline_runtime_pg::crash_reuses_completed_operations_and_payout_waits_for_confirmation_evidence",
    "withdrawal_propagation": "versioned_pipeline_runtime_pg::withdrawal_commits_tombstone_propagation_audit_and_export_invalidation_atomically",
    "key_rotation": "trace_commons_ingest_internal::key_rotation_drill_records_passed_evidence_for_managed_key_rotation_window",
    "audit_chain_verification": "trace_commons_ingest_internal::audit_chain_drill_records_passed_evidence_without_raw_failures",
    "backup_restore": "pipeline-backup-restore-smoke",
    "hf_corpus_qualification": None,
}
drills = []
for drill_id, test_id in drill_sources.items():
    status = "pass" if test_id else "blocked"
    blockers = [] if test_id else ["hf_corpus_evidence_missing"]
    evidence = hashlib.sha256(
        f"{revision_hash}:{drill_id}:{test_id}".encode()
    ).hexdigest()
    drills.append(
        {
            "drill_id": drill_id,
            "status": status,
            "safe_blockers": blockers,
            "observed_at": generated_at,
            "maximum_age_seconds": 604800,
            "test_id": test_id,
            "evidence_hash": f"sha256:{evidence}",
        }
    )

inputs = {
    "code_revision_hash": revision_hash,
    "base_revision_hash": base_revision_hash,
    "bundle_id": corpus["bundle_id"],
    "corpus_digest": corpus["corpus_digest"],
    "configuration_digest": corpus["configuration_digest"],
    "inventory_digest": inventory["inventory_digest"],
    "contract_manifest_digest": file_hash(manifest_path),
    "restore_evidence_hash": restore["evidence_hash"],
}
evidence_hash = "sha256:" + hashlib.sha256(
    json.dumps(
        {"inputs": inputs, "drills": drills},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()
report = {
    "schema": "trace_commons.pipeline_qualification_report.v1",
    "generated_at": generated_at,
    "scope": "local_test",
    "status": "blocked",
    "production_promotion_ready": False,
    "safe_blockers": [
        "local_reference_scorer",
        "local_reference_embedder",
        "synthetic_index",
        "synthetic_settlement",
        "static_bearer_authentication",
        "hf_corpus_evidence_missing",
    ],
    "external_payout_enabled": False,
    "inputs": inputs,
    "drills": drills,
    "acceptance_layers": [
        "protocol_schema",
        "policy_contract",
        "phase_runner",
        "bundle_identity_and_corpus",
        "postgresql_transaction_and_rls",
        "adapter_idempotency",
        "crash_recovery",
        "black_box_api",
        "operator_drill",
        "end_to_end_scenario",
    ],
    "evidence_hash": evidence_hash,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

python3 scripts/operator/lab/lab.py catalog \
  --report "${CORPUS_REPORT}" \
  --catalog "${CATALOG}" \
  --record "${REPORT}" \
  --record "${INVENTORY}" \
  --record "${RESTORE_REPORT}"

echo "PipelineQualificationOK: report=${REPORT} catalog=${CATALOG}"
