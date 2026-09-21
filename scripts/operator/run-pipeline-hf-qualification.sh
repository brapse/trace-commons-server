#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIN="${ROOT}/docs/superpowers/specs/versioned-pipeline-hf-corpus-v1.json"
OUTPUT="${ROOT}/.local/pipeline-hf"
CATALOG="${ROOT}/.local/pipeline-lab-catalog.json"
EVIDENCE="${OUTPUT}/qualification-report.json"
LOCAL_DIR="${TRACE_COMMONS_PIPELINE_HF_LOCAL_JSONL_DIR:-}"

cd "${ROOT}"
mkdir -p "${OUTPUT}"

PINNED=()
while IFS= read -r value; do
  PINNED[${#PINNED[@]}]="${value}"
done < <(python3 - "${PIN}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
for field in (
    "repository", "revision", "split", "translator", "bootstrap_count",
    "holdout_count", "min_words", "max_words", "expected_instrument_count",
    "source_digest", "order_digest",
):
    print(value[field])
PY
)

MIN_WORDS="${PINNED[6]}"
SOURCE_DIGEST="${PINNED[9]}"
ORDER_DIGEST="${PINNED[10]}"
if [[ -n "${LOCAL_DIR}" ]]; then
  MIN_WORDS=1
  SOURCE_DIGEST="${TRACE_COMMONS_PIPELINE_HF_LOCAL_SOURCE_DIGEST:-sha256:fdf56253bff083a19045afa91dc3ba8142d994b72c1dcc1b23bec5be4dd0e9ef}"
  ORDER_DIGEST="${TRACE_COMMONS_PIPELINE_HF_LOCAL_ORDER_DIGEST:-sha256:6135f8f173fd9b60f13e986e1c002b91d7a32d147fd2425c66ee2b5023b7dfcb}"
fi

EXPORT_ARGS=(
  --repository "${PINNED[0]}"
  --revision "${PINNED[1]}"
  --split "${PINNED[2]}"
  --translator "${PINNED[3]}"
  --output-dir "${OUTPUT}"
  --bootstrap-count "${PINNED[4]}"
  --holdout-count "${PINNED[5]}"
  --min-words "${MIN_WORDS}"
  --max-words "${PINNED[7]}"
  --expected-instrument-count "${PINNED[8]}"
  --expected-source-digest "${SOURCE_DIGEST}"
  --expected-order-digest "${ORDER_DIGEST}"
)
if [[ -n "${LOCAL_DIR}" ]]; then
  EXPORT_ARGS+=(--local-jsonl-dir "${LOCAL_DIR}")
fi

RUSTFLAGS="-D warnings" cargo run -q -p trace-commons-server \
  --bin trace-commons-pipeline-corpus-export -- "${EXPORT_ARGS[@]}"

bash scripts/operator/lab/run.sh corpus-run \
  --policies compatibility \
  --corpus "${OUTPUT}/bootstrap-corpus.json" \
  --json-report "${OUTPUT}/bootstrap-report.json" \
  --markdown-report "${OUTPUT}/bootstrap-report.md" \
  --catalog "${CATALOG}"
bash scripts/operator/lab/run.sh corpus-run \
  --policies compatibility \
  --corpus "${OUTPUT}/holdout-corpus.json" \
  --json-report "${OUTPUT}/holdout-report.json" \
  --markdown-report "${OUTPUT}/holdout-report.md" \
  --catalog "${CATALOG}"

python3 - \
  "${OUTPUT}/source-manifest.json" \
  "${OUTPUT}/bootstrap-report.json" \
  "${OUTPUT}/holdout-report.json" \
  "${EVIDENCE}" "${PIN}" "$([[ -n "${LOCAL_DIR}" ]] && echo local || echo remote)" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

source_path, bootstrap_path, holdout_path, output_path, pin_path = map(
    pathlib.Path, sys.argv[1:6]
)
mode = sys.argv[6]
source = json.loads(source_path.read_text())
bootstrap = json.loads(bootstrap_path.read_text())
holdout = json.loads(holdout_path.read_text())
pin = json.loads(pin_path.read_text())


def require(condition, label):
    if not condition:
        raise SystemExit(label)


def qualify_report(report, expected_count):
    require(report["expected_fixture_count"] == expected_count, "sample_count_mismatch")
    require(report["completed_fixture_count"] == expected_count, "incomplete_run")
    require(report["failure_count"] == 0, "corpus_behavior_mismatch")
    for fixture in report["fixtures"]:
        require(fixture["replay_same_run"], "replay_mismatch")
        require(fixture["changed_content_refused"], "replay_conflict_mismatch")
        for field in ("consent", "privacy", "scoring", "settlement"):
            require(
                fixture[f"{field}_state"] == fixture[f"expected_{field}_state"],
                f"{field}_mismatch",
            )
        require(
            fixture["instrument_count"] == fixture["expected_instrument_count"],
            "multi_instrument_mismatch",
        )


qualify_report(bootstrap, source["bootstrap_count"])
qualify_report(holdout, source["holdout_count"])
require(bootstrap["bundle_id"] == holdout["bundle_id"], "bundle_mismatch")
if mode == "remote":
    for field in (
        "source_digest", "configuration_digest", "order_digest",
        "bootstrap_corpus_digest", "holdout_corpus_digest",
    ):
        require(source[field] == pin[field], f"{field}_mismatch")
now = datetime.now(timezone.utc)
inputs = {
    "bundle_id": holdout["bundle_id"],
    "corpus_digest": holdout["corpus_digest"],
    "configuration_digest": holdout["configuration_digest"],
    "source_digest": source["source_digest"],
    "source_configuration_digest": source["configuration_digest"],
    "sample_order_digest": source["order_digest"],
    "bootstrap_report_digest": bootstrap["report_digest"],
    "holdout_report_digest": holdout["report_digest"],
}
evidence_hash = "sha256:" + hashlib.sha256(
    json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
report = {
    "schema": "trace_commons.pipeline_hf_qualification_report.v1",
    "observed_at": now.isoformat(),
    "maximum_age_seconds": 604800,
    "status": "pass",
    "production_promotion_ready": False,
    "safe_blockers": ["full_promotion_evaluation_required"],
    "inputs": inputs,
    "evidence_hash": evidence_hash,
}
output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

python3 scripts/operator/lab/lab.py catalog \
  --report "${OUTPUT}/holdout-report.json" \
  --catalog "${CATALOG}" \
  --record "${EVIDENCE}"

echo "PipelineHfQualificationOK: evidence=${EVIDENCE}"
