#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec bash "${ROOT}/scripts/operator/lab/run.sh" corpus-run --policies minimal \
  --json-report "${ROOT}/.local/pipeline-minimal-corpus-report.json" \
  --markdown-report "${ROOT}/.local/pipeline-minimal-corpus-report.md" \
  --catalog "${ROOT}/.local/pipeline-lab-catalog.json" "$@"
