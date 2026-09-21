#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec bash "${ROOT}/scripts/operator/lab/run.sh" corpus-run --policies compatibility \
  --json-report "${ROOT}/.local/pipeline-compatibility-corpus-report.json" \
  --markdown-report "${ROOT}/.local/pipeline-compatibility-corpus-report.md" \
  --catalog "${ROOT}/.local/pipeline-lab-catalog.json" "$@"
