#!/usr/bin/env bash
set -euo pipefail

FILTER="${1:?test filter is required}"
shift
LISTING="$(RUSTFLAGS="${RUSTFLAGS:--D warnings}" cargo test "$@" "${FILTER}" -- --list)"
if ! grep -Eq ': test$' <<<"${LISTING}"; then
  echo "cargo test filter matched zero tests: ${FILTER}" >&2
  exit 1
fi
RUSTFLAGS="${RUSTFLAGS:--D warnings}" cargo test "$@" "${FILTER}"
