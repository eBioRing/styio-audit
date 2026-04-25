#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -m styio_audit.cli sync-upstream-local-workflows \
  --framework-root "$ROOT_DIR" \
  "$@"
