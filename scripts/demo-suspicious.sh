#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-https://example.com}"
REQUESTS="${2:-40}"
CONCURRENCY="${3:-8}"

echo "burst target=${TARGET} requests=${REQUESTS} concurrency=${CONCURRENCY}"
seq "${REQUESTS}" | xargs -n1 -P "${CONCURRENCY}" -I{} sh -c '
  curl --http1.1 -fsS -o /dev/null "'"${TARGET}"'" || true
'
