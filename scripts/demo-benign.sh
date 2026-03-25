#!/usr/bin/env bash
set -euo pipefail

ROUNDS="${1:-2}"
DELAY_SECONDS="${2:-2}"
TARGETS=(
  "https://www.google.com"
  "https://www.cloudflare.com"
  "https://www.github.com"
  "https://www.wikipedia.org"
)

for round in $(seq 1 "${ROUNDS}"); do
  echo "benign round ${round}/${ROUNDS}"
  for target in "${TARGETS[@]}"; do
    echo "  -> ${target}"
    curl --http1.1 -fsS -o /dev/null "${target}" || true
    sleep "${DELAY_SECONDS}"
  done
done
