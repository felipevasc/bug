#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-ufu.br}"
OUT_DIR="data/runs/ufu_20260210T133747Z"

# Ensure output path exists so that the skill can locate the crawl artifacts.
mkdir -p "$OUT_DIR"

export ALLOW_VULN=1
export INPUT_PROBE_MAX_CANDIDATES="${INPUT_PROBE_MAX_CANDIDATES:-200}"
export PAYLOADS_PER_PARAM="${PAYLOADS_PER_PARAM:-30}"
export RATE="${RATE:-2}"
export TIMEOUT="${TIMEOUT:-15}"

node "src/skills/nodejs/vuln/01-input-probe.js" \
  --target "$TARGET" \
  --out-dir "$OUT_DIR" \
  --allow-vuln \
  --rate "$RATE" \
  --timeout "$TIMEOUT" \
  "$@"
