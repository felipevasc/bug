#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="data/runs/${run_ts}"
scope_file="/tmp/bug-scope-${run_ts}.txt"

cat >"$scope_file" <<'EOF'
example.com
*.example.com
EOF

echo "[smoke] out_dir=$out_dir" >&2

jsonl="$(RUN_TS="$run_ts" node src/bin/run-pipeline.js --pipeline scripts/pipeline.smoke.json --target example.com --dry-run --out-dir "$out_dir" --scope-file "$scope_file" --timeout 3 --rate 5 || true)"
if [[ -z "$jsonl" ]]; then
  echo "[smoke] FAIL: no JSONL output" >&2
  exit 1
fi

echo "$jsonl" | python3 - <<'PY'
import json,sys
req=("type","tool","stage","target","ts","severity","evidence")
for i,line in enumerate(sys.stdin.read().splitlines(),1):
  line=line.strip()
  if not line: continue
  o=json.loads(line)
  for k in req:
    assert k in o, (i,k)
print("ok")
PY

report_dir="data/reports/${run_ts}"
if [[ ! -f "${report_dir}/report.md" ]]; then
  echo "[smoke] FAIL: missing report.md at ${report_dir}/report.md" >&2
  exit 1
fi

echo "[smoke] OK" >&2

