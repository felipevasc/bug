#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_vuln_stage_for_existing_run.sh --run <run-dir> [--target <target>] [--force]
  --run     Path to the existing run directory (data/runs/...)
  --target  Optional override of the target (auto-detected from records if omitted)
  --force   Re-run even if previous CVE enrichment records already exist
EOF
}

run_dir=""
target=""
force=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      run_dir="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --force)
      force=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$run_dir" ]]; then
  echo "Run directory is required (--run)." >&2
  usage
  exit 1
fi

run_dir=$(realpath "$run_dir")
records_file="$run_dir/records.jsonl"

if [[ ! -f "$records_file" ]]; then
  echo "records.jsonl not found under ${run_dir}." >&2
  exit 1
fi

if [[ -z "$target" ]]; then
  target=$(
    python3 - "$records_file" <<'PY'
import json
import sys

records_path = sys.argv[1]
with open(records_path, 'r', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        tgt = rec.get('target')
        if tgt:
            print(tgt)
            break
PY
  )
  target=${target//$'\n'/}
fi

if [[ -z "$target" ]]; then
  echo "Unable to determine the target from records. Provide --target." >&2
  exit 1
fi

if [[ "$force" != true ]] && grep -q '"tool":"cve-enrich"' "$records_file"; then
  echo "CVE enrichment already exists for this run; use --force to re-run." >&2
  exit 0
fi

node src/bin/run-pipeline.js --stage vuln --target "$target" --out-dir "$run_dir" --allow-vuln
