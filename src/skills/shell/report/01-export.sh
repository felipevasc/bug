#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/report/export
# @inputs: target[, out-dir]
# @outputs: note
# @tools: tar

TARGET=""
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    *)
      if [[ -z "$TARGET" ]]; then
        TARGET="$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 --target <target> (or positional <target>)" >&2
  exit 1
fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_TS="${RUN_TS:-}"
if [[ -z "$RUN_TS" ]]; then RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"; fi
ROOT_OUT="${OUT_DIR:-}"
if [[ -z "$ROOT_OUT" ]]; then ROOT_OUT="data/runs/${RUN_TS}"; fi
REPORT_DIR="data/reports/${RUN_TS}"
mkdir -p "$REPORT_DIR"

emit_note() {
  local tool="$1"; shift
  local sev="$1"; shift
  local msg="$1"; shift
  printf '{"type":"note","tool":"%s","stage":"report","target":"%s","ts":"%s","severity":"%s","evidence":%s,"data":{"message":"%s"},"source":"src/skills/shell/report/01-export.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$sev" "[]" "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
}

if command -v tar >/dev/null 2>&1; then
  archive="${REPORT_DIR}/evidence.tar.gz"
  tar -C "$ROOT_OUT" -czf "$archive" evidence records.jsonl 2>/dev/null || true
  printf '{"type":"note","tool":"export","stage":"report","target":"%s","ts":"%s","severity":"info","evidence":["%s"],"data":{"archive":"%s","out_dir":"%s"},"source":"src/skills/shell/report/01-export.sh"}\n' \
    "$TARGET" "$TS" "$archive" "$archive" "$ROOT_OUT"
else
  emit_note "tar" "info" "tool not found; skipping archive"
fi
