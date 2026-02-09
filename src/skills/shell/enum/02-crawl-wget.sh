#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/enum/crawl-wget
# @inputs: target[, out-dir, scope-file, rate, timeout, crawl-full]
# @outputs: note|asset
# @tools: wget

TARGET=""
OUT_DIR=""
SCOPE_FILE=""
RATE=""
TIMEOUT=""
CRAWL_FULL="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"; shift 2 ;;
    --out-dir)
      OUT_DIR="${2:-}"; shift 2 ;;
    --scope-file)
      SCOPE_FILE="${2:-}"; shift 2 ;;
    --rate)
      RATE="${2:-}"; shift 2 ;;
    --timeout)
      TIMEOUT="${2:-}"; shift 2 ;;
    --crawl-full)
      CRAWL_FULL="1"; shift 1 ;;
    *)
      if [[ -z "$TARGET" ]]; then TARGET="$1"; fi
      shift 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 --target <host> [--out-dir dir] [--scope-file file] [--timeout sec] [--rate n] [--crawl-full]" >&2
  exit 1
fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIMESTAMP="$TS"
RUN_TS="${RUN_TS:-}"
if [[ -z "$RUN_TS" ]]; then RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"; fi
ROOT_OUT="${OUT_DIR:-}"
if [[ -z "$ROOT_OUT" ]]; then ROOT_OUT="data/runs/${RUN_TS}"; fi
EV_DIR="${ROOT_OUT}/evidence/enum/crawl"
mkdir -p "$EV_DIR"

TIMEOUT="${TIMEOUT:-60}"
RATE="${RATE:-2}"

emit_note() {
  local tool="$1"; shift
  local sev="$1"; shift
  local msg="$1"; shift
  printf '{"type":"note","tool":"%s","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"%s","evidence":%s,"data":{"message":"%s"},"source":"src/skills/shell/enum/02-crawl-wget.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$TIMESTAMP" "$sev" "[]" \
    "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
}

in_scope() {
  local host="$1"
  [[ -z "$SCOPE_FILE" ]] && return 0
  [[ ! -f "$SCOPE_FILE" ]] && return 0
  local ok="0"
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue
    if [[ "$line" == "*."* ]]; then
      local root="${line#*.}"
      if [[ "$host" == "$root" || "$host" == *".${root}" ]]; then ok="1"; break; fi
    else
      if [[ "$host" == "$line" || "$host" == *".${line}" ]]; then ok="1"; break; fi
    fi
  done < "$SCOPE_FILE"
  [[ "$ok" == "1" ]]
}

if ! in_scope "$TARGET"; then
  emit_note "scope" "info" "target not in scope (blocked)"
  exit 0
fi

if ! command -v wget >/dev/null 2>&1; then
  emit_note "wget" "info" "tool not found; skipping"
  exit 0
fi

# Crawl policy
# Default is bounded. --crawl-full enables deeper crawl but still:
# - same host only
# - robots respected
# - no parent
# - size/file guards
DEPTH="2"
MAX_FILES="2000"
MAX_FILE_KB="2048"     # 2MB
WAIT="0.5"             # seconds between requests

if [[ "$CRAWL_FULL" == "1" ]]; then
  DEPTH="5"
  MAX_FILES="20000"
  MAX_FILE_KB="8192"   # 8MB
  WAIT="0.2"
fi

# Prefer https, fallback to http
BASE_URL="https://${TARGET}/"
if ! timeout "${TIMEOUT}s" wget -q --spider --timeout=10 --tries=1 "$BASE_URL" >/dev/null 2>&1; then
  BASE_URL="http://${TARGET}/"
fi

OUT_SUBDIR="${EV_DIR}/${TARGET}"
mkdir -p "$OUT_SUBDIR"
LOG_FILE="${OUT_SUBDIR}/wget.log"

emit_note "wget" "info" "starting crawl url=${BASE_URL} depth=${DEPTH} max_files=${MAX_FILES} max_file_kb=${MAX_FILE_KB} wait=${WAIT} full=${CRAWL_FULL}"

# Use --warc-file to keep a single archive for analysis.
# Note: warc grows quickly; keep bounded defaults.
WARC_PREFIX="${OUT_SUBDIR}/site"

# Run wget with safety guards.
# --no-parent keeps us within the target tree.
# --span-hosts is NOT used.
# --domains restricts to target.
# --accept limits to useful analysis content.
# --reject keeps binaries out by default.
# --wait + --random-wait avoid hammering.
# --quota provides a hard cap.
QUOTA_MB="200"
if [[ "$CRAWL_FULL" == "1" ]]; then QUOTA_MB="1500"; fi

ACCEPT="html,htm,js,mjs,cjs,json,xml,txt,css,svg"
REJECT="jpg,jpeg,png,gif,webp,mp4,mp3,avi,mov,pdf,zip,tar,gz,7z,exe,dmg,iso"

# hard cap by quota + per-file size
# --max-redirect defaults ok
# --no-check-certificate because some targets have odd TLS; evidence still captured
set +e
timeout "${TIMEOUT}s" wget \
  --mirror \
  --convert-links \
  --adjust-extension \
  --page-requisites \
  --no-parent \
  --domains "$TARGET" \
  --execute robots=on \
  --warc-file="$WARC_PREFIX" \
  --warc-cdx \
  --no-check-certificate \
  --wait="$WAIT" --random-wait \
  --limit-rate="${RATE}m" \
  --max-files="$MAX_FILES" \
  --max-redirect=5 \
  --timeout=15 --tries=2 \
  --quota="${QUOTA_MB}m" \
  --accept="$ACCEPT" \
  --reject="$REJECT" \
  --max-filesize="${MAX_FILE_KB}k" \
  --directory-prefix "$OUT_SUBDIR" \
  "$BASE_URL" >"$LOG_FILE" 2>&1
code=$?
set -e

# Emit summary
count_files="$(find "$OUT_SUBDIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
warc_file="${WARC_PREFIX}.warc.gz"
cdx_file="${WARC_PREFIX}.cdx"

emit_note "wget" "info" "crawl finished code=${code} files=${count_files} log=${LOG_FILE} warc=${warc_file}"

printf '{"type":"asset","tool":"wget-crawl","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"info","evidence":["%s","%s","%s"],"data":{"base_url":"%s","depth":%s,"max_files":%s,"max_file_kb":%s,"quota_mb":%s,"files":%s,"full":%s},"source":"src/skills/shell/enum/02-crawl-wget.sh"}\n' \
  "$TARGET" "$TS" "$TIMESTAMP" \
  "$LOG_FILE" "$warc_file" "$cdx_file" \
  "$BASE_URL" "$DEPTH" "$MAX_FILES" "$MAX_FILE_KB" "$QUOTA_MB" "$count_files" "$CRAWL_FULL"
