#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/enum/crawl-wget
# @inputs: target[, url, out-dir, scope-file, rate, timeout, crawl-full, update-wordlists]
# @outputs: note|asset
# @tools: wget, python3, scripts/update-wordlists.sh

TARGET=""
URL=""
OUT_DIR=""
SCOPE_FILE=""
RATE=""
TIMEOUT=""
CRAWL_FULL="0"
UPDATE_WORDLISTS="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"; shift 2 ;;
    --url)
      URL="${2:-}"; shift 2 ;;
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
    --update-wordlists)
      UPDATE_WORDLISTS="1"; shift 1 ;;
    *)
      if [[ -z "$TARGET" ]]; then TARGET="$1"; fi
      shift 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 --target <host> [--url url] [--out-dir dir] [--scope-file file] [--timeout sec] [--rate n] [--crawl-full] [--update-wordlists]" >&2
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
if [[ -z "$URL" ]]; then URL="${TARGET_URL:-}"; fi

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

# Prefer explicit URL when provided; otherwise probe https/http.
if [[ -n "$URL" ]]; then
  BASE_URL="$URL"
  if [[ ! "$BASE_URL" =~ ^https?:// ]]; then
    BASE_URL="https://${BASE_URL}"
  fi
  # Strip fragments for crawl base.
  BASE_URL="${BASE_URL%%#*}"
else
  BASE_URL="https://${TARGET}/"
  if ! timeout "${TIMEOUT}s" wget -q --spider --timeout=10 --tries=1 "$BASE_URL" >/dev/null 2>&1; then
    BASE_URL="http://${TARGET}/"
  fi
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

URLS_INTERNAL="${OUT_SUBDIR}/urls_internal.txt"
URLS_EXTERNAL="${OUT_SUBDIR}/urls_external.txt"

extract_urls() {
  local base_url="$1"; shift
  local target_host="$1"; shift
  local out_root="$1"; shift
  local wget_log="$1"; shift

  local tmp
  tmp="$(mktemp)"
  : >"$tmp"

  # From wget log: request URLs and redirect locations.
  if [[ -f "$wget_log" ]]; then
    rg -oN --no-filename 'https?://[^[:space:]<>"'\'')\\]]+' "$wget_log" 2>/dev/null >>"$tmp" || true
    rg -n --no-filename '^Location: ' "$wget_log" 2>/dev/null | sed -E 's/^Location:[[:space:]]+//' >>"$tmp" || true
  fi

  # From downloaded content: only text-ish extensions we accept.
  find "$out_root" -type f \( \
    -iname '*.html' -o -iname '*.htm' -o -iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.css' -o -iname '*.json' -o -iname '*.xml' -o -iname '*.txt' -o -iname '*.svg' \
  \) -size -10M 2>/dev/null | while read -r f; do
    rg -oN --no-filename 'https?://[^[:space:]<>"'\'')\\]]+' "$f" 2>/dev/null >>"$tmp" || true
    rg -oN --no-filename '//[^[:space:]<>"'\'')\\]]+' "$f" 2>/dev/null >>"$tmp" || true
    rg -oN --no-filename '(/[^[:space:]<>"'\'')\\]]+)' "$f" 2>/dev/null >>"$tmp" || true
  done

  python3 - "$target_host" "$base_url" "$URLS_INTERNAL" "$URLS_EXTERNAL" <"$tmp" <<'PY'
import sys
from urllib.parse import urlsplit, urlunsplit

target = sys.argv[1].strip().lower()
base = sys.argv[2].strip()
out_i = sys.argv[3]
out_e = sys.argv[4]

base_split = urlsplit(base)
base_scheme = base_split.scheme or "https"

def clean(s: str) -> str:
  s = s.strip()
  # Strip common trailing punctuation from JS/HTML contexts.
  while s and s[-1] in ".,;:)]}>'\"":
    s = s[:-1]
  while s and s[0] in "<'\"(":
    s = s[1:]
  return s.strip()

internal = set()
external = set()

for raw in sys.stdin:
  s = clean(raw)
  if not s:
    continue
  if s.startswith("//"):
    s = f"{base_scheme}:{s}"
  if s.startswith("/"):
    # Keep as absolute URL for consistency.
    s = f"{base_scheme}://{target}{s}"

  if not (s.startswith("http://") or s.startswith("https://")):
    continue

  try:
    sp = urlsplit(s)
  except Exception:
    continue
  host = (sp.hostname or "").lower()
  if not host:
    continue

  # Normalize: drop fragment.
  sp = sp._replace(fragment="")
  s_norm = urlunsplit(sp)

  def is_internal(h: str) -> bool:
    return h == target or h.endswith("." + target)

  if is_internal(host):
    internal.add(s_norm)
  else:
    external.add(s_norm)

with open(out_i, "w", encoding="utf-8") as f:
  for u in sorted(internal):
    f.write(u + "\n")
with open(out_e, "w", encoding="utf-8") as f:
  for u in sorted(external):
    f.write(u + "\n")
PY

  rm -f "$tmp"
}

if command -v rg >/dev/null 2>&1; then
  extract_urls "$BASE_URL" "$TARGET" "$OUT_SUBDIR" "$LOG_FILE" || true
else
  emit_note "wget" "info" "rg not found; skipping URL extraction"
  : >"$URLS_INTERNAL"
  : >"$URLS_EXTERNAL"
fi

internal_count="$(wc -l <"$URLS_INTERNAL" | tr -d ' ')"
external_count="$(wc -l <"$URLS_EXTERNAL" | tr -d ' ')"

if [[ "$UPDATE_WORDLISTS" == "1" ]]; then
  WL_PATHS="wordlists/custom/paths.txt"
  WL_API="wordlists/custom/api_endpoints.txt"
  WL_PARAMS="wordlists/custom/params.txt"
  before_paths="$(wc -l <"$WL_PATHS" 2>/dev/null | tr -d ' ' || echo 0)"
  before_api="$(wc -l <"$WL_API" 2>/dev/null | tr -d ' ' || echo 0)"
  before_params="$(wc -l <"$WL_PARAMS" 2>/dev/null | tr -d ' ' || echo 0)"

  if [[ -x "scripts/update-wordlists.sh" || -f "scripts/update-wordlists.sh" ]]; then
    bash scripts/update-wordlists.sh --from-run "$ROOT_OUT" >&2 || true
    after_paths="$(wc -l <"$WL_PATHS" 2>/dev/null | tr -d ' ' || echo 0)"
    after_api="$(wc -l <"$WL_API" 2>/dev/null | tr -d ' ' || echo 0)"
    after_params="$(wc -l <"$WL_PARAMS" 2>/dev/null | tr -d ' ' || echo 0)"

    add_paths="$(( after_paths - before_paths ))"
    add_api="$(( after_api - before_api ))"
    add_params="$(( after_params - before_params ))"

    printf '{"type":"note","tool":"wordlists","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"info","evidence":[],"data":{"paths_added_lines":%s,"api_endpoints_added_lines":%s,"params_added_lines":%s},"source":"src/skills/shell/enum/02-crawl-wget.sh"}\n' \
      "$TARGET" "$TS" "$TIMESTAMP" "$add_paths" "$add_api" "$add_params"
  else
    emit_note "wordlists" "info" "scripts/update-wordlists.sh not found; skipping"
  fi
fi

printf '{"type":"asset","tool":"wget-crawl","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"info","evidence":["%s","%s","%s","%s","%s"],"data":{"base_url":"%s","depth":%s,"max_files":%s,"max_file_kb":%s,"quota_mb":%s,"files":%s,"full":%s,"urls_internal":%s,"urls_external":%s},"source":"src/skills/shell/enum/02-crawl-wget.sh"}\n' \
  "$TARGET" "$TS" "$TIMESTAMP" \
  "$LOG_FILE" "$warc_file" "$cdx_file" "$URLS_INTERNAL" "$URLS_EXTERNAL" \
  "$BASE_URL" "$DEPTH" "$MAX_FILES" "$MAX_FILE_KB" "$QUOTA_MB" "$count_files" "$CRAWL_FULL" \
  "$internal_count" "$external_count"
