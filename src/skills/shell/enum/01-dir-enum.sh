#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/enum/dir-enum
# @inputs: target[, out-dir, scope-file, rate, timeout]
# @outputs: finding|note
# @tools: ffuf, dirsearch, curl

TARGET=""
OUT_DIR=""
SCOPE_FILE=""
RATE=""
TIMEOUT=""
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
    --scope-file)
      SCOPE_FILE="${2:-}"
      shift 2
      ;;
    --rate)
      RATE="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT="${2:-}"
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
EV_DIR="${ROOT_OUT}/evidence/enum/dir"
mkdir -p "$EV_DIR"
TIMEOUT="${TIMEOUT:-30}"
RATE="${RATE:-50}"

emit_note() {
  local tool="$1"; shift
  local sev="$1"; shift
  local msg="$1"; shift
  printf '{"type":"note","tool":"%s","stage":"enum","target":"%s","ts":"%s","severity":"%s","evidence":%s,"data":{"message":"%s"},"source":"src/skills/shell/enum/01-dir-enum.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$sev" "[]" "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
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

base=""
if command -v curl >/dev/null 2>&1; then
  code="$(timeout "${TIMEOUT}s" curl -k -s -o /dev/null -w '%{http_code}' "https://${TARGET}/" || true)"
  if [[ "$code" != "000" && -n "$code" ]]; then
    base="https://${TARGET}"
  else
    code2="$(timeout "${TIMEOUT}s" curl -s -o /dev/null -w '%{http_code}' "http://${TARGET}/" || true)"
    if [[ "$code2" != "000" && -n "$code2" ]]; then base="http://${TARGET}"; fi
  fi
else
  emit_note "curl" "info" "tool not found; cannot verify scheme"
  base="http://${TARGET}"
fi

wordlist="/usr/share/wordlists/dirb/common.txt"
if [[ ! -f "$wordlist" ]]; then
  wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
fi
if [[ ! -f "$wordlist" ]]; then
  emit_note "wordlist" "info" "no common wordlist found; skipping"
  exit 0
fi

if command -v ffuf >/dev/null 2>&1; then
  out_json="${EV_DIR}/${TARGET}.ffuf.json"
  timeout "${TIMEOUT}s" ffuf -u "${base}/FUZZ" -w "$wordlist" -ac -t 40 -rate "$RATE" -timeout "${TIMEOUT}" -of json -o "$out_json" >/dev/null 2>&1 || true
  if [[ -s "$out_json" ]]; then
    # Extract a few interesting hits for JSONL record.
    hits="$(python3 - "$out_json" <<'PY'
import json,sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8',errors='ignore'))
  res=d.get('results') or []
  out=[]
  for r in res[:50]:
    out.append({"url":r.get("url"),"status":r.get("status"),"length":r.get("length")})
  print(json.dumps(out))
except Exception:
  print("[]")
PY
)"
    printf '{"type":"finding","tool":"ffuf","stage":"enum","target":"%s","ts":"%s","severity":"info","evidence":["%s"],"data":{"base":"%s","hits":%s},"source":"src/skills/shell/enum/01-dir-enum.sh"}\n' \
      "$TARGET" "$TS" "$out_json" "$base" "$hits"
  else
    emit_note "ffuf" "info" "ffuf produced no output"
  fi
else
  emit_note "ffuf" "info" "tool not found; skipping"
fi
