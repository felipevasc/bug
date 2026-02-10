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

# Accept URL values in --target and normalize to a hostname.
norm="$(
  python3 - "$TARGET" <<'PY'
import re,sys
from urllib.parse import urlsplit

s=(sys.argv[1] if len(sys.argv)>1 else "").strip()

def has_scheme(x: str) -> bool:
  return re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", x or "") is not None

def looks_like_url(x: str) -> bool:
  if not x:
    return False
  if has_scheme(x):
    return True
  if re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+/\\d{1,2}$", x):
    return False
  if re.search(r"[/?#]", x):
    return True
  if re.match(r"^[^/]+:\\d{1,5}$", x):
    return True
  return False

host=s
if looks_like_url(s):
  u=s if has_scheme(s) else "https://"+s
  try:
    sp=urlsplit(u)
    host=(sp.hostname or s).lower().rstrip(".")
  except Exception:
    host=s.lower().rstrip(".")
else:
  host=s.lower().rstrip(".")

print(host)
PY
)"
if [[ -n "$norm" ]]; then TARGET="$norm"; fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIMESTAMP="$TS"
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
  printf '{"type":"note","tool":"%s","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"%s","evidence":%s,"data":{"message":"%s"},"source":"src/skills/shell/enum/01-dir-enum.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$TIMESTAMP" "$sev" "[]" "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
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

# Prefer repo-curated wordlist if present; otherwise fallback to SecLists.
wordlist="wordlists/custom/paths.txt"
if [[ ! -f "$wordlist" ]]; then
  wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
fi
if [[ ! -f "$wordlist" ]]; then
  wordlist="/usr/share/wordlists/dirb/common.txt"
fi
if [[ ! -f "$wordlist" ]]; then
  emit_note "wordlist" "info" "no common wordlist found; skipping"
  exit 0
fi

if command -v ffuf >/dev/null 2>&1; then
  out_json="${EV_DIR}/${TARGET}.ffuf.json"
  timeout --foreground "${TIMEOUT}s" ffuf -u "${base}/FUZZ" -w "$wordlist" -ac -t 20 -rate "$RATE" -timeout "${TIMEOUT}" -of json -o "$out_json" >/dev/null 2>&1 || true
  if [[ -s "$out_json" ]]; then
    # Extract interesting hits (2xx, 3xx, 401, 403) and emit one finding per hit.
    hits_tsv="${EV_DIR}/${TARGET}.ffuf.interesting.tsv"
    hits_txt="${EV_DIR}/${TARGET}.ffuf.interesting.txt"
    python3 - "$out_json" "$hits_tsv" "$hits_txt" <<'PY'
import json,sys
from pathlib import Path
p=sys.argv[1]
tsv=Path(sys.argv[2])
txt=Path(sys.argv[3])
try:
  d=json.load(open(p,'r',encoding='utf-8',errors='ignore'))
  res=d.get('results') or []
  interesting=[]
  for r in res:
    url=r.get("url")
    st=r.get("status")
    ln=r.get("length")
    if not url or st is None:
      continue
    try:
      st_i=int(st)
    except Exception:
      continue
    if (200 <= st_i < 300) or (300 <= st_i < 400) or st_i in (401,403):
      interesting.append((st_i, url, ln if ln is not None else ""))
  # Stable output order: status then URL
  interesting.sort(key=lambda x: (x[0], x[1]))
  tsv.write_text("\n".join([f"{st}\t{url}\t{ln}" for st, url, ln in interesting]) + ("\n" if interesting else ""), encoding="utf-8", errors="ignore")
  txt.write_text("\n".join([f"{st} {url}" for st, url, _ in interesting]) + ("\n" if interesting else ""), encoding="utf-8", errors="ignore")
except Exception:
  tsv.write_text("", encoding="utf-8", errors="ignore")
  txt.write_text("", encoding="utf-8", errors="ignore")
PY

    while IFS=$'\t' read -r status url length; do
      [[ -z "${url:-}" ]] && continue
      sev="info"
      if [[ "$status" == "401" || "$status" == "403" ]]; then sev="low"; fi
      if [[ "$status" =~ ^3 ]]; then sev="info"; fi
      printf '{"type":"finding","tool":"ffuf","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"%s","evidence":["%s","%s","%s"],"data":{"kind":"interesting_path","base":"%s","url":"%s","status":%s,"length":%s},"source":"src/skills/shell/enum/01-dir-enum.sh"}\n' \
        "$TARGET" "$TS" "$TIMESTAMP" "$sev" "$out_json" "$hits_txt" "$hits_tsv" "$base" \
        "$(printf '%s' "$url" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')" \
        "$(printf '%s' "$status" | python3 -c 'import sys; s=sys.stdin.read().strip(); print(s if s else "null")')" \
        "$(printf '%s' "${length:-}" | python3 -c 'import sys; s=sys.stdin.read().strip(); print(s if s else "null")')"
    done < "$hits_tsv"

    cnt="$(wc -l <"$hits_tsv" | tr -d ' ')"
    emit_note "ffuf" "info" "ffuf interesting results: ${cnt} (see evidence)"
  else
    emit_note "ffuf" "info" "ffuf produced no output"
  fi
else
  emit_note "ffuf" "info" "tool not found; skipping"
fi
