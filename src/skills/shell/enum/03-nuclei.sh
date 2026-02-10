#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/enum/nuclei
# @inputs: target[, out-dir, scope-file, rate, timeout, allow-vuln]
# @outputs: finding|note
# @tools: nuclei

TARGET=""
OUT_DIR=""
SCOPE_FILE=""
RATE=""
TIMEOUT=""
ALLOW_VULN_FLAG="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2;;
    --rate) RATE="${2:-}"; shift 2;;
    --timeout) TIMEOUT="${2:-}"; shift 2;;
    --allow-vuln) ALLOW_VULN_FLAG="true"; shift 1;;
    *)
      if [[ -z "$TARGET" ]]; then TARGET="$1"; fi
      shift;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 --target <target>" >&2
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
EV_DIR="${ROOT_OUT}/evidence/enum/nuclei"
mkdir -p "$EV_DIR"

RATE="${RATE:-2}"
# TIMEOUT is treated as *overall runtime budget* (seconds) for the skill.
# Nuclei's per-request timeout should be much smaller; otherwise it can appear to hang.
RUN_TIMEOUT="${TIMEOUT:-60}"
REQ_TIMEOUT="${NUCLEI_REQ_TIMEOUT:-20}"
# Keep req timeout sane relative to run timeout.
if [[ "$RUN_TIMEOUT" =~ ^[0-9]+$ ]]; then
  if [[ "$REQ_TIMEOUT" =~ ^[0-9]+$ && "$REQ_TIMEOUT" -gt "$RUN_TIMEOUT" ]]; then
    REQ_TIMEOUT="$RUN_TIMEOUT"
  fi
fi

emit_note() {
  local tool="$1"; shift
  local sev="$1"; shift
  local msg="$1"; shift
  printf '{"type":"note","tool":"%s","stage":"enum","target":"%s","ts":"%s","timestamp":"%s","severity":"%s","evidence":[],"data":{"message":"%s"},"source":"src/skills/shell/enum/03-nuclei.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$TIMESTAMP" "$sev" "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
}

if [[ "$ALLOW_VULN_FLAG" != "true" && "${ALLOW_VULN:-}" != "1" && "${ALLOW_VULN:-}" != "true" ]]; then
  emit_note "vuln-gate" "info" "blocked by default; require --allow-vuln (or env ALLOW_VULN=1)"
  exit 0
fi

if ! command -v nuclei >/dev/null 2>&1; then
  emit_note "nuclei" "info" "tool not found; skipping"
  exit 0
fi

records_path="${ROOT_OUT}/records.jsonl"
urls_txt="${EV_DIR}/${TARGET}.urls.txt"
: >"$urls_txt"

# Collect URLs from records.jsonl emitted by http-enum (httpx asset) and curl findings.
if [[ -f "$records_path" ]]; then
  python3 - "$records_path" "$SCOPE_FILE" >"$urls_txt" <<'PY'
import json,sys,re
from pathlib import Path

records=Path(sys.argv[1]).read_text(encoding='utf-8',errors='ignore').splitlines()
scope_path=sys.argv[2] if len(sys.argv)>2 else ''

entries=[]
if scope_path:
  p=Path(scope_path)
  if p.is_file():
    for raw in p.read_text(encoding='utf-8',errors='ignore').splitlines():
      s=raw.split('#',1)[0].strip()
      if s:
        entries.append(s)

def host_in_scope(host:str)->bool:
  if not entries:
    return True
  h=host.lower().rstrip('.')
  for e in entries:
    e=e.lower().rstrip('.')
    if e.startswith('*.'):
      root=e[2:]
      if h==root or h.endswith('.'+root):
        return True
    else:
      if h==e or h.endswith('.'+e):
        return True
  return False

urls=set()
for line in records:
  line=line.strip()
  if not line: continue
  try:
    o=json.loads(line)
  except Exception:
    continue
  if o.get('tool')=='httpx' and o.get('type')=='asset':
    for u in (o.get('data') or {}).get('urls') or []:
      if isinstance(u,str): urls.add(u)
  if o.get('tool')=='curl' and o.get('type')=='finding':
    u=(o.get('data') or {}).get('effective_url') or (o.get('data') or {}).get('url')
    if isinstance(u,str): urls.add(u)

out=[]
for u in sorted(urls):
  m=re.match(r'^https?://([^/]+)', u)
  if not m: continue
  host=m.group(1).split(':')[0]
  if host_in_scope(host):
    out.append(u)

print('\n'.join(out))
PY
else
  # Fallback: just scan the canonical target URLs.
  printf '%s\n' "https://${TARGET}/" "http://${TARGET}/" >"$urls_txt"
fi

cnt="$(wc -l <"$urls_txt" | tr -d ' ')"
if [[ "$cnt" == "0" ]]; then
  emit_note "nuclei" "info" "no in-scope URLs collected; skipping"
  exit 0
fi

out_jsonl="${EV_DIR}/${TARGET}.nuclei.jsonl"
: >"$out_jsonl"

# Conservative nuclei run.
# -rl : requests per second
# -timeout : per request timeout
# -severity: we keep all, but can filter later
# templates: focus on misconfig/exposures/headers/cves
emit_note "nuclei" "info" "running nuclei on ${cnt} urls (rate=${RATE}, run_timeout=${RUN_TIMEOUT}, req_timeout=${REQ_TIMEOUT})"

# Note: templates location is managed by nuclei itself (templates installed under ~/.local/nuclei-templates).
# Use tags/categories to keep it safe.
cat "$urls_txt" | timeout "${RUN_TIMEOUT}s" nuclei \
  -silent \
  -jsonl \
  -rl "$RATE" \
  -timeout "$REQ_TIMEOUT" \
  -tags misconfig,exposure,exposures,headers,cve \
  -severity info,low,medium,high,critical \
  2>"${EV_DIR}/${TARGET}.nuclei.stderr.txt" \
  | tee "$out_jsonl" >/dev/null || true

# Emit records from nuclei output.
python3 - "$out_jsonl" "$TARGET" <<'PY'
import json,sys
from datetime import datetime, timezone
from pathlib import Path

def now_iso():
  return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

def emit(o):
  if 'ts' not in o: o['ts']=now_iso()
  if 'timestamp' not in o: o['timestamp']=o['ts']
  sys.stdout.write(json.dumps(o,separators=(',',':'))+'\n')

p=Path(sys.argv[1])
target_arg = sys.argv[2] if len(sys.argv) > 2 else ""
if not p.exists() or p.stat().st_size==0:
  emit({"type":"note","tool":"nuclei","stage":"enum","target":target_arg,"severity":"info","evidence":[str(p)],"data":{"message":"nuclei produced no output"},"source":"src/skills/shell/enum/03-nuclei.sh"})
  raise SystemExit(0)

sev_map={"info":"info","low":"low","medium":"med","high":"high","critical":"crit"}

for line in p.read_text(encoding='utf-8',errors='ignore').splitlines():
  line=line.strip()
  if not line: continue
  try:
    o=json.loads(line)
  except Exception:
    continue
  info=o.get('info') or {}
  name=info.get('name') or info.get('description') or 'nuclei'
  severity=sev_map.get(str(info.get('severity') or 'info').lower(),'info')
  matched=o.get('matched') or o.get('host') or ''
  template=o.get('template-id') or o.get('templateID') or ''
  emit({
    "type":"finding",
    "tool":"nuclei",
    "stage":"enum",
    "target": matched,
    "severity": severity,
    "evidence": [str(p)],
    "data": {"template": template, "name": name, "matcher": o.get('matcher-name') or o.get('matcherName')},
    "source": "src/skills/shell/enum/03-nuclei.sh"
  })
PY
