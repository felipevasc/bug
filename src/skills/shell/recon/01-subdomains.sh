#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/recon/subdomains
# @inputs: target[, out-dir, scope-file, rate, timeout]
# @outputs: asset|note
# @tools: subfinder, amass, assetfinder

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
      # Backwards-compatible: allow positional target.
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
ROOT_OUT="${OUT_DIR:-${OUT_DIR:-}}"
if [[ -z "$ROOT_OUT" ]]; then ROOT_OUT="${OUT_DIR:-${OUT_DIR:-}}"; fi
if [[ -z "$ROOT_OUT" ]]; then ROOT_OUT="data/runs/${RUN_TS}"; fi
EV_DIR="${ROOT_OUT}/evidence/recon/subdomains"
mkdir -p "$EV_DIR"
TIMEOUT="${TIMEOUT:-20}"

emit_note() {
  local tool="$1"; shift
  local sev="$1"; shift
  local msg="$1"; shift
  printf '{"type":"note","tool":"%s","stage":"recon","target":"%s","ts":"%s","severity":"%s","evidence":%s,"data":{"message":"%s"},"source":"src/skills/shell/recon/01-subdomains.sh"}\n' \
    "$tool" "$TARGET" "$TS" "$sev" "[]" "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip())[1:-1])')"
}

emit_asset() {
  local host="$1"; shift
  local tool="$1"; shift
  local ev="$1"; shift
  printf '{"type":"asset","tool":"%s","stage":"recon","target":"%s","ts":"%s","severity":"info","evidence":%s,"data":{"kind":"hostname","root":"%s"},"source":"src/skills/shell/recon/01-subdomains.sh"}\n' \
    "$tool" "$host" "$TS" "$(printf '%s' "$ev" | python3 -c 'import json,sys; print(json.dumps([sys.stdin.read().strip()]))')" "$TARGET"
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

tmp="${EV_DIR}/${TARGET}.subdomains.raw.txt"
: > "$tmp"

if command -v subfinder >/dev/null 2>&1; then
  timeout "${TIMEOUT}s" subfinder -silent -d "$TARGET" 2>/dev/null >>"$tmp" || true
else
  emit_note "subfinder" "info" "tool not found; skipping"
fi

if command -v amass >/dev/null 2>&1; then
  timeout "${TIMEOUT}s" amass enum -passive -d "$TARGET" 2>/dev/null >>"$tmp" || true
else
  emit_note "amass" "info" "tool not found; skipping"
fi

if command -v assetfinder >/dev/null 2>&1; then
  timeout "${TIMEOUT}s" assetfinder --subs-only "$TARGET" 2>/dev/null >>"$tmp" || true
else
  emit_note "assetfinder" "info" "tool not found; skipping"
fi

out="${EV_DIR}/${TARGET}.subdomains.txt"
sort -u "$tmp" | grep -E '^[A-Za-z0-9._-]+$' >"$out" || true

count="$(wc -l <"$out" | tr -d ' ')"
emit_note "subdomains" "info" "discovered ${count} hostnames (see evidence)"

while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  if in_scope "$host"; then
    emit_asset "$host" "subdomains" "$out"
  fi
done < "$out"
