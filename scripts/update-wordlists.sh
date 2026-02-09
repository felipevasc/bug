#!/usr/bin/env bash
set -euo pipefail

# Update repo wordlists from a run directory.
# Usage:
#   bash scripts/update-wordlists.sh --from-run data/runs/<RUN_TS>

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-run)
      RUN_DIR="${2:-}"; shift 2 ;;
    *)
      echo "Usage: $0 --from-run data/runs/<RUN_TS>" >&2
      exit 2 ;;
  esac
done

[[ -n "$RUN_DIR" ]] || { echo "missing --from-run" >&2; exit 2; }
[[ -d "$RUN_DIR" ]] || { echo "run dir not found: $RUN_DIR" >&2; exit 2; }

WL_DIR="wordlists/custom"
mkdir -p "$WL_DIR"
PATHS_WL="$WL_DIR/paths.txt"
API_WL="$WL_DIR/api_endpoints.txt"
PARAMS_WL="$WL_DIR/params.txt"

# Ensure files exist
: >>"$PATHS_WL"
: >>"$API_WL"
: >>"$PARAMS_WL"

add_unique() {
  local infile="$1"; shift
  local dst="$1"; shift
  [[ -s "$infile" ]] || return 0

  # keep comments/header at top; append new unique lines at end.
  local tmp
  tmp="$(mktemp)"
  # existing content
  cat "$dst" >"$tmp"

  # filter: remove blanks and comments
  awk 'NF && $0 !~ /^#/' "$infile" | tr -d '\r' | sort -u >"${tmp}.new"
  awk 'NF && $0 !~ /^#/' "$dst" | tr -d '\r' | sort -u >"${tmp}.old"

  comm -13 "${tmp}.old" "${tmp}.new" >"${tmp}.diff" || true
  if [[ -s "${tmp}.diff" ]]; then
    {
      echo
      echo "# --- added from run $(basename "$RUN_DIR") on $(date -u +%Y-%m-%dT%H:%M:%SZ) ---"
      cat "${tmp}.diff"
    } >>"$dst"
  fi

  rm -f "$tmp" "${tmp}.new" "${tmp}.old" "${tmp}.diff"
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# 1) From ffuf outputs
find "$RUN_DIR" -type f -name '*.ffuf.json' -size +0c 2>/dev/null | while read -r ff; do
  python3 scripts/wordlists/extract_paths_from_ffuf.py "$ff" >"$TMP_DIR/paths_from_ffuf.txt" || true
  add_unique "$TMP_DIR/paths_from_ffuf.txt" "$PATHS_WL"
done

# 2) From crawled content (if user ran a crawler separately and saved under evidence/enum/crawl)
CRAWL_DIR="$RUN_DIR/evidence/enum/crawl"
if [[ -d "$CRAWL_DIR" ]]; then
  python3 scripts/wordlists/extract_from_js.py endpoints "$CRAWL_DIR" >"$TMP_DIR/endpoints_from_js.txt" || true
  python3 scripts/wordlists/extract_from_js.py params "$CRAWL_DIR" >"$TMP_DIR/params_from_js.txt" || true
  add_unique "$TMP_DIR/endpoints_from_js.txt" "$API_WL"
  add_unique "$TMP_DIR/params_from_js.txt" "$PARAMS_WL"
fi

echo "[wordlists] updated: $PATHS_WL $API_WL $PARAMS_WL" >&2
