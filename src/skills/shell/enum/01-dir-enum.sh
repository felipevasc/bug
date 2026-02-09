#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/enum/dir-enum
# @inputs: target
# @outputs: finding
# @tools: ffuf, dirsearch

TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
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
JSON=$(printf '{"type":"finding","target":"%s","data":{"category":"dir-enum","paths":["/admin","/backup"],"notes":"placeholder"},"timestamp":"%s","source":"src/skills/shell/enum/01-dir-enum.sh"}\n' "$TARGET" "$TS")

echo "$JSON"
