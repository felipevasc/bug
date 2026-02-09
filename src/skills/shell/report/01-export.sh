#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/report/export
# @inputs: target
# @outputs: note
# @tools: faraday-cli

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
JSON=$(printf '{"type":"note","target":"%s","data":{"summary":"placeholder export","format":"md"},"timestamp":"%s","source":"src/skills/shell/report/01-export.sh"}\n' "$TARGET" "$TS")

echo "$JSON"
