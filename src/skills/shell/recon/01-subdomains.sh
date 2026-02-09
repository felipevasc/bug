#!/usr/bin/env bash
set -euo pipefail

# @skill: shell/recon/subdomains
# @inputs: target
# @outputs: asset
# @tools: subfinder, assetfinder

TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="${2:-}"
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
JSON=$(printf '{"type":"asset","target":"%s","data":{"method":"subdomains","notes":"placeholder"},"timestamp":"%s","source":"src/skills/shell/recon/01-subdomains.sh"}\n' "$TARGET" "$TS")

echo "$JSON"
