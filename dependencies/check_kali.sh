#!/usr/bin/env bash
set -euo pipefail

need=(nmap httpx whatweb sslscan curl jq dig)
want=(ffuf nuclei amass subfinder assetfinder naabu)

printf "[deps] Checking required tools...\n" >&2
for t in "${need[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "  [OK] %s -> %s\n" "$t" "$(command -v "$t")"
  else
    printf "  [MISSING] %s\n" "$t"
  fi
done

printf "\n[deps] Checking recommended tools...\n" >&2
for t in "${want[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "  [OK] %s -> %s\n" "$t" "$(command -v "$t")"
  else
    printf "  [MISSING] %s\n" "$t"
  fi
done

printf "\n[deps] Faraday services (if installed)...\n" >&2
if command -v faraday-manage >/dev/null 2>&1; then
  echo "  faraday-manage: OK" >&2
  (ss -lntp 2>/dev/null || true) | sed -n '1,5p' >&2 || true
else
  echo "  faraday-manage: MISSING" >&2
fi
