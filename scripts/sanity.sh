#!/usr/bin/env bash
set -euo pipefail

# Quick local sanity checks (no Faraday required).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "[sanity] FAIL: $*" >&2
  exit 1
}

command -v node >/dev/null 2>&1 || fail "node not found"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
command -v bash >/dev/null 2>&1 || fail "bash not found"

echo "[sanity] node: $(node -v)"
echo "[sanity] python: $(python3 --version)"

echo "[sanity] node syntax checks"
node --check scripts/new-skill.js
node --check src/lib/faraday.js
node --check src/bin/run-pipeline.js
node --check src/bin/faraday-ingest.js
node --check src/bin/faraday-query.js
node --check src/skills/nodejs/recon/01-passive-recon.js
node --check src/skills/nodejs/enum/01-http-enum.js
node --check src/skills/nodejs/exploit/01-proof-of-concept.js
node --check src/skills/nodejs/report/01-faraday-summary.js

echo "[sanity] python compile"
python3 -m py_compile src/skills/python/recon/01-dns-recon.py
python3 -m py_compile src/skills/python/enum/01-port-scan.py
python3 -m py_compile src/skills/python/exploit/01-ssrf-check.py
python3 -m py_compile src/skills/python/report/01-faraday-note.py

echo "[sanity] shell smoke"
bash src/skills/shell/recon/01-subdomains.sh --target example.com >/dev/null
bash src/skills/shell/enum/01-dir-enum.sh --target example.com >/dev/null
bash src/skills/shell/exploit/01-sqli-test.sh --target example.com >/dev/null
bash src/skills/shell/report/01-export.sh --target example.com >/dev/null

echo "[sanity] pipeline dry-run count"
count=$(node src/bin/run-pipeline.js --target example.com --dry-run 2>/dev/null | wc -l | tr -d ' ')
if [[ "$count" != "12" ]]; then
  fail "expected 12 records, got $count"
fi

echo "[sanity] OK"
