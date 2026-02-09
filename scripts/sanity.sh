#!/usr/bin/env bash
set -euo pipefail

# Quick local sanity checks (no Faraday required).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

print_howto() {
  cat <<'EOF'
[sanity] How-to: instalar dependencias (inclui Faraday opcional)

Minimo para rodar o sanity/pipeline (dry-run):
- node
- python3
- bash

Faraday (opcional)

Opcao A: instalar o pacote .deb (amd64) da release 5.19.0:
  wget -O /tmp/faraday-server_amd64.deb https://github.com/infobyte/faraday/releases/download/v5.19.0/faraday-server_amd64.deb
  sudo dpkg -i /tmp/faraday-server_amd64.deb || sudo apt-get -f install

Opcao B: instalar via venv + fonte (passos base):
  pip3 install virtualenv
  virtualenv faraday_venv
  source faraday_venv/bin/activate
  git clone git@github.com:infobyte/faraday.git
  cd faraday
  pip3 install .
  faraday-manage initdb
  faraday-server

Dica: depois de subir o Faraday, configure:
  FARADAY_URL (ex: http://127.0.0.1:5985)
  FARADAY_WORKSPACE (workspace existente)
  FARADAY_TOKEN ou FARADAY_USER/FARADAY_PASS
EOF
}

fail() {
  echo "[sanity] FAIL: $*" >&2
  echo "[sanity] Tip: rode 'bash scripts/sanity.sh --howto' para ver como instalar dependencias." >&2
  exit 1
}

if [[ "${1:-}" == "--howto" || "${1:-}" == "--deps" || "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  case "${1:-}" in
    --help|-h)
      cat <<'EOF'
Usage:
  bash scripts/sanity.sh
  bash scripts/sanity.sh --howto
EOF
      ;;
    *)
      print_howto
      ;;
  esac
  exit 0
fi

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
echo "[sanity] Tip: para instalar dependencias/Faraday, rode: bash scripts/sanity.sh --howto" >&2
