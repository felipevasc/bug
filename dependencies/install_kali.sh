#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash dependencies/install_kali.sh
# Optional env:
#   INSTALL_FARADAY=0   # skip faraday
#   INSTALL_NUCLEI=1    # install nuclei (default 1)
#   INSTALL_GO_TOOLS=1  # install subfinder/assetfinder/naabu via go (default 1)

INSTALL_FARADAY="${INSTALL_FARADAY:-1}"
INSTALL_NUCLEI="${INSTALL_NUCLEI:-1}"
INSTALL_GO_TOOLS="${INSTALL_GO_TOOLS:-1}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[deps] This script uses apt and needs sudo." >&2
fi

echo "[deps] apt update" >&2
sudo apt update

echo "[deps] installing base packages" >&2
sudo apt install -y \
  ca-certificates curl jq git \
  dnsutils \
  nmap sslscan whatweb \
  python3 python3-venv python3-pip \
  timeout \
  || true

# httpx is often from apt in Kali; if not available, user can install via go.
if ! command -v httpx >/dev/null 2>&1; then
  echo "[deps] httpx not found after apt. (Optional) Install via go: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" >&2
fi

echo "[deps] installing recon/enum packages" >&2
sudo apt install -y \
  amass \
  ffuf \
  seclists \
  || true

if [[ "$INSTALL_NUCLEI" == "1" ]]; then
  echo "[deps] installing nuclei" >&2
  sudo apt install -y nuclei || true
  if command -v nuclei >/dev/null 2>&1; then
    echo "[deps] updating nuclei templates" >&2
    nuclei -update-templates || true
  fi
fi

# Go-based tools (recommended for bug bounty stacks)
if [[ "$INSTALL_GO_TOOLS" == "1" ]]; then
  if command -v go >/dev/null 2>&1; then
    echo "[deps] installing go tools (subfinder, assetfinder, naabu)" >&2
    # Ensure GOPATH/bin is in PATH for the current shell
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$PATH:$GOPATH/bin"

    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
    go install -v github.com/tomnomnom/assetfinder@latest || true
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

    echo "[deps] go tools installed to: $GOPATH/bin" >&2
    echo "[deps] add to PATH if needed: export PATH=\"$PATH:$GOPATH/bin\"" >&2
  else
    echo "[deps] go not found; skipping subfinder/assetfinder/naabu via go." >&2
    echo "[deps] Install go: sudo apt install -y golang" >&2
  fi
fi

if [[ "$INSTALL_FARADAY" == "1" ]]; then
  echo "[deps] installing Faraday (optional)" >&2
  # Faraday pulls postgres+redis dependencies
  sudo apt install -y faraday postgresql redis-server || true

  if command -v faraday-manage >/dev/null 2>&1; then
    echo "[deps] initializing faraday DB (idempotent-ish)" >&2
    sudo faraday-manage initdb || true

    echo "[deps] starting services" >&2
    sudo service postgresql start || true
    sudo service redis-server start || true
    sudo service faraday start || sudo service faraday restart || true

    echo "[deps] Faraday should be on http://127.0.0.1:5985" >&2
  else
    echo "[deps] faraday-manage not found (install may have failed)." >&2
  fi
fi

echo "[deps] done. Run: bash dependencies/check_kali.sh" >&2
