#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash dependencies/install_kali.sh
# Optional env:
#   INSTALL_FARADAY=0   # skip faraday
#   INSTALL_NUCLEI=1    # install nuclei (default 1)
#   INSTALL_GO_TOOLS=1  # install subfinder/assetfinder/naabu via go (default 1)

INSTALL_FARADAY="${INSTALL_FARADAY:-0}"
INSTALL_NUCLEI="${INSTALL_NUCLEI:-1}"
INSTALL_GO_TOOLS="${INSTALL_GO_TOOLS:-1}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[deps] This script uses apt and needs sudo." >&2
fi

user_home() {
  # If the script is executed as root (or via sudo), try to target the original user's home.
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    getent passwd "$SUDO_USER" | cut -d: -f6
    return
  fi
  printf "%s" "${HOME}"
}

ensure_gopath_on_path() {
  local home_dir gopath gopath_bin bashrc profile
  home_dir="$(user_home)"
  gopath="${GOPATH:-$home_dir/go}"
  gopath_bin="$gopath/bin"
  bashrc="$home_dir/.bashrc"
  profile="$home_dir/.profile"

  export GOPATH="$gopath"
  case ":$PATH:" in
    *":$gopath_bin:"*) : ;;
    *)
      export PATH="$PATH:$gopath_bin"
      ;;
  esac

  # Persist for future shells (idempotent).
  # We avoid complex shell detection; .profile is generally loaded for login shells, .bashrc for interactive bash.
  local line_gopath line_path target_file
  line_gopath='export GOPATH="${GOPATH:-$HOME/go}"'
  line_path='export PATH="$PATH:$GOPATH/bin"'

  target_file="$profile"
  if [[ ! -f "$profile" && -f "$bashrc" ]]; then
    target_file="$bashrc"
  fi

  if [[ -f "$target_file" ]]; then
    if ! grep -Fqs "$line_path" "$target_file"; then
      {
        echo ""
        echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
        echo "$line_gopath"
        echo "$line_path"
      } >>"$target_file"
      echo "[deps] Added GOPATH/PATH exports to: $target_file" >&2
    fi
  else
    # If neither exists, create .profile.
    {
      echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
      echo "$line_gopath"
      echo "$line_path"
    } >"$profile"
    echo "[deps] Created and updated: $profile" >&2
  fi

  echo "[deps] GOPATH is: $GOPATH" >&2
  echo "[deps] Go tools will be installed to: $GOPATH/bin" >&2
  echo "[deps] If a new shell still can't find tools, run: source \"$target_file\"" >&2
}

go_install_or_die() {
  local pkg="$1"
  local hint="$2"
  if ! go install -v "$pkg"; then
    echo "[deps] ERROR: go install failed for: $pkg" >&2
    echo "[deps] Common fixes:" >&2
    echo "  - Verify go works: go version" >&2
    echo "  - Ensure network access to proxy/VCS (or set GOPROXY=direct)" >&2
    echo "  - Ensure PATH includes GOPATH/bin (see notes above)" >&2
    if [[ -n "$hint" ]]; then
      echo "  - Hint: $hint" >&2
    fi
    exit 1
  fi
}

echo "[deps] apt update" >&2
sudo apt update

echo "[deps] installing base packages" >&2
sudo apt install -y \
  ca-certificates \
  curl \
  jq \
  git \
  dnsutils \
  nmap sslscan whatweb \
  python3 python3-venv python3-pip \
  coreutils # provides the `timeout` binary; there is no `timeout` apt package on Kali

# httpx is often from apt in Kali; if not available, user can install via go.
if ! command -v httpx >/dev/null 2>&1; then
  echo "[deps] httpx not found after apt; will try to install via go (if enabled)." >&2
fi

echo "[deps] installing recon/enum packages" >&2
sudo apt install -y \
  amass \
  ffuf \
  seclists

if [[ "$INSTALL_NUCLEI" == "1" ]]; then
  echo "[deps] installing nuclei" >&2
  sudo apt install -y nuclei
  if command -v nuclei >/dev/null 2>&1; then
    echo "[deps] updating nuclei templates" >&2
    nuclei -update-templates || true
  fi
fi

# Go-based tools (recommended for bug bounty stacks)
if [[ "$INSTALL_GO_TOOLS" == "1" ]]; then
  echo "[deps] ensuring golang is installed (INSTALL_GO_TOOLS=1)" >&2
  if ! command -v go >/dev/null 2>&1; then
    sudo apt install -y golang
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo "[deps] ERROR: go still not found after installing golang." >&2
    exit 1
  fi

  ensure_gopath_on_path

  echo "[deps] installing go tools (subfinder, assetfinder, naabu)" >&2
  go_install_or_die "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ""
  go_install_or_die "github.com/tomnomnom/assetfinder@latest" ""
  go_install_or_die "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" ""

  if ! command -v httpx >/dev/null 2>&1; then
    echo "[deps] installing httpx via go" >&2
    go_install_or_die "github.com/projectdiscovery/httpx/cmd/httpx@latest" ""
  fi
fi

if [[ "$INSTALL_FARADAY" == "1" ]]; then
  echo "[deps] installing Faraday (optional)" >&2
  # Faraday pulls postgres+redis dependencies
  sudo apt install -y faraday postgresql redis-server

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
