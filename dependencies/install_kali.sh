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

have_sudo() {
  # Some environments block sudo with "no new privileges"; detect early.
  command -v sudo >/dev/null 2>&1 || return 1
  sudo -n true >/dev/null 2>&1
}

SUDO=""
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
elif have_sudo; then
  SUDO="sudo"
else
  echo "[deps] WARN: sudo is not usable; falling back to user-local installs where possible." >&2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="$REPO_ROOT/.tools"
TOOLS_BIN="$TOOLS_DIR/bin"
TOOLS_GOPATH="$TOOLS_DIR/gopath"
mkdir -p "$TOOLS_BIN" "$TOOLS_GOPATH/bin"

# Make repo-local tool installs discoverable for this process.
export PATH="$TOOLS_BIN:$TOOLS_GOPATH/bin:$PATH"

FALLBACK_LOCAL="0"
if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
  FALLBACK_LOCAL="1"
fi

user_home() {
  # If the script is executed as root (or via sudo), try to target the original user's home.
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    getent passwd "$SUDO_USER" | cut -d: -f6
    return
  fi
  printf "%s" "${HOME}"
}

can_write_path() {
  local p="$1"
  if [[ -e "$p" ]]; then
    [[ -w "$p" ]]
  else
    [[ -w "$(dirname "$p")" ]]
  fi
}

ensure_local_bin_on_path() {
  local home_dir bashrc profile target_file line
  home_dir="$(user_home)"
  bashrc="$home_dir/.bashrc"
  profile="$home_dir/.profile"
  target_file="$profile"
  if [[ ! -f "$profile" && -f "$bashrc" ]]; then
    target_file="$bashrc"
  fi

  mkdir -p "$home_dir/.local/bin"
  case ":$PATH:" in
    *":$home_dir/.local/bin:"*) : ;;
    *) export PATH="$PATH:$home_dir/.local/bin" ;;
  esac

  line='export PATH="$PATH:$HOME/.local/bin"'
  if can_write_path "$target_file" && [[ -f "$target_file" ]]; then
    if ! grep -Fqs "$line" "$target_file"; then
      {
        echo ""
        echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
        echo "$line"
      } >>"$target_file"
      echo "[deps] Added ~/.local/bin to PATH in: $target_file" >&2
    fi
  elif can_write_path "$profile"; then
    {
      echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
      echo "$line"
    } >"$profile"
    echo "[deps] Created and updated: $profile" >&2
  else
    echo "[deps] NOTE: cannot write to $target_file; add this to your shell profile manually:" >&2
    echo "  $line" >&2
  fi
}

install_jq_userlocal() {
  local arch url dest
  ensure_local_bin_on_path

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) url="https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64" ;;
    aarch64|arm64) url="https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-arm64" ;;
    *)
      echo "[deps] ERROR: unsupported arch for user-local jq install: $arch" >&2
      return 1
      ;;
  esac

  # Prefer repo-local install location if sudo isn't usable (e.g. sandbox/container).
  if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
    dest="$TOOLS_BIN/jq"
  else
    dest="$(user_home)/.local/bin/jq"
  fi
  echo "[deps] installing jq to $dest" >&2
  curl -fsSL "$url" -o "$dest"
  chmod +x "$dest"
}

install_go_userlocal() {
  local home_dir ver arch os tarball url dest_root bashrc profile target_file line
  home_dir="$(user_home)"
  ensure_local_bin_on_path

  ver="$(curl -fsSL https://go.dev/VERSION?m=text | head -n1)"
  os="linux"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) tarball="${ver}.${os}-amd64.tar.gz" ;;
    aarch64|arm64) tarball="${ver}.${os}-arm64.tar.gz" ;;
    *)
      echo "[deps] ERROR: unsupported arch for user-local go install: $arch" >&2
      return 1
      ;;
  esac

  url="https://go.dev/dl/${tarball}"
  if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
    dest_root="$TOOLS_DIR"
  else
    dest_root="$home_dir/.local"
  fi
  echo "[deps] installing go ($ver) user-local under $dest_root/go" >&2
  rm -rf "$dest_root/go"
  mkdir -p "$dest_root"
  curl -fsSL "$url" -o /tmp/go.tgz
  tar -C "$dest_root" -xzf /tmp/go.tgz

  bashrc="$home_dir/.bashrc"
  profile="$home_dir/.profile"
  target_file="$profile"
  if [[ ! -f "$profile" && -f "$bashrc" ]]; then
    target_file="$bashrc"
  fi

  line='export PATH="$PATH:$HOME/.local/go/bin"'
  if can_write_path "$target_file" && [[ -f "$target_file" ]] && ! grep -Fqs "$line" "$target_file"; then
    {
      echo ""
      echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
      echo "$line"
    } >>"$target_file"
    echo "[deps] Added user-local go bin to PATH in: $target_file" >&2
  elif ! can_write_path "$target_file"; then
    echo "[deps] NOTE: cannot write to $target_file; add this to your shell profile manually:" >&2
    if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
      echo "  export PATH=\"\$PATH:$TOOLS_DIR/go/bin\"" >&2
    else
      echo "  $line" >&2
    fi
  fi

  if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
    export PATH="$PATH:$TOOLS_DIR/go/bin"
  else
    export PATH="$PATH:$home_dir/.local/go/bin"
  fi
}

ensure_gopath_on_path() {
  local home_dir gopath gopath_bin bashrc profile
  home_dir="$(user_home)"
  if [[ "$FALLBACK_LOCAL" == "1" ]]; then
    # Avoid inheriting a pre-set GOPATH pointing outside writable areas.
    gopath="$TOOLS_GOPATH"
  else
    gopath="${GOPATH:-$home_dir/go}"
  fi
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
  elif can_write_path "$profile"; then
    # If neither exists, create .profile.
    {
      echo "# Added by /mnt/c/dev/bug dependencies/install_kali.sh"
      echo "$line_gopath"
      echo "$line_path"
    } >"$profile"
    echo "[deps] Created and updated: $profile" >&2
  else
    echo "[deps] NOTE: cannot write to shell profiles; add these lines manually:" >&2
    if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
      echo "  export GOPATH=\"${GOPATH:-$TOOLS_GOPATH}\"" >&2
      echo "  export PATH=\"\$PATH:${GOPATH:-$TOOLS_GOPATH}/bin\"" >&2
    else
      echo "  $line_gopath" >&2
      echo "  $line_path" >&2
    fi
  fi

  echo "[deps] GOPATH is: $GOPATH" >&2
  echo "[deps] Go tools will be installed to: $GOPATH/bin" >&2
  echo "[deps] If a new shell still can't find tools, run: source \"$target_file\"" >&2
}

go_install_or_die() {
  local pkg="$1"
  local hint="$2"
  # In some environments, Go's pure resolver/proxy DNS lookups can be blocked.
  # Force cgo resolver and avoid the public module proxy to reduce DNS/UDP dependence.
  if ! env GODEBUG=netdns=cgo GOPROXY=direct GOSUMDB=off go install -v "$pkg"; then
    echo "[deps] ERROR: go install failed for: $pkg" >&2
    echo "[deps] Common fixes:" >&2
    echo "  - Verify go works: go version" >&2
    echo "  - Ensure network access to VCS host (github.com) and DNS is working" >&2
    echo "  - Try manually: env GOPROXY=direct GOSUMDB=off GODEBUG=netdns=cgo go install -v \"$pkg\"" >&2
    echo "  - Ensure PATH includes GOPATH/bin (see notes above)" >&2
    if [[ -n "$hint" ]]; then
      echo "  - Hint: $hint" >&2
    fi
    exit 1
  fi
}

echo "[deps] apt update" >&2
if [[ -n "$SUDO" ]]; then
  $SUDO apt update
else
  echo "[deps] skipping apt update (no sudo available)" >&2
fi

echo "[deps] installing base packages" >&2
if [[ -n "$SUDO" ]]; then
  $SUDO apt install -y \
    ca-certificates \
    curl \
    jq \
    git \
    dnsutils \
    nmap sslscan whatweb \
    python3 python3-venv python3-pip \
    coreutils \
    wkhtmltopdf \
    fonts-dejavu-core \
    fonts-liberation # coreutils provides the `timeout` binary; wkhtmltopdf generates PDF reports
else
  echo "[deps] skipping apt base package install (no sudo available)" >&2
  command -v curl >/dev/null 2>&1 || { echo "[deps] ERROR: curl is required but missing." >&2; exit 1; }
  if ! command -v jq >/dev/null 2>&1; then
    install_jq_userlocal
  fi
fi

# httpx is often from apt in Kali; if not available, user can install via go.
if ! command -v httpx >/dev/null 2>&1; then
  echo "[deps] httpx not found after apt; will try to install via go (if enabled)." >&2
fi

echo "[deps] installing recon/enum packages" >&2
if [[ -n "$SUDO" ]]; then
  $SUDO apt install -y \
    amass \
    ffuf \
    seclists
else
  echo "[deps] skipping apt recon/enum packages install (no sudo available)" >&2
fi

if [[ "$INSTALL_NUCLEI" == "1" ]]; then
  echo "[deps] installing nuclei" >&2
  if [[ -n "$SUDO" ]]; then
    $SUDO apt install -y nuclei
  else
    echo "[deps] skipping nuclei install (no sudo available)" >&2
  fi
  if command -v nuclei >/dev/null 2>&1; then
    echo "[deps] updating nuclei templates" >&2
    nuclei -update-templates || true
  fi
fi

# Go-based tools (recommended for bug bounty stacks)
if [[ "$INSTALL_GO_TOOLS" == "1" ]]; then
  echo "[deps] ensuring golang is installed (INSTALL_GO_TOOLS=1)" >&2
  if ! command -v go >/dev/null 2>&1; then
    if [[ -n "$SUDO" ]]; then
      $SUDO apt install -y golang
    else
      install_go_userlocal
    fi
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
  if [[ -n "$SUDO" ]]; then
    $SUDO apt install -y faraday postgresql redis-server
  else
    echo "[deps] ERROR: Faraday install requires sudo/apt. Re-run on Kali/WSL with sudo, or set INSTALL_FARADAY=0." >&2
    exit 1
  fi

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
