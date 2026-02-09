#!/usr/bin/env bash
set -euo pipefail

# Starts Faraday on environments where the distro-provided `faraday` wrapper
# (which relies on systemd + sudo) may not work, e.g. constrained WSL/container.
#
# Usage:
#   src/bin/faraday-start.sh [--bind 127.0.0.1] [--port 5985]

BIND_ADDRESS="127.0.0.1"
PORT="5985"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bind)
      BIND_ADDRESS="${2:-}"; shift 2 ;;
    --port)
      PORT="${2:-}"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--bind 127.0.0.1] [--port 5985]" >&2
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

URL="http://${BIND_ADDRESS}:${PORT}"

if [[ ! -d "${HOME}/.faraday" ]]; then
  mkdir -p "${HOME}/.faraday"/{logs,storage,uploaded_reports,session,config} 2>/dev/null || true
fi

# The packaged Faraday expects Postgres. If DB doesn't exist, init it.
# This may require sudo/root (to become postgres). If sudo isn't usable, we emit guidance.
if command -v sudo >/dev/null 2>&1; then
  if sudo -n true >/dev/null 2>&1; then
    if ! sudo -u postgres -- psql -lqt 2>/dev/null | cut -d '|' -f 1 | tr -d ' ' | grep -qx "faraday"; then
      echo ">>> Init database (faraday)" >&2
      sudo faraday-manage initdb >/dev/null
    fi
  else
    echo ">>> Warning: sudo needs a password or is blocked; skipping initdb check." >&2
    echo ">>> If this is a first run, execute: sudo faraday-manage initdb" >&2
  fi
else
  echo ">>> Warning: sudo not found; skipping initdb check." >&2
fi

echo ">>> Starting faraday-server at ${URL}" >&2
exec faraday-server --bind_address "${BIND_ADDRESS}" --port "${PORT}"

