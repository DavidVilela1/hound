#!/usr/bin/env sh
# Start only the privileged capture daemon (Linux/macOS) using the project's venv.
# The API/dashboard should already be running as your normal user:  python run.py
#
# Usage: scripts/run_capture.sh <interface> [extra args...]
set -eu
if [ $# -lt 1 ]; then
  echo "usage: $0 <interface> [extra args]   (list interfaces: python run.py interfaces)" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
IFACE="$1"; shift
cd "$ROOT"
if [ "$(id -u)" -eq 0 ]; then
  exec "$PY" run.py capture --interface "$IFACE" "$@"
fi
# Only this process is elevated; the web server keeps running unprivileged.
exec sudo "$PY" run.py capture --interface "$IFACE" "$@"
