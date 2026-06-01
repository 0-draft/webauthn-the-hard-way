#!/usr/bin/env bash
# Bring up the WebAuthn Relying Party on http://localhost:5000.
#
# Creates a venv on first run, installs the two deps (flask, cryptography),
# starts the Flask app, and opens a browser tab.
#
# Re-running just re-launches the server using the existing venv.

set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"

if [[ ! -d "$VENV" ]]; then
  echo "[run.sh] creating venv at $VENV"
  python3 -m venv "$VENV"
fi

# shellcheck source=/dev/null
source "$VENV/bin/activate"

if ! python -c "import flask, cryptography" 2>/dev/null; then
  echo "[run.sh] installing dependencies"
  pip install --upgrade pip >/dev/null
  pip install "flask>=3.0" "cryptography>=42.0" >/dev/null
fi

if [[ "${OPEN_BROWSER:-1}" == "1" ]]; then
  ( sleep 1 && command -v open >/dev/null && open http://localhost:5000 ) &
fi

echo "[run.sh] starting Flask on http://localhost:5000"
echo "[run.sh] open the page, click Register, then Authenticate."
echo "[run.sh] Ctrl-C to stop."

exec python -m server.app
