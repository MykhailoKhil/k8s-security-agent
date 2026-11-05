#!/usr/bin/env bash
# Installs everything the agent needs on macOS or Linux. Safe to re-run.
# macOS (and Linuxbrew): Homebrew, which is NOT version-pinned. Linux: pinned, sha256-verified binaries from tools.lock into ~/.local/bin.
# Python dependencies are always installed from the hash-locked requirements.txt.
set -euo pipefail
cd "$(dirname "$0")"

BIN="$HOME/.local/bin"
export PATH="$BIN:$PATH"
have() { command -v "$1" >/dev/null 2>&1; }

if have brew; then
  for p in kubectl kubescape trivy jq; do have "$p" || brew install "$p"; done
else
  [ "$(uname -s)" = "Linux" ] || { echo "On macOS install Homebrew first: https://brew.sh"; exit 1; }
  have curl || { echo "curl is required"; exit 1; }
  missing=()
  for p in kubectl trivy kubescape jq; do have "$p" || missing+=("$p"); done
  [ "${#missing[@]}" -eq 0 ] || ./install-tools.sh "$BIN" "${missing[@]}"
fi

have python3 || { echo "python3 (3.10+) is required"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q --require-hashes -r requirements.txt
.venv/bin/python test_scan.py && .venv/bin/python test_render.py && .venv/bin/python test_gitutil.py

echo "Installed: $(kubectl version --client 2>/dev/null | head -1), trivy $(trivy --version | head -1), kubescape, jq"
echo "If tools are not found in a new shell, add to PATH: export PATH=\"$BIN:\$PATH\""
echo "Then configure env vars (see .env.example) and run: set -a; . ./.env; set +a; .venv/bin/python agent.py"
