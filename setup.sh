#!/usr/bin/env bash
# Installs everything the agent needs on macOS or Linux. Safe to re-run.
# Uses Homebrew when present (mac, or Linuxbrew); otherwise installs binaries into ~/.local/bin.
set -euo pipefail
cd "$(dirname "$0")"

BIN="$HOME/.local/bin"
export PATH="$BIN:$HOME/.kubescape/bin:$PATH"
have() { command -v "$1" >/dev/null 2>&1; }

if have brew; then
  for p in kubectl kubescape trivy jq; do have "$p" || brew install "$p"; done
else
  [ "$(uname -s)" = "Linux" ] || { echo "On macOS install Homebrew first: https://brew.sh"; exit 1; }
  mkdir -p "$BIN"
  case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported arch $(uname -m)"; exit 1 ;; esac
  have curl || { echo "curl is required"; exit 1; }

  if ! have kubectl; then
    v=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
    curl -fsSL -o "$BIN/kubectl" "https://dl.k8s.io/release/$v/bin/linux/$ARCH/kubectl"
    # verify against the published checksum before making it executable
    echo "$(curl -fsSL "https://dl.k8s.io/release/$v/bin/linux/$ARCH/kubectl.sha256")  $BIN/kubectl" | sha256sum -c -
    chmod +x "$BIN/kubectl"
  fi
  have trivy    || curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN"
  have kubescape || curl -fsSL https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
  if ! have jq; then
    curl -fsSL -o "$BIN/jq" "https://github.com/jqlang/jq/releases/latest/download/jq-linux-$ARCH"
    chmod +x "$BIN/jq"
  fi
fi

have python3 || { echo "python3 (3.10+) is required"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python test_scan.py && .venv/bin/python test_render.py

echo "Installed: $(kubectl version --client 2>/dev/null | head -1), trivy $(trivy --version | head -1), kubescape, jq"
echo "If tools are not found in a new shell, add to PATH: export PATH=\"$BIN:\$HOME/.kubescape/bin:\$PATH\""
echo "Then set ANTHROPIC_API_KEY and run: .venv/bin/python agent.py --context <ctx> --manifests <dir>"
