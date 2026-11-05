#!/usr/bin/env bash
# Linux only. Installs pinned, checksum-verified binaries from tools.lock.
# Usage: ./install-tools.sh <bin dir> [kubectl trivy kubescape jq ...]   (default: all four)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/tools.lock"
BIN="${1:?usage: install-tools.sh <bin dir> [tool...]}"; shift
[ "$#" -gt 0 ] || set -- kubectl trivy kubescape jq
case "$(uname -m)" in
  x86_64) A=amd64; TA=64bit ;;
  aarch64|arm64) A=arm64; TA=ARM64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$BIN"

# get <url> <expected sha256> <dest>: download, verify, fail closed
get() {
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null 2>&1 || { echo "CHECKSUM MISMATCH for $1" >&2; exit 1; }
}
pin() { local v="$1_$A"; echo "${!v}"; }

for t in "$@"; do
  case "$t" in
    kubectl)   get "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${A}/kubectl" "$(pin KUBECTL_SHA256)" "$tmp/kubectl"
               install -m 0755 "$tmp/kubectl" "$BIN/kubectl" ;;
    trivy)     get "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TA}.tar.gz" "$(pin TRIVY_SHA256)" "$tmp/trivy.tgz"
               tar -xzf "$tmp/trivy.tgz" -C "$tmp" trivy; install -m 0755 "$tmp/trivy" "$BIN/trivy" ;;
    kubescape) get "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${A}" "$(pin KUBESCAPE_SHA256)" "$tmp/kubescape"
               install -m 0755 "$tmp/kubescape" "$BIN/kubescape" ;;
    jq)        get "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${A}" "$(pin JQ_SHA256)" "$tmp/jq"
               install -m 0755 "$tmp/jq" "$BIN/jq" ;;
    *) echo "unknown tool: $t" >&2; exit 1 ;;
  esac
  echo "installed $t"
done
