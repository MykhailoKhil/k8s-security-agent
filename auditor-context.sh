#!/usr/bin/env bash
# Usage: ./auditor-context.sh <admin-context>...   (re-run to renew the 24h token)
# Applies auditor-rbac.yaml with the admin context, then creates context <ctx>-auditor.
set -euo pipefail
cd "$(dirname "$0")"
for C in "$@"; do
  kubectl --context "$C" apply -f auditor-rbac.yaml
  T=$(kubectl --context "$C" -n security-audit create token auditor --duration 24h)
  kubectl config set-credentials "auditor@$C" --token="$T" >/dev/null
  kubectl config set-context "$C-auditor" --cluster="$C" --user="auditor@$C" >/dev/null
  echo "$C-auditor: delete pods=$(kubectl --context "$C-auditor" auth can-i delete pods -A) get secrets=$(kubectl --context "$C-auditor" auth can-i get secrets -A)"
done
