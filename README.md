# k8s security audit agent

Read-only audit of live clusters and manifest repos (CIS, NSA/CISA, MITRE, Pod Security Standards, image CVEs, secrets, RBAC, Argo CD scope) that produces `findings.json` and a self-contained `report.html`.

## How it works (fast and cheap)
1. **Scan (Python, parallel, ~100 s):** kubescape + trivy + kubectl run at once; output is reduced to a ~15-30 KB digest.
2. **Triage (one LLM call, no tools, ~30 s, about $0.10):** dedupes, ranks, writes fixes as JSON. The model never gets a shell and never sees raw scanner output.
3. **Render (Python):** deterministic, HTML-escaped report.

`TRIVY_SCANNERS=secret,misconfig` skips image CVEs for a run of about 40 s.

## Configure (env vars only; see `.env.example`)
| Var | Meaning |
|---|---|
| `ANTHROPIC_API_KEY` | required (in the container) |
| `K8S_CONTEXTS` | comma list of kubeconfig contexts, use read-only ones |
| `AUDIT_PATHS` / `AUDIT_REPOS` | local dirs / https git URLs (+ `GIT_TOKEN`) with manifests, Kustomize, Helm |
| `OUT_DIR` | default `out` |
| `TRIVY_SCANNERS`, `EFFORT`, `CLAUDE_MODEL`, `SCAN_TIMEOUT` | tuning |

## Run locally
```bash
./setup.sh                      # macOS (brew) or Linux: kubectl, kubescape, trivy, jq, .venv, tests
./auditor-context.sh k3d-workload k3d-mgmt   # read-only ServiceAccount + <ctx>-auditor contexts (24h token)
set -a; . ./.env; set +a
.venv/bin/python agent.py && open out/report.html
```

## Docker
```bash
docker build -t k8s-security-agent .
docker run --rm --env-file .env -e K8S_CONTEXTS=ctx -e KUBECONFIG=/kube/config \
  -v ~/.kube/config:/kube/config:ro -v "$PWD/out:/out" k8s-security-agent
```
The image runs as non-root, with kubectl, trivy and kubescape pinned by build args.

## Helm (scheduled in a cluster)
```bash
kubectl create secret generic anthropic-api-key --from-literal=api-key=...
kubectl create secret generic audit-kubeconfig --from-file=config=./auditor-kubeconfig
helm install audit chart/k8s-security-agent \
  --set env.K8S_CONTEXTS=k3d-workload-auditor --set kubeconfigSecret.name=audit-kubeconfig \
  --set persistence.enabled=true
```
The chart creates no credentials and mounts no ServiceAccount token. The pod is non-root, read-only root FS, all caps dropped.

## Safety
- Cluster access is whatever the kubeconfig allows: use `auditor-rbac.yaml` (view + a few read rules, **no Secrets**).
- Scanner commands are fixed in `scan.py` (no model-written shell), trivy runs with `--disable-node-collector`, and the LLM call has no tools.
- Not covered: node/control-plane CIS checks (need a privileged pod), secrets in git history.

## Tests
`python test_scan.py && python test_render.py`
