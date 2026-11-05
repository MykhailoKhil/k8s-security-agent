# k8s security audit agent

Read-only audit of live clusters and manifest repos. Produces `report.html` (open it in a browser) and `findings.json`.

**Checks:** CIS, NSA/CISA and MITRE (kubescape), Pod Security Standards, image CVEs, secrets and misconfigurations (trivy), cluster-admin / wildcard RBAC bindings, Argo CD project scope.
**Run time and cost:** about 130 s and $0.10 per run for one cluster plus two repos.

## How it works
1. **Scan** (`scan.py`, Python, parallel, ~100 s): kubescape, trivy and kubectl run at once; their output is reduced to a ~15-30 KB digest.
2. **Triage** (`agent.py`, one LLM call, no tools, ~30 s): dedupes, ranks and writes fixes as JSON. The model gets no shell and never sees raw scanner output.
3. **Render** (`render.py`): deterministic, HTML-escaped report.

`TRIVY_SCANNERS=secret,misconfig` skips image CVEs for a faster run.

## Quick start
```bash
./setup.sh                                   # macOS (brew) or Linux: kubectl, kubescape, trivy, jq, .venv, tests
./auditor-context.sh k3d-workload k3d-mgmt   # read-only identity + <ctx>-auditor contexts (24 h token)
cp .env.example .env                         # edit contexts / paths
set -a; . ./.env; set +a
.venv/bin/python agent.py && open out/report.html
```
`auditor-context.sh` needs admin on the target cluster once; re-run it to renew the 24 h token.

## Configuration (env vars only, no CLI flags)
See `.env.example` for every variable. Main ones: `K8S_CONTEXTS`, `AUDIT_PATHS`, `AUDIT_REPOS` (+ `GIT_TOKEN`), `OUT_DIR`, `ANTHROPIC_API_KEY`.

## Output files (`OUT_DIR`)
| File | What |
|---|---|
| `report.html` | the report |
| `findings.json` | structured findings, frameworks, "not checked" |
| `digest.json` | what the model saw (use it to audit the model's claims) |
| `ks-*.json`, `trivy*.json`, `pss-*.json` | raw scanner output |

## Docker
```bash
docker build -t k8s-security-agent .
docker run --rm --env-file .env -e OUT_DIR=/out -e KUBECONFIG=/kube/config \
  -v ~/.kube/config:/kube/config:ro -v "$PWD/out:/out" k8s-security-agent
```
Non-root image; kubectl, trivy and kubescape versions are build args. Inside a container a local k3d API server at `0.0.0.0:<port>` is not reachable; use a kubeconfig whose server is `host.docker.internal` (not tested here).

## Helm (scheduled run in a cluster)
Push the image somewhere the cluster can pull from (or `k3d image import k8s-security-agent:dev -c <cluster>`), then:
```bash
kubectl create secret generic anthropic-api-key --from-literal=api-key=...
kubectl create secret generic audit-kubeconfig --from-file=config=./auditor-kubeconfig
helm install audit chart/k8s-security-agent \
  --set image.repository=<registry>/k8s-security-agent \
  --set env.K8S_CONTEXTS=<context> --set kubeconfigSecret.name=audit-kubeconfig \
  --set persistence.enabled=true
```
Weekly CronJob by default (`schedule`). The chart creates no credentials and mounts no ServiceAccount token; the pod is non-root with a read-only root filesystem and all capabilities dropped. Not deployed or tested in a cluster yet (only `helm lint`).

## Safety
- Cluster access is whatever the kubeconfig allows. Use `auditor-rbac.yaml`: built-in `view` plus a few read rules, **no Secrets, no write verbs**.
- Scanner commands are fixed in `scan.py` (no model-written shell); trivy runs with `--disable-node-collector`; the LLM call has no tools.
- Findings are LLM-written from the digest. Treat `digest.json` and the raw scanner files as the source of truth.

## Not covered
Node and control-plane CIS checks (need a privileged pod, so the read-only identity skips them), and secrets in git history. Both are listed under "Not checked" in every report.

## Troubleshooting
| Symptom | Fix |
|---|---|
| `connection refused` to the cluster | start Docker, then `k3d cluster start <name>` |
| `Unauthorized` / expired | re-run `./auditor-context.sh <ctx>` (24 h token) |
| a scanner shows under "Not checked" | open `digest.json` for its error line |
| `model did not return JSON` | see `llm-raw.txt` in `OUT_DIR`, re-run (try `EFFORT=medium`) |
| `framework not found` | `kubescape list frameworks`, update `KS_FRAMEWORKS` in `scan.py` |

## Files
`agent.py` entrypoint, `scan.py` scanners and reducers, `render.py` HTML, `auditor-rbac.yaml` + `auditor-context.sh` read-only identity, `Dockerfile`, `chart/` Helm chart, `test_*.py` tests (`python test_scan.py && python test_render.py`).
