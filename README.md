# k8s security audit agent

Read-only audit of live clusters and manifest repos. Produces `report.html` (open it in a browser) and `findings.json`.

**Checks:** CIS, NSA/CISA and MITRE (kubescape), Pod Security Standards, image CVEs, secrets and misconfigurations (trivy), cluster-admin / wildcard RBAC bindings, Argo CD project scope.
**Run time and cost:** about 130 s and $0.10 per run for one cluster plus two repos.

## How it works
1. **Scan** (`scan.py`, Python, parallel, ~100 s): kubescape, trivy and kubectl run at once; their output is reduced to a ~15-30 KB digest.
2. **Triage** (`agent.py`, one LLM call, no tools, ~30 s): dedupes, ranks and writes fixes as JSON. The model gets no shell and never sees raw scanner output.
3. **Render** (`render.py`): deterministic, HTML-escaped report. Run cost and time are added by code (`meta`) and shown in the report header.

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

## Evals (triage quality)
`evals/fixtures/<case>/` holds a `digest.json` (the exact input the model sees), an `expected.json` (what a correct triage must include, severity ranges, what it must not claim) and a `recorded.json` (a saved model reply). 12 cases: privileged pod + hostPath, RBAC sprawl, missing NetworkPolicy and `:latest`, committed secrets, fixable CVEs, Argo CD wildcard scope, a clean cluster, a real digest from the lab, and four adversarial ones (prompt injection in scanner text, a failed scanner, 40+ failed controls, expected-vs-real host access).

```bash
python test_evals.py                                  # offline: metric logic, fixture sanity, mutation tests, replay of recorded replies
EVAL_MODE=live EVAL_RECORD=1 EVAL_RECORD_AS=recorded-mine EVAL_LABEL=mine .venv/bin/python evals/run_evals.py   # calls the API (~$0.2-0.5 for all 12)
EVAL_REPLAY=recorded-baseline EVAL_LABEL=baseline .venv/bin/python evals/run_evals.py   # re-score any saved recording offline
EVAL_CASES=real-lab,fixable-cve EVAL_OUT=evals/results-x .venv/bin/python evals/run_evals.py   # subset; EVAL_MODE defaults to recorded (offline)
```

**Metrics** (`evals/metrics.py`): *recall* = expected findings found; *severity accuracy* = found items whose severity is in the expected range; *precision (labeled)* = findings that match an expected or acceptable item; *hallucination* = a finding citing a control/CVE ID, version, `Kind/name` resource, hyphenated resource name or number >= 10 that does not occur in `digest.json`; *must-not violations* = severity ceilings (for example the k3s default `system:masters` binding above MEDIUM), banned claims ("cluster is secure", "no vulnerabilities") and invented fix versions; plus JSON validity against the schema, kept `not_checked` entries, framework numbers copied exactly, cost and latency.

**Baseline (the Phase 1 prompt, Sonnet 5.5, effort low; 12 cases, live replies recorded 2026-11-05):**

| metric | value |
|---|---|
| JSON valid | 12/12 |
| recall | 1.0 (22/22 expected findings) |
| severity accuracy | 1.0 |
| fix-version accuracy | 1.0 |
| hallucinated findings | 0 of 69 |
| must-not violations | 0 |
| evidence grounded | 0.99 (1 of 69 findings quotes no digest identifier) |
| confidence field | absent (0.0) |
| framework number errors | 0 |
| precision (labeled) | 0.91: 63 of 69 findings match a label; the other 6 are legitimate (non-root MEDIUM, roll-ups of 40 controls, node-exporter/svclb rated MEDIUM as expected) and were left unlabeled |
| cost / latency per case | $0.028 / 17 s (real-lab: $0.10 / 33 s) |

### Phase 2: triage prompt changelog
One change at a time, each re-run live on all 12 cases (replies saved as `recorded-<label>.json`, re-scored offline with the final scorer; `recorded.json` is the latest accepted run).

| change | valid | recall | precision | halluc | evidence grounded | confidence | must-not | avg cost | avg time |
|---|---|---|---|---|---|---|---|---|---|
| baseline (Phase 1 prompt) | 1.0 | 1.0 | 0.913 | 0 | 0.986 | 0.0 | 0 | $0.0276 | 16.7s |
| 1. schema-enforced output (`output_format` JSON schema) | 1.0 | 1.0 | 0.913 | 0 | 0.971 | 0.0 | 0 | $0.0227 | 14.7s |
| 2. required `confidence` high/medium/low + rubric in the prompt | 1.0 | 1.0 | 0.913 | 0 | 1.0 | 1.0 | 0 | $0.0306 | 19.5s |
| 3. evidence must quote digest identifiers | 1.0 | 1.0 | 0.882 | 0 | 1.0 | 1.0 | 0 | $0.0397 | 17.1s |
| 3, second run (same prompt, noise check) | 1.0 | 1.0 | 0.881 | 0 | 1.0 | 1.0 | 0 | $0.0179 | 12.7s |

What changed and what it means:
- **Change 1** guarantees the reply matches the schema (before, it was a free-text JSON that happened to parse). No quality delta; the structured-output call sometimes takes a 2nd or 3rd turn, so `max_turns` is 3.
- **Change 2** adds a per-finding `confidence` (36 high, 24 medium, 8 low over 68 findings in the final run) and shows it in the report. The rubric: high = shown directly by the digest, medium = inferred from context, low = partial data or a failed scanner.
- **Change 3** is the requested "quote identifiers" rule. **The evals cannot show it helps:** grounding was already 0.99 before it and 1.0 after change 2, and precision moved 0.913 -> 0.882, which is one extra finding the labels do not cover. I kept it because you asked for it and it did no measurable harm, not because it measured better.
- **Cost is noise-level, not a trend:** the identical prompt cost $0.040 and $0.018 per case in two runs. The cause is how many turns the structured-output call takes (2 vs 3, recorded as `turns` in each reply), which varies per call. Compare cost only across many runs.
- **Scorer changes made during Phase 2** (all recordings re-scored with the final version): injection bans apply to titles and the summary, so reporting the attack in evidence is not penalised; digit-only ranges like `12-13` are not names; the grounding check accepts versions, package paths (`github.com/org/pkg`), `N SEVERITY` counts that match the digest, and quoted digest field names. The first versions of these checks produced false positives and false negatives; the table above uses the final one throughout.
- The suite is still saturated on quality (recall 1.0, 0 hallucinations, 0 violations), so Phase 2 improvements show up only in the new structural properties (schema, confidence, grounding), not in triage accuracy.

How to read this honestly:
- **The suite is saturated.** The current prompt scores 1.0 on everything, so these numbers show no headroom for Phase 2: they protect against regressions, they cannot yet show an improvement.
- **Labels were adjusted after the first run:** I added the `acceptable` roll-ups (k3s default binding, medium CVE summaries, small misconfigs) after reading the first 8 cases' output, and fixed the hallucination detector's false positives (slashes in prose, ID lists, PSS counts). Raw first-pass numbers were 37% hallucinated, all of which were detector noise. The 4 hard cases were not relabeled.
- **Detector limits:** names without a hyphen or a `Kind/` prefix, and counts the model derives by adding digest numbers, are not checked. Fixtures are hand-written in the digest shape; only `real-lab` is a real scan.
- `evals/results-baseline.{json,md}` hold the per-case detail; table mode says "recorded" because the numbers are re-scored from the saved live replies.

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
`agent.py` entrypoint, `triage.py` the LLM call, `scan.py` scanners and reducers, `evals/` triage evals, `render.py` HTML, `auditor-rbac.yaml` + `auditor-context.sh` read-only identity, `Dockerfile`, `chart/` Helm chart, `test_*.py` tests (`python test_scan.py && python test_render.py && python test_evals.py`).
