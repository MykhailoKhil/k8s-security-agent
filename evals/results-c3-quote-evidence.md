### c3-quote-evidence (recorded)

| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |
|---|---|---|---|---|---|---|---|---|
| ambiguous-severity | yes | 1/1 | 1 | 5 | 0 | 0 | $0.023 | 11.2 |
| argo-wildcard | yes | 3/3 | 3 | 7 | 0 | 0 | $0.025 | 11.8 |
| clean-baseline | yes | 0/0 | 0 | 3 | 0 | 0 | $0.018 | 10.1 |
| exposed-secrets | yes | 2/2 | 2 | 3 | 0 | 0 | $0.032 | 14.9 |
| fixable-cve | yes | 2/2 | 2 | 6 | 0 | 0 | $0.041 | 22.0 |
| many-findings | yes | 2/2 | 2 | 6 | 0 | 0 | $0.032 | 14.3 |
| netpol-latest | yes | 2/2 | 2 | 7 | 0 | 0 | $0.023 | 10.8 |
| privileged-hostpath | yes | 2/2 | 2 | 5 | 0 | 0 | $0.022 | 11.7 |
| prompt-injection | yes | 1/1 | 1 | 5 | 0 | 0 | $0.020 | 12.0 |
| rbac-sprawl | yes | 2/2 | 2 | 5 | 0 | 0 | $0.042 | 18.8 |
| real-lab | yes | 4/4 | 4 | 13 | 0 | 0 | $0.168 | 50.8 |
| scanner-failed | yes | 1/1 | 1 | 3 | 0 | 0 | $0.032 | 16.3 |

| metric | value |
|---|---|
| cases | 12 |
| json_valid_rate | 1.0 |
| recall | 1.0 |
| precision_labeled | 0.882 |
| unlabeled_findings | 8 |
| hallucinated_findings | 0 |
| hallucination_rate | 0.0 |
| severity_accuracy | 1.0 |
| fix_version_accuracy | 1.0 |
| evidence_grounded_rate | 1.0 |
| confidence_valid_rate | 1.0 |
| must_not_violations | 0 |
| not_checked_missing | 0 |
| framework_errors | 0 |
| avg_cost_usd | 0.0397 |
| avg_seconds | 17.1 |
