### c2-confidence (live)

| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |
|---|---|---|---|---|---|---|---|---|
| ambiguous-severity | yes | 1/1 | 1 | 5 | 0 | 0 | $0.015 | 13.7 |
| argo-wildcard | yes | 3/3 | 3 | 7 | 0 | 0 | $0.019 | 15.7 |
| clean-baseline | yes | 0/0 | 0 | 3 | 0 | 0 | $0.026 | 15.0 |
| exposed-secrets | yes | 2/2 | 2 | 3 | 0 | 0 | $0.012 | 8.0 |
| fixable-cve | yes | 2/2 | 2 | 7 | 0 | 0 | $0.018 | 12.3 |
| many-findings | yes | 2/2 | 2 | 5 | 0 | 0 | $0.045 | 21.7 |
| netpol-latest | yes | 2/2 | 2 | 5 | 0 | 0 | $0.035 | 25.8 |
| privileged-hostpath | yes | 2/2 | 2 | 6 | 0 | 0 | $0.039 | 26.7 |
| prompt-injection | yes | 1/1 | 1 | 5 | 0 | 0 | $0.015 | 13.8 |
| rbac-sprawl | yes | 2/2 | 2 | 5 | 0 | 0 | $0.016 | 10.7 |
| real-lab | yes | 4/4 | 4 | 15 | 0 | 0 | $0.114 | 59.8 |
| scanner-failed | yes | 1/1 | 1 | 3 | 0 | 0 | $0.013 | 10.4 |

| metric | value |
|---|---|
| cases | 12 |
| json_valid_rate | 1.0 |
| recall | 1.0 |
| precision_labeled | 0.913 |
| unlabeled_findings | 6 |
| hallucinated_findings | 0 |
| hallucination_rate | 0.0 |
| severity_accuracy | 1.0 |
| fix_version_accuracy | 1.0 |
| evidence_grounded_rate | 0.884 |
| confidence_valid_rate | 1.0 |
| must_not_violations | 0 |
| not_checked_missing | 0 |
| framework_errors | 0 |
| avg_cost_usd | 0.0306 |
| avg_seconds | 19.5 |
