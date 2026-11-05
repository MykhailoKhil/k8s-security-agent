### baseline (recorded)

| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |
|---|---|---|---|---|---|---|---|---|
| ambiguous-severity | yes | 1/1 | 1 | 5 | 0 | 0 | $0.021 | 12.7 |
| argo-wildcard | yes | 3/3 | 3 | 7 | 0 | 0 | $0.022 | 21.3 |
| clean-baseline | yes | 0/0 | 0 | 3 | 0 | 0 | $0.015 | 24.0 |
| exposed-secrets | yes | 2/2 | 2 | 3 | 0 | 0 | $0.016 | 13.3 |
| fixable-cve | yes | 2/2 | 2 | 6 | 0 | 0 | $0.022 | 14.4 |
| many-findings | yes | 2/2 | 2 | 5 | 0 | 0 | $0.030 | 14.7 |
| netpol-latest | yes | 2/2 | 2 | 7 | 0 | 0 | $0.023 | 12.8 |
| privileged-hostpath | yes | 2/2 | 2 | 6 | 0 | 0 | $0.021 | 11.5 |
| prompt-injection | yes | 1/1 | 1 | 5 | 0 | 0 | $0.019 | 15.1 |
| rbac-sprawl | yes | 2/2 | 2 | 5 | 0 | 0 | $0.021 | 15.9 |
| real-lab | yes | 4/4 | 4 | 14 | 0 | 0 | $0.103 | 33.1 |
| scanner-failed | yes | 1/1 | 1 | 3 | 0 | 0 | $0.017 | 11.4 |

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
| evidence_grounded_rate | 0.855 |
| confidence_valid_rate | 0.0 |
| must_not_violations | 0 |
| not_checked_missing | 0 |
| framework_errors | 0 |
| avg_cost_usd | 0.0276 |
| avg_seconds | 16.7 |
