### c3-repeat (recorded)

| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |
|---|---|---|---|---|---|---|---|---|
| ambiguous-severity | yes | 1/1 | 1 | 5 | 0 | 0 | $0.020 | 15.9 |
| argo-wildcard | yes | 3/3 | 3 | 7 | 0 | 0 | $0.019 | 12.4 |
| clean-baseline | yes | 0/0 | 0 | 3 | 0 | 0 | $0.011 | 8.5 |
| exposed-secrets | yes | 2/2 | 2 | 3 | 0 | 0 | $0.012 | 8.3 |
| fixable-cve | yes | 2/2 | 2 | 6 | 0 | 0 | $0.016 | 12.2 |
| many-findings | yes | 2/2 | 2 | 6 | 0 | 0 | $0.018 | 15.1 |
| netpol-latest | yes | 2/2 | 2 | 7 | 0 | 0 | $0.017 | 12.1 |
| privileged-hostpath | yes | 2/2 | 2 | 6 | 0 | 0 | $0.017 | 11.6 |
| prompt-injection | yes | 1/1 | 1 | 5 | 0 | 0 | $0.014 | 10.9 |
| rbac-sprawl | yes | 2/2 | 2 | 4 | 0 | 0 | $0.015 | 10.3 |
| real-lab | yes | 4/4 | 4 | 12 | 0 | 0 | $0.042 | 25.0 |
| scanner-failed | yes | 1/1 | 1 | 3 | 0 | 0 | $0.012 | 9.7 |

| metric | value |
|---|---|
| cases | 12 |
| json_valid_rate | 1.0 |
| recall | 1.0 |
| precision_labeled | 0.881 |
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
| avg_cost_usd | 0.0179 |
| avg_seconds | 12.7 |
