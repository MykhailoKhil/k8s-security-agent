### c1-strict-schema (recorded)

| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |
|---|---|---|---|---|---|---|---|---|
| ambiguous-severity | yes | 1/1 | 1 | 5 | 0 | 0 | $0.015 | 13.5 |
| argo-wildcard | yes | 3/3 | 3 | 7 | 0 | 0 | $0.017 | 14.7 |
| clean-baseline | yes | 0/0 | 0 | 3 | 0 | 0 | $0.011 | 8.4 |
| exposed-secrets | yes | 2/2 | 2 | 3 | 0 | 0 | $0.011 | 8.3 |
| fixable-cve | yes | 2/2 | 2 | 6 | 0 | 0 | $0.015 | 15.3 |
| many-findings | yes | 2/2 | 2 | 5 | 0 | 0 | $0.017 | 12.1 |
| netpol-latest | yes | 2/2 | 2 | 7 | 0 | 0 | $0.017 | 11.5 |
| privileged-hostpath | yes | 2/2 | 2 | 5 | 0 | 0 | $0.015 | 11.4 |
| prompt-injection | yes | 1/1 | 1 | 5 | 0 | 0 | $0.014 | 23.5 |
| rbac-sprawl | yes | 2/2 | 2 | 5 | 0 | 0 | $0.022 | 12.5 |
| real-lab | yes | 4/4 | 4 | 15 | 0 | 0 | $0.101 | 34.0 |
| scanner-failed | yes | 1/1 | 1 | 3 | 0 | 0 | $0.017 | 11.2 |

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
| evidence_grounded_rate | 0.942 |
| confidence_valid_rate | 0.0 |
| must_not_violations | 0 |
| not_checked_missing | 0 |
| framework_errors | 0 |
| avg_cost_usd | 0.0227 |
| avg_seconds | 14.7 |
