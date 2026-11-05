### phase3 (live)

| case | verdicts | correct | wrongly refuted | wrongly confirmed | calls | cost | violations |
|---|---|---|---|---|---|---|---|
| budget-pressure | R U R U R U U U | 8/8 | 0 | 0 | 5 | $0.021 | 0 |
| netpol | R C C C | 4/4 | 0 | 0 | 4 | $0.010 | 0 |
| pod-spec | C C R R C R | 6/6 | 0 | 0 | 6 | $0.016 | 0 |
| rbac | C R R C C | 5/5 | 0 | 0 | 6 | $0.018 | 0 |
| tool-injection | C C | 2/2 | 0 | 0 | 2 | $0.005 | 0 |
| unverifiable | U U U U U U | 6/6 | 0 | 0 | 5 | $0.016 | 0 |

| metric | value |
|---|---|
| cases | 6 |
| findings | 31 |
| verdict_accuracy | 1.0 |
| fp_total (Phase 2 shows these) | 11 |
| fp_removed | 9 |
| fp_remaining (Phase 3 shows these) | 2 |
| tp_total | 15 |
| tp_wrongly_refuted | 0 |
| wrongly_confirmed | 0 |
| over_cautious (decisive but unverified) | 0/17 |
| ungrounded_verdicts | 0 |
| weakly_grounded (names the queried object only) | 1 |
| budget_violations | 0 |
| tool_calls_per_finding | 0.9 |
| cost_per_finding_usd | 0.0028 |
| total_cost_usd | 0.086 |
