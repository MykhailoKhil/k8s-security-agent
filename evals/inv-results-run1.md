### phase3-run1 (recorded)

| case | verdicts | correct | wrongly refuted | wrongly confirmed | calls | cost | violations |
|---|---|---|---|---|---|---|---|
| budget-pressure | R U R U U U U U | 8/8 | 0 | 0 | 5 | $0.047 | 0 |
| netpol | R U C C | 3/4 | 0 | 0 | 4 | $0.025 | 0 |
| pod-spec | C U R R C U | 4/6 | 0 | 0 | 6 | $0.040 | 0 |
| rbac | C R R C C | 5/5 | 0 | 0 | 6 | $0.038 | 0 |
| tool-injection | C C | 2/2 | 0 | 0 | 2 | $0.013 | 0 |
| unverifiable | U R U U | 3/4 | 1 | 0 | 3 | $0.024 | 0 |

| metric | value |
|---|---|
| cases | 6 |
| findings | 29 |
| verdict_accuracy | 0.862 |
| fp_total (Phase 2 shows these) | 11 |
| fp_removed | 7 |
| fp_remaining (Phase 3 shows these) | 4 |
| tp_total | 15 |
| tp_wrongly_refuted | 1 |
| wrongly_confirmed | 0 |
| over_cautious (decisive but unverified) | 3/17 |
| ungrounded_verdicts | 0 |
| weakly_grounded (names the queried object only) | 0 |
| budget_violations | 0 |
| tool_calls_per_finding | 0.9 |
| cost_per_finding_usd | 0.0064 |
| total_cost_usd | 0.187 |
