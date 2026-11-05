"""Offline checks for the investigation evals: fixture sanity, scorer logic, mutation tests on recorded runs."""
import json
from pathlib import Path

from evals.inv_metrics import aggregate, score_case

D = Path("evals/investigation")
for d in sorted(D.iterdir()):
    inp = json.loads((d / "input.json").read_text())["findings"]
    exp = json.loads((d / "expected.json").read_text())
    assert len(inp) == len(exp["accept"]), d.name
    assert all(set(a) <= {"confirmed", "refuted", "unverified"} and a for a in exp["accept"]), d.name
    assert json.loads((d / "cluster.json").read_text())
    assert not any(o.get("kind") == "Secret" for o in json.loads((d / "cluster.json").read_text())), "fixtures must not contain Secrets"


def load(case, name="recorded"):
    r = json.loads((D / case / f"{name}.json").read_text())
    e = json.loads((D / case / "expected.json").read_text())
    return r, e


def sc(case, mutate=None, name="recorded"):
    r, e = load(case, name)
    if mutate:
        mutate(r)
    return score_case(r["findings"], r["trace"], e["accept"], e.get("budget", {}))


if (D / "netpol" / "recorded.json").exists():
    cases = {d.name: sc(d.name) for d in sorted(D.iterdir()) if (d / "recorded.json").exists()}
    agg = aggregate(cases)
    assert agg["budget_violations"] == 0 and agg["ungrounded_verdicts"] == 0 and agg["tp_wrongly_refuted"] == 0
    # mutation tests: the scorer must notice each failure mode
    assert sc("netpol", lambda r: r["findings"][1].update(verified=False))["wrongly_refuted"] == [1]             # true finding dropped
    assert sc("unverifiable", lambda r: r["findings"][0].update(verified=True))["wrongly_confirmed"] == [0]      # confirmed the undecidable
    assert sc("rbac", lambda r: r["trace"].update(run_calls=99))["budget_violations"]                             # run budget broken
    assert sc("budget-pressure", lambda r: r["trace"]["findings"][0].update(calls=9))["budget_violations"]        # per-finding budget broken
    assert sc("rbac", lambda r: r["trace"]["calls"].append({"finding": 0, "tool": "get_manifest", "args": {"kind": "Secret"}, "ok": True}))["budget_violations"]
    assert sc("rbac", lambda r: r["trace"]["calls"].append({"finding": 0}))["budget_violations"]                  # unlogged call shape
    assert sc("rbac", lambda r: r["findings"][0].update(verification_evidence="completely unrelated words"))["ungrounded"]
    assert sc("netpol", lambda r: [f.update(verified="unverified") for f in r["findings"]])["over_cautious"] == 4
print("investigation evals ok")
