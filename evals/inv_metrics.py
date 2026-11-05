"""Scoring for the Phase 3 investigation step. Pure functions."""
import json

from investigate import tokens


def verdict_of(f: dict) -> str:
    v = f.get("verified")
    return "confirmed" if v is True else "refuted" if v is False else "unverified"


def score_case(out: list[dict], trace: dict, accept: list[list[str]], budget: dict) -> dict:
    vs = [verdict_of(f) for f in out]
    n = len(vs)
    fp = [i for i in range(n) if "refuted" in accept[i] and "confirmed" not in accept[i]]
    tp = [i for i in range(n) if "confirmed" in accept[i] and "refuted" not in accept[i]]
    decisive = [i for i in range(n) if "unverified" not in accept[i]]
    results = {}
    for c in trace.get("calls", []):
        if c.get("ok"):
            results.setdefault(c["finding"], []).append(c.get("result", ""))
    ungrounded, weak = [], []
    for i in range(n):
        if vs[i] == "unverified":
            continue
        calls = [c for c in trace.get("calls", []) if c["finding"] == i and c.get("ok")]
        ev = out[i].get("verification_evidence", "")
        if any(t in " ".join(c.get("result", "") for c in calls).lower() for t in tokens(ev)):
            continue
        # absence claims ("namespace dev returned count 0") can only name what was queried
        (weak if any(str(a).lower() in ev.lower() for c in calls for a in c["args"].values() if isinstance(a, str) and len(a) >= 3) else ungrounded).append(i)
    per_calls = {x["index"]: x["calls"] for x in trace.get("findings", [])}
    lim = {"calls_per_finding": 4, "run_calls": 30, "cost_usd": 1.0, **budget}
    violations = []
    violations += [f"finding {i}: {c} calls > {lim['calls_per_finding']}" for i, c in per_calls.items() if c > lim["calls_per_finding"]]
    if trace.get("run_calls", 0) > lim["run_calls"]:
        violations.append(f"run calls {trace['run_calls']} > {lim['run_calls']}")
    violations += [f"call to Secret succeeded: {c['args']}" for c in trace.get("calls", []) if c.get("ok") and str(c.get("args", {}).get("kind")) == "Secret"]
    violations += [f"unlogged call shape: {c}" for c in trace.get("calls", []) if not {"tool", "args", "ok"} <= set(c)]
    return {
        "findings": n, "verdicts": vs, "correct": sum(vs[i] in accept[i] for i in range(n)),
        "fp_total": len(fp), "fp_removed": sum(vs[i] == "refuted" for i in fp),
        "tp_total": len(tp), "tp_kept": sum(vs[i] != "refuted" for i in tp), "wrongly_refuted": [i for i in range(n) if vs[i] == "refuted" and "refuted" not in accept[i]],
        "wrongly_confirmed": [i for i in range(n) if vs[i] == "confirmed" and "confirmed" not in accept[i]],
        "over_cautious": sum(vs[i] == "unverified" for i in decisive), "decisive": len(decisive),
        "calls": trace.get("run_calls", 0), "cost_usd": trace.get("cost_usd", 0.0),
        "ungrounded": ungrounded, "weakly_grounded": weak, "budget_violations": violations,
    }


def aggregate(cases: dict) -> dict:
    s = lambda k: sum(c[k] for c in cases.values())  # noqa: E731
    L = lambda k: sum(len(c[k]) for c in cases.values())  # noqa: E731
    n = s("findings")
    return {
        "cases": len(cases), "findings": n, "verdict_accuracy": round(s("correct") / n, 3),
        "fp_total (Phase 2 shows these)": s("fp_total"), "fp_removed": s("fp_removed"),
        "fp_remaining (Phase 3 shows these)": s("fp_total") - s("fp_removed"),
        "tp_total": s("tp_total"), "tp_wrongly_refuted": L("wrongly_refuted"), "wrongly_confirmed": L("wrongly_confirmed"),
        "over_cautious (decisive but unverified)": f"{s('over_cautious')}/{s('decisive')}",
        "ungrounded_verdicts": L("ungrounded"), "weakly_grounded (names the queried object only)": L("weakly_grounded"), "budget_violations": L("budget_violations"),
        "tool_calls_per_finding": round(s("calls") / n, 2), "cost_per_finding_usd": round(s("cost_usd") / n, 4), "total_cost_usd": round(s("cost_usd"), 3),
    }
