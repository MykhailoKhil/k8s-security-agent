"""Run the investigation step over evals/investigation/* against a fake cluster and score it.
EVAL_MODE=recorded|live (default recorded: replays recorded.json, offline) ; EVAL_RECORD=1 saves live results ;
EVAL_CASES=a,b ; EVAL_LABEL=name ; EVAL_OUT=evals/inv-results"""
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evals.inv_metrics import aggregate, score_case  # noqa: E402
from investigate import Budget, FakeReader, investigate  # noqa: E402

D = Path(__file__).parent / "investigation"


async def run_case(name, mode, sem):
    d = D / name
    findings = json.loads((d / "input.json").read_text())["findings"]
    exp = json.loads((d / "expected.json").read_text())
    budget = {**exp.get("budget", {})}
    if mode == "live":
        async with sem:
            b = Budget(**{k: v for k, v in budget.items() if k in Budget.__dataclass_fields__})
            out, trace = await investigate(findings, FakeReader(json.loads((d / "cluster.json").read_text())), b)
        if os.environ.get("EVAL_RECORD") == "1":
            (d / f"{os.environ.get('EVAL_RECORD_AS', 'recorded')}.json").write_text(json.dumps({"findings": out, "trace": trace}, indent=1))
    else:
        rec = json.loads((d / f"{os.environ.get('EVAL_REPLAY', 'recorded')}.json").read_text())
        out, trace = rec["findings"], rec["trace"]
    return name, score_case(out, trace, exp["accept"], budget)


async def main():
    mode = os.environ.get("EVAL_MODE", "recorded")
    names = [x for x in os.environ.get("EVAL_CASES", "").split(",") if x] or sorted(p.name for p in D.iterdir() if p.is_dir())
    sem = asyncio.Semaphore(2)
    cases = dict(await asyncio.gather(*(run_case(n, mode, sem) for n in names)))
    cases = {n: cases[n] for n in names}
    agg = aggregate(cases)
    label = os.environ.get("EVAL_LABEL", "run")
    L = [f"### {label} ({mode})", "", "| case | verdicts | correct | wrongly refuted | wrongly confirmed | calls | cost | violations |", "|---|---|---|---|---|---|---|---|"]
    for n, c in cases.items():
        L.append(f"| {n} | {' '.join(v[0].upper() for v in c['verdicts'])} | {c['correct']}/{c['findings']} | {len(c['wrongly_refuted'])} | {len(c['wrongly_confirmed'])} | {c['calls']} | ${c['cost_usd']:.3f} | {len(c['budget_violations'])} |")
    L += ["", "| metric | value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in agg.items()]
    out = Path(os.environ.get("EVAL_OUT", "evals/inv-results"))
    out.with_suffix(".json").write_text(json.dumps({"label": label, "mode": mode, "aggregate": agg, "cases": cases}, indent=1))
    out.with_suffix(".md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    asyncio.run(main())
