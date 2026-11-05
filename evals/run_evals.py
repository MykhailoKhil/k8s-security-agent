"""Run triage over fixtures and score it. Env-configured:
EVAL_MODE=recorded|live (default recorded: replays recorded.json, offline, free)
EVAL_RECORD=1   save live replies to fixtures/<case>/<EVAL_RECORD_AS>.json (default recorded); EVAL_REPLAY=<name> replays another recording
EVAL_CASES=a,b  subset;  EVAL_CONCURRENCY=3;  EVAL_LABEL=baseline  (names this run in results)
EVAL_OUT=evals/results  (writes <out>.json and <out>.md)"""
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evals.metrics import aggregate, score_case  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


async def run_case(name: str, mode: str, sem: asyncio.Semaphore) -> tuple[str, dict]:
    d = FIX / name
    digest = json.loads((d / "digest.json").read_text())
    expected = json.loads((d / "expected.json").read_text())
    if mode == "live":
        from triage import extract_json, triage
        async with sem:
            try:
                r = await triage(json.dumps(digest, separators=(",", ":")), expected["targets"])
            except Exception as e:  # one failing case must not kill the run; it scores as invalid JSON
                return name, {"json_valid": False, "schema_errors": [f"triage call failed: {e}"[:200]], "cost_usd": 0, "seconds": 0}
        if os.environ.get("EVAL_RECORD") == "1":
            (d / f"{os.environ.get('EVAL_RECORD_AS', 'recorded')}.json").write_text(json.dumps(r, indent=1))
    else:
        r = json.loads((d / f"{os.environ.get('EVAL_REPLAY', 'recorded')}.json").read_text())
        from triage import extract_json
    try:
        data = extract_json(r["text"])
    except ValueError:
        data = None
    res = score_case(data, digest, expected) if data is not None else {"json_valid": False, "schema_errors": ["no JSON in reply"]}
    res.update({"cost_usd": r.get("cost_usd", 0), "seconds": round(r.get("seconds", 0), 1)})
    return name, res


def table(label: str, mode: str, cases: dict, agg: dict) -> str:
    L = [f"### {label} ({mode})", "", "| case | valid | found/expected | sev ok | findings | halluc | violations | cost | s |", "|---|---|---|---|---|---|---|---|---|"]
    for n, c in cases.items():
        if "expected" not in c:
            L.append(f"| {n} | no | - | - | - | - | - | ${c.get('cost_usd', 0):.3f} | {c.get('seconds', 0)} |")
            continue
        L.append(f"| {n} | yes | {c['found']}/{c['expected']} | {c['severity_ok']} | {c['findings']} | {c['hallucinated']} | {len(c['violations'])} | ${c['cost_usd']:.3f} | {c['seconds']} |")
    L += ["", "| metric | value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in agg.items()]
    return "\n".join(L)


async def main():
    mode = os.environ.get("EVAL_MODE", "recorded")
    names = [x for x in os.environ.get("EVAL_CASES", "").split(",") if x] or sorted(p.name for p in FIX.iterdir() if p.is_dir())
    sem = asyncio.Semaphore(int(os.environ.get("EVAL_CONCURRENCY", "3")))
    cases = dict(await asyncio.gather(*(run_case(n, mode, sem) for n in names)))
    cases = {n: cases[n] for n in names}
    agg = aggregate(cases)
    label = os.environ.get("EVAL_LABEL", "run")
    out = Path(os.environ.get("EVAL_OUT", "evals/results"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps({"label": label, "mode": mode, "aggregate": agg, "cases": cases}, indent=1))
    md = table(label, mode, cases, agg)
    out.with_suffix(".md").write_text(md + "\n")
    print(md)


if __name__ == "__main__":
    asyncio.run(main())
