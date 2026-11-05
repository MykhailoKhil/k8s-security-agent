"""Remediation evals: real scanners + (live or recorded) model edits on small manifest repos; dry-run only, nothing leaves the machine.
EVAL_MODE=recorded|live (recorded replays recorded.json edits, still runs the scanners) ; EVAL_RECORD=1 ; EVAL_CASES=a,b ; EVAL_LABEL ; EVAL_OUT=evals/rem-results"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import remediate as rm  # noqa: E402
from scan import scan  # noqa: E402

D = Path(__file__).parent / "remediation"
PROTECTED = ("image", "ports", "command", "args", "env", "name", "namespace", "replicas")


def protected(doc, path=""):
    """Flatten the fields whose change would alter behaviour (not hardening) into {path: value}."""
    out = {}
    if isinstance(doc, dict):
        for k, v in doc.items():
            p = f"{path}/{k}"
            if k in PROTECTED:
                out[p] = json.dumps(v, sort_keys=True)
            else:
                out.update(protected(v, p))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            out.update(protected(v, f"{path}[{i}]"))
    return out


def protected_violations(before: str, after: str) -> list[str]:
    b, a = [protected(d) for d in yaml.safe_load_all(before)], [protected(d) for d in yaml.safe_load_all(after)]
    return [f"{k}: {x.get(k)} -> {y.get(k)}" for x, y in zip(b, a) for k in set(x) | set(y) if x.get(k) != y.get(k)] + ([] if len(a) == len(b) else ["document count changed"])


async def run_case(name, mode, sem):
    d = D / name
    exp = json.loads((d / "expected.json").read_text())
    tmp = Path(tempfile.mkdtemp(prefix="rem-"))
    repo, out = tmp / "app", tmp / "out"            # scope name is "app" in every case
    shutil.copytree(d / "repo", repo)
    snapshot = {p: p.read_text() for p in repo.rglob("*") if p.is_file()}
    _, items, scanned = await scan([], [str(repo)], out / "initial", 300)
    (out / "initial").mkdir(parents=True, exist_ok=True)
    if mode == "live":
        ask = rm.sdk_edits
    else:
        rec = json.loads((d / f"{os.environ.get('EVAL_REPLAY', 'recorded')}.json").read_text())

        async def ask(files, by_file):
            return rec
    box = {}

    async def spy(files, by_file):
        async with sem:
            box["r"] = await ask(files, by_file)
        return box["r"]
    res = await rm.remediate_repo("app", repo, items, scanned, out, "dry-run", ask=spy, scan_fn=scan)
    if mode == "live" and os.environ.get("EVAL_RECORD") == "1" and "r" in box:
        (d / f"{os.environ.get('EVAL_RECORD_AS', 'recorded')}.json").write_text(json.dumps(box["r"], indent=1))
    fails = []
    ok_status = res["status"] == exp.get("expect_status") if "expect_status" in exp else res["status"] in exp["expect_status_any"]
    if not ok_status:
        fails.append(f"status {res['status']} ({res['reason'][:90]})")
    v = res.get("verification") or {}
    if v and v["introduced"]:
        fails.append(f"introduced {v['introduced']}")
    if exp.get("min_resolved") and v.get("resolved", 0) < exp["min_resolved"]:
        fails.append(f"resolved {v.get('resolved', 0)} < {exp['min_resolved']}")
    if exp.get("should_resolve_any_of") and not set(v.get("resolved_rules", [])) & set(exp["should_resolve_any_of"]):
        fails.append("none of the expected rules resolved")
    patch = (out / "remediation" / "app" / "patch.diff")
    patch_text = patch.read_text() if patch.exists() else ""
    plan_text = json.dumps(box.get("r", {}).get("edits", []))
    hits = [t for t in exp.get("forbidden_text", []) if t in patch_text or t in plan_text]
    if hits:
        fails.append(f"forbidden text in output: {hits}")
    pv = []
    for rel in res.get("files", []):
        after = out / "remediation" / "work" / "app" / rel
        if after.exists():
            pv += protected_violations(snapshot[repo / rel], after.read_text())
    if pv:
        fails.append(f"protected fields changed: {pv[:2]}")
    if exp.get("kustomize_must_build") and res["status"] == "dry-run":
        kd = out / "remediation" / "work" / "app" / "k8s"
        if subprocess.run(["kubectl", "kustomize", str(kd)], capture_output=True).returncode != 0:
            fails.append("kustomize does not build")
    untouched = all(p.read_text() == t for p, t in snapshot.items())
    if not untouched:
        fails.append("source checkout was modified")
    added = sum(1 for line in patch_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in patch_text.splitlines() if line.startswith("-") and not line.startswith("---"))
    shutil.rmtree(tmp, ignore_errors=True)
    return name, {"status": res["status"], "pass": not fails, "fails": fails, "resolved": v.get("resolved", 0), "introduced": v.get("introduced", 0), "targeted_items": len(items),
                  "lines_added": added, "lines_removed": removed, "edits": len(box.get("r", {}).get("edits", [])), "skipped": len(box.get("r", {}).get("skipped", [])), "cost_usd": res.get("cost", 0.0)}


async def main():
    mode = os.environ.get("EVAL_MODE", "recorded")
    names = [x for x in os.environ.get("EVAL_CASES", "").split(",") if x] or sorted(p.name for p in D.iterdir() if p.is_dir())
    sem = asyncio.Semaphore(2)
    cases = dict(await asyncio.gather(*(run_case(n, mode, sem) for n in names)))
    cases = {n: cases[n] for n in names}
    s = lambda k: sum(c[k] for c in cases.values())  # noqa: E731
    agg = {"cases": len(cases), "passed": sum(c["pass"] for c in cases.values()), "items_resolved": s("resolved"), "items_introduced": s("introduced"),
           "lines_added": s("lines_added"), "lines_removed": s("lines_removed"), "edits": s("edits"), "skipped_by_model": s("skipped"), "total_cost_usd": round(s("cost_usd"), 3)}
    label = os.environ.get("EVAL_LABEL", "run")
    L = [f"### {label} ({mode})", "", "| case | status | pass | resolved | introduced | +/- lines | edits | skipped | cost | failures |", "|---|---|---|---|---|---|---|---|---|---|"]
    for n, c in cases.items():
        L.append(f"| {n} | {c['status']} | {'yes' if c['pass'] else 'NO'} | {c['resolved']} | {c['introduced']} | +{c['lines_added']}/-{c['lines_removed']} | {c['edits']} | {c['skipped']} | ${c['cost_usd']:.3f} | {'; '.join(c['fails'])[:140]} |")
    L += ["", "| metric | value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in agg.items()]
    o = Path(os.environ.get("EVAL_OUT", "evals/rem-results"))
    o.with_suffix(".json").write_text(json.dumps({"label": label, "mode": mode, "aggregate": agg, "cases": cases}, indent=1))
    o.with_suffix(".md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    asyncio.run(main())
