"""Run history and run-to-run diff. Identity is the fingerprint sha1(scope|rule|resource) built from scanner output,
never from the LLM's wording, so the same issue is the same issue however a finding is phrased or merged."""
import datetime
import json
from pathlib import Path

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _rank(s: str) -> int:
    return SEV.index(s) if s in SEV else len(SEV)


def load_previous(hist: Path) -> dict | None:
    for p in sorted(hist.glob("run-*.json"), reverse=True):
        try:
            run = json.loads(p.read_text())
            if isinstance(run.get("items"), list) and "scanned" in run:
                return run
        except (OSError, ValueError):
            continue  # a corrupt or partial file must not break the next run
    return None


def save_run(hist: Path, run: dict, keep: int = 30) -> Path:
    hist.mkdir(parents=True, exist_ok=True)
    p = hist / f"run-{run['time']}.json"
    p.write_text(json.dumps(run, separators=(",", ":")))
    for old in sorted(hist.glob("run-*.json"))[:-max(keep, 1)]:
        old.unlink()
    return p


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _groups(items: list[dict], show: int = 8) -> list[dict]:
    g: dict[str, dict] = {}
    for i in items:
        x = g.setdefault(i["rule"], {"rule": i["rule"], "title": i["title"], "severity": i["severity"], "count": 0, "resources": []})
        x["count"] += 1
        x["resources"].append(f"{i['scope']}: {i['resource']}")
        if _rank(i["severity"]) < _rank(x["severity"]):
            x["severity"] = i["severity"]
    out = sorted(g.values(), key=lambda x: (_rank(x["severity"]), -x["count"], x["rule"]))
    for x in out:
        x["resources"] = sorted(set(x["resources"]))[:show]
    return out


def diff(prev: dict | None, cur: dict) -> dict:
    """New / Fixed / Persisting between two runs. Only compares what was scanned in both runs:
    a scanner that failed or a target that was not included never turns into 'fixed' or 'new'."""
    if not prev:
        return {"previous": None, "items": len(cur["items"])}
    p = {i["fp"]: i for i in prev["items"]}
    c = {i["fp"]: i for i in cur["items"]}
    src = lambda i: f"{i['scope']}|{i['source']}"  # noqa: E731
    was, is_ = set(prev["scanned"]), set(cur["scanned"])
    new = [i for f, i in c.items() if f not in p and src(i) in was]
    no_baseline = sum(1 for f, i in c.items() if f not in p and src(i) not in was)
    persisting = [i for f, i in c.items() if f in p]
    fixed = [i for f, i in p.items() if f not in c and src(i) in is_]
    not_comparable = sum(1 for f, i in p.items() if f not in c and src(i) not in is_)
    return {"previous": prev["time"], "counts": {"new": len(new), "fixed": len(fixed), "persisting": len(persisting)},
            "new": _groups(new), "fixed": _groups(fixed), "persisting": _groups(persisting, show=3),
            "not_comparable": not_comparable, "no_baseline": no_baseline}


def annotate(findings: list[dict], cur_items: list[dict], prev: dict | None) -> list[dict]:
    """Tag each LLM finding with whether the scanner items behind it (matched by rule ID) are new or persisting."""
    if not prev:
        return findings
    was = {i["fp"] for i in prev["items"]}
    prev_scanned = set(prev["scanned"])
    out = []
    for f in findings:
        rules = {str(c).upper() for c in f.get("controls") or []}
        m = [i for i in cur_items if i["rule"].upper() in rules and f"{i['scope']}|{i['source']}" in prev_scanned]
        if not m:
            out.append(f)
            continue
        n_new = sum(i["fp"] not in was for i in m)
        out.append({**f, "change": {"status": "new" if n_new == len(m) else "persisting" if n_new == 0 else "partly new", "items": len(m), "new_items": n_new}})
    return out
