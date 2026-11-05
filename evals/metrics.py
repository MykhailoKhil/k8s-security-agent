"""Scoring for triage output. Pure functions, no network. See evals/README in the main README for definitions."""
import json
import re

SEV = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]  # ascending
ID_RE = re.compile(r"\b(?:C-\d{4}|KSV-?\d+|CVE-\d{4}-\d+|GHSA-[\w-]+|AVD-[\w-]+)\b", re.I)
VER_RE = re.compile(r"(?<![\w.-])v?\d+\.\d+(?:\.\d+)*(?![\w.-])")
PATH_RE = re.compile(r"[\w.:-]*/[\w.:/-]+")           # ns/Kind/name style
NAME_RE = re.compile(r"[A-Za-z0-9_.:]+(?:-[A-Za-z0-9_.:]+)+")  # hyphenated names, only taken from 'resource'
NUM_RE = re.compile(r"(?<![\w.-])\d{2,}(?![\w.-])")   # integers >= 10 stated as facts


def rank(s) -> int:
    s = str(s).upper()
    return SEV.index(s) if s in SEV else -1


def validate(d) -> list[str]:
    """Schema check for the findings object (the contract the renderer relies on)."""
    if not isinstance(d, dict):
        return ["not an object"]
    errs = []
    for k, t in (("summary", str), ("targets", list), ("frameworks", list), ("findings", list), ("not_checked", list)):
        if not isinstance(d.get(k), t):
            errs.append(f"{k}: missing or not {t.__name__}")
    for i, f in enumerate(d.get("findings") or []):
        if not isinstance(f, dict):
            errs.append(f"findings[{i}] not an object")
            continue
        if str(f.get("severity", "")).upper() not in SEV:
            errs.append(f"findings[{i}].severity invalid: {f.get('severity')!r}")
        for k in ("title", "resource", "evidence", "fix"):
            if not isinstance(f.get(k), str):
                errs.append(f"findings[{i}].{k} not a string")
        if not isinstance(f.get("controls"), list):
            errs.append(f"findings[{i}].controls not a list")
    return errs


def _blob(f: dict) -> str:
    return " ".join([str(f.get("title", "")), str(f.get("resource", "")), str(f.get("evidence", "")),
                     " ".join(map(str, f.get("controls") or []))]).lower()


def matches(f: dict, tokens: list[str]) -> bool:
    b = _blob(f)
    return any(t.lower() in b for t in tokens)


def untraceable(f: dict, digest_text: str) -> list[str]:
    """Identifiers, versions, paths and numbers in a finding that do not occur in the digest."""
    dl = digest_text.lower()
    ints = set(re.findall(r"(?<![\w.-])\d+(?![\w.-])", digest_text))
    claim = " ".join([str(f.get("title", "")), str(f.get("evidence", "")), " ".join(map(str, f.get("controls") or []))])
    res = str(f.get("resource", ""))
    bad = []
    for t in ID_RE.findall(claim + " " + res):
        if t.lower() not in dl:
            bad.append(t)
    for t in VER_RE.findall(claim):
        if t.lower().lstrip("v") not in dl:
            bad.append(t)
    for t in PATH_RE.findall(claim + " " + res):
        t = t.strip(".,;:()'\"`")
        if len(t) > 3 and t.lower() not in dl and t.lower().strip("/") not in dl:
            bad.append(t)
    for t in NAME_RE.findall(res):
        if len(t) > 3 and t.lower() not in dl:
            bad.append(t)
    for t in NUM_RE.findall(claim):
        if t not in ints:
            bad.append(t)
    return sorted(set(bad))


def framework_errors(data: dict, digest: dict) -> list[str]:
    truth = {}
    def walk(o):
        if isinstance(o, dict):
            if "frameworks" in o and isinstance(o["frameworks"], list):
                for fw in o["frameworks"]:
                    truth.setdefault(str(fw.get("name", "")).lower(), []).append(fw)
            for v in o.values():
                walk(v)
    walk(digest)
    errs = []
    for fw in data.get("frameworks") or []:
        name = str(fw.get("name", "")).lower()
        cands = [v for k, vs in truth.items() if name.startswith(k) for v in vs]
        if not any(all(fw.get(k) == c.get(k) for k in ("passed", "failed", "skipped") if k in fw) and
                   (fw.get("score") is None or abs(float(fw["score"]) - float(c.get("score", -1))) < 0.11) for c in cands):
            errs.append(f"{fw.get('name')}: {fw.get('passed')}/{fw.get('failed')}/{fw.get('skipped')} score {fw.get('score')} not in digest")
    return errs


def score_case(data, digest: dict, expected: dict) -> dict:
    errs = validate(data)
    r = {"json_valid": not errs, "schema_errors": errs[:5]}
    if errs and not isinstance(data, dict):
        return r
    findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
    digest_text = json.dumps(digest)
    inc = expected.get("must_include", [])
    found = sev_ok = fix_ok = fix_n = 0
    missed, wrong_sev = [], []
    matched_idx = set()
    for item in inc:
        ms = [(i, f) for i, f in enumerate(findings) if matches(f, item["any_of"])]
        matched_idx.update(i for i, _ in ms)
        if not ms:
            missed.append(item["id"])
            continue
        found += 1
        lo, hi = (rank(x) for x in item["severity"])
        if any(lo <= rank(f.get("severity")) <= hi for _, f in ms):
            sev_ok += 1
        else:
            wrong_sev.append(f"{item['id']}: got {sorted({str(f.get('severity')) for _, f in ms})}, want {item['severity']}")
        if item.get("fix_contains"):
            fix_n += 1
            if any(all(s in str(f.get("fix", "")) for s in item["fix_contains"]) for _, f in ms):
                fix_ok += 1
    for i, f in enumerate(findings):
        if i not in matched_idx and any(matches(f, a["any_of"]) for a in expected.get("acceptable", [])):
            matched_idx.add(i)
    violations = []
    for m in expected.get("must_not", []):
        for i, f in enumerate(findings):
            if not matches(f, m["match"]) or any(matches(f, x["any_of"]) for x in inc):
                continue
            if m.get("forbid_in_fix"):
                if re.search(m["forbid_in_fix"], str(f.get("fix", ""))):
                    violations.append(f"{m['id']}: fix contains a version for {f.get('title')!r}")
            elif m.get("above") is None or rank(f.get("severity")) > rank(m["above"]):
                violations.append(f"{m['id']}: {f.get('severity')} {f.get('title')!r}")
    cap = expected.get("max_severity_overall")
    if cap:
        violations += [f"overall cap {cap}: {f.get('severity')} {f.get('title')!r}" for f in findings if rank(f.get("severity")) > rank(cap)]
    if expected.get("max_findings") and len(findings) > expected["max_findings"]:
        violations.append(f"{len(findings)} findings > max {expected['max_findings']}")
    nc_text = json.dumps(data.get("not_checked") or []).lower()
    nc_missing = [s for s in expected.get("must_have_not_checked", []) if s.lower() not in nc_text]
    halluc = {f.get("title"): bad for f in findings if (bad := untraceable(f, digest_text))}
    r.update({
        "findings": len(findings), "expected": len(inc), "found": found, "missed": missed,
        "severity_ok": sev_ok, "wrong_severity": wrong_sev, "fix_checks": fix_n, "fix_ok": fix_ok,
        "labeled_correct": len(matched_idx), "unlabeled": len(findings) - len(matched_idx),
        "hallucinated": len(halluc), "hallucination_detail": halluc,
        "violations": violations, "not_checked_missing": nc_missing,
        "framework_errors": framework_errors(data, digest),
    })
    return r


def aggregate(cases: dict) -> dict:
    ok = [c for c in cases.values() if "expected" in c]
    n_find = sum(c["findings"] for c in ok)
    exp = sum(c["expected"] for c in ok)
    return {
        "cases": len(cases),
        "json_valid_rate": round(sum(c["json_valid"] for c in cases.values()) / max(len(cases), 1), 3),
        "recall": round(sum(c["found"] for c in ok) / exp, 3) if exp else None,
        "precision_labeled": round(sum(c["labeled_correct"] for c in ok) / n_find, 3) if n_find else None,
        "unlabeled_findings": sum(c["unlabeled"] for c in ok),
        "hallucinated_findings": sum(c["hallucinated"] for c in ok),
        "hallucination_rate": round(sum(c["hallucinated"] for c in ok) / n_find, 3) if n_find else None,
        "severity_accuracy": round(sum(c["severity_ok"] for c in ok) / max(sum(c["found"] for c in ok), 1), 3),
        "fix_version_accuracy": (round(sum(c["fix_ok"] for c in ok) / sum(c["fix_checks"] for c in ok), 3) if sum(c["fix_checks"] for c in ok) else None),
        "must_not_violations": sum(len(c["violations"]) for c in ok),
        "not_checked_missing": sum(len(c["not_checked_missing"]) for c in ok),
        "framework_errors": sum(len(c["framework_errors"]) for c in ok),
        "avg_cost_usd": round(sum(c.get("cost_usd", 0) for c in cases.values()) / max(len(cases), 1), 4),
        "avg_seconds": round(sum(c.get("seconds", 0) for c in cases.values()) / max(len(cases), 1), 1),
    }
