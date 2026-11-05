"""CI-safe checks: metric logic on synthetic data, fixture sanity, and a replay of recorded replies (no API)."""
import json
from pathlib import Path

from evals.metrics import aggregate, score_case, untraceable, validate

# --- metric logic
digest = {"clusters": {"c": {"kubescape": {"frameworks": [{"name": "NSA", "score": 61.1, "passed": 5, "failed": 16, "skipped": 5}],
                                            "failed_controls": [{"id": "C-0057", "examples": ["default/Deployment/shell"]}]},
                             "trivy k8s": {"critical_high_vulns": [{"id": "CVE-2026-1", "fixed": "1.2.3", "resource": "kube-system/Deployment/traefik"}]}}}}
good = {"summary": "s", "targets": [], "frameworks": [{"name": "NSA (c)", "passed": 5, "failed": 16, "skipped": 5, "score": 61.1}],
        "findings": [{"severity": "HIGH", "title": "Privileged container", "resource": "default/Deployment/shell", "controls": ["C-0057"], "evidence": "C-0057 fails on 1 resource", "fix": "x"},
                     {"severity": "CRITICAL", "title": "k3s default binding", "resource": "system:masters", "controls": [], "evidence": "e", "fix": ""}],
        "not_checked": [{"item": "node and control-plane CIS", "reason": "r"}]}
exp = {"must_include": [{"id": "priv", "any_of": ["C-0057"], "severity": ["HIGH", "CRITICAL"]}],
       "acceptable": [], "must_not": [{"id": "masters", "match": ["system:masters"], "above": "MEDIUM"}], "must_have_not_checked": ["node and control-plane"]}
r = score_case(good, digest, exp)
assert r["json_valid"] and r["found"] == 1 and r["severity_ok"] == 1 and r["hallucinated"] == 0 and r["framework_errors"] == []
assert len(r["violations"]) == 1 and r["unlabeled"] == 1 and r["not_checked_missing"] == []

bad = json.loads(json.dumps(good))
bad["findings"][0].update(controls=["C-0099"], evidence="C-0099 on ns/Pod/ghost with fix 9.9.9 across 77 resources", severity="LOW")
bad["frameworks"][0]["failed"] = 3
rb = score_case(bad, digest, exp)
assert rb["hallucinated"] >= 1 and set(untraceable(bad["findings"][0], json.dumps(digest))) >= {"C-0099", "9.9.9", "77", "ns/Pod/ghost"}
assert rb["missed"] == ["priv"] or rb["wrong_severity"]  # C-0099 no longer matches the C-0057 token, or severity is out of range
assert rb["framework_errors"]
assert validate({"findings": [{"severity": "bogus"}]}) and not validate(good) and validate("x")
agg = aggregate({"a": r, "b": rb})
assert agg["cases"] == 2 and agg["hallucinated_findings"] >= 1

# --- fixtures are internally consistent: every expected token occurs in the digest, so a correct model can pass
for d in sorted(Path("evals/fixtures").iterdir()):
    dg = (d / "digest.json").read_text().lower()
    ex = json.loads((d / "expected.json").read_text())
    for item in ex["must_include"]:
        assert any(t.lower() in dg for t in item["any_of"]), f"{d.name}/{item['id']}: no token in digest"
        assert item["severity"][0] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    for nc in ex.get("must_have_not_checked", []):
        assert nc.lower() in dg, f"{d.name}: not_checked {nc!r} missing from digest"

# --- replay recorded replies if present (offline, free)
import asyncio, os
from evals.run_evals import run_case
if any((d / "recorded.json").exists() for d in Path("evals/fixtures").iterdir()):
    async def replay():
        sem = asyncio.Semaphore(1)
        return [await run_case(d.name, "recorded", sem) for d in sorted(Path("evals/fixtures").iterdir()) if (d / "recorded.json").exists()]
    res = asyncio.run(replay())
    assert all(c["json_valid"] for _, c in res), [n for n, c in res if not c["json_valid"]]
print("evals ok")
