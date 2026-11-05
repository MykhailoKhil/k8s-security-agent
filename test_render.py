from render import render

d = {
    "targets": ["ctx"], "summary": "<script>alert(1)</script>",
    "frameworks": [{"name": "nsa", "passed": 5, "failed": 2, "skipped": 0, "score": 71.2}, {"name": "x", "score": "bad"}],
    "findings": [
        {"severity": "low", "title": "b", "resource": "r", "controls": ["C-1"], "evidence": "e"},
        {"severity": "CRITICAL", "title": "<img src=x onerror=1>", "resource": "r", "controls": [], "evidence": "e", "fix": "a: <b>", "confidence": "<i>high</i>"},
    ],
    "not_checked": [{"item": "node CIS", "reason": "needs privileged pod"}],
}
out = render(d)
assert "<script>alert" not in out and "<img src=x" not in out and "a: <b>" not in out  # escaped
assert out.index("CRITICAL") < out.index("LOW")  # sorted by severity
assert "n/a" in out and "71.2%" in out
assert "$0.1, 90s" in render({"meta": {"cost_usd": 0.1, "seconds": 90}})
render({})  # empty input must not crash
assert "confidence: &lt;i&gt;high&lt;/i&gt;" in out
ver = render({"findings": [
    {"severity": "HIGH", "title": "real <b>", "resource": "r", "evidence": "e", "verified": True, "verification_evidence": "binding b1 grants *"},
    {"severity": "CRITICAL", "title": "fp thing", "resource": "r", "evidence": "e", "verified": False, "verification_evidence": "default-deny exists <i>"},
    {"severity": "LOW", "title": "unk", "resource": "r", "evidence": "e", "verified": "unverified", "verification_evidence": "no tool"}]})
assert "Refuted by investigation (1)" in ver and "default-deny exists &lt;i&gt;" in ver and "confirmed by investigation: binding b1 grants *" in ver
assert 'border-top:4px solid #b42318"><b>0</b>' in ver and "unverified: no tool" in ver                      # the refuted CRITICAL is not counted
assert "Refuted" not in render({"findings": [{"severity": "LOW", "title": "x", "evidence": "e"}]})
df = {"previous": "20260101T000000Z", "counts": {"new": 1, "fixed": 2, "persisting": 3}, "not_comparable": 4, "no_baseline": 5,
      "new": [{"rule": "C-9", "title": "<b>bad</b>", "severity": "CRITICAL", "count": 12, "resources": ["c: ns/Deployment/<x>"]}],
      "fixed": [{"rule": "C-1", "title": "old", "severity": "HIGH", "count": 1, "resources": ["c: a/b/c"]}],
      "persisting": [{"rule": "C-2", "title": "p", "severity": "LOW", "count": 3, "resources": []}]}
dr = render({"diff": df, "findings": [{"severity": "HIGH", "title": "x", "evidence": "e", "change": {"status": "partly new", "items": 4, "new_items": 1}}]})
assert "Changes since 20260101T000000Z" in dr and "&lt;b&gt;bad&lt;/b&gt;" in dr and "ns/Deployment/&lt;x&gt;" in dr and "<b>bad</b>" not in dr
assert "<b>1</b>New" in dr and "<b>2</b>Fixed" in dr and "<b>3</b>Persisting" in dr and "partly new (1 of 4 items)" in dr
assert "4 items from last run cannot be compared" in dr and "5 items are from targets" in dr and " …" in dr   # 12 items, 1 shown
assert "First run: baseline of 7 scanner items" in render({"diff": {"previous": None, "items": 7}}) and "Changes since" not in render({})
print("render ok")
