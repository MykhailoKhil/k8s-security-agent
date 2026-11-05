from render import render

d = {
    "targets": ["ctx"], "summary": "<script>alert(1)</script>",
    "frameworks": [{"name": "nsa", "passed": 5, "failed": 2, "skipped": 0, "score": 71.2}, {"name": "x", "score": "bad"}],
    "findings": [
        {"severity": "low", "title": "b", "resource": "r", "controls": ["C-1"], "evidence": "e"},
        {"severity": "CRITICAL", "title": "<img src=x onerror=1>", "resource": "r", "controls": [], "evidence": "e", "fix": "a: <b>"},
    ],
    "not_checked": [{"item": "node CIS", "reason": "needs privileged pod"}],
}
out = render(d)
assert "<script>alert" not in out and "<img src=x" not in out and "a: <b>" not in out  # escaped
assert out.index("CRITICAL") < out.index("LOW")  # sorted by severity
assert "n/a" in out and "71.2%" in out
assert "$0.1, 90s" in render({"meta": {"cost_usd": 0.1, "seconds": 90}})
render({})  # empty input must not crash
print("render ok")
