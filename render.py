"""Render findings.json -> one self-contained HTML report. Deterministic: the LLM only fills the JSON."""
import datetime
import html
import json
import sys

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
COLORS = {"CRITICAL": "#b42318", "HIGH": "#dc6803", "MEDIUM": "#b8860b", "LOW": "#2e7d32"}

CSS = """
body{font:15px/1.5 -apple-system,Segoe UI,sans-serif;margin:0;background:#f6f7f9;color:#1a1d21}
main{max-width:1100px;margin:0 auto;padding:24px}
h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:1px solid #d9dde3;padding-bottom:6px}
.meta{color:#667}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;border-radius:8px;padding:12px 18px;min-width:110px;box-shadow:0 1px 2px #0002}
.card b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 2px #0002}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eceff3;vertical-align:top}
th{background:#eef1f5}.badge{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;font-weight:600}
pre{background:#10151c;color:#e6edf3;padding:10px;border-radius:6px;overflow:auto;margin:6px 0 0;font-size:12px}
details summary{cursor:pointer;color:#175cd3}.bar{height:8px;background:#e4e7ec;border-radius:4px;min-width:90px}
.bar i{display:block;height:8px;border-radius:4px;background:#2e7d32}
"""


def e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def badge(sev: str) -> str:
    s = str(sev).upper()
    return f'<span class="badge" style="background:{COLORS.get(s, "#667")}">{e(s)}</span>'


def render(d: dict) -> str:
    counts = {s: 0 for s in SEV}
    for f in d.get("findings", []):
        s = str(f.get("severity", "")).upper()
        if s in counts:
            counts[s] += 1
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {COLORS[s]}"><b>{counts[s]}</b>{s.title()}</div>' for s in SEV
    )
    order = {s: i for i, s in enumerate(SEV)}
    findings = sorted(d.get("findings", []), key=lambda f: order.get(str(f.get("severity", "")).upper(), 9))
    rows = "".join(
        f"<tr><td>{badge(f.get('severity', ''))}</td><td><b>{e(f.get('title'))}</b><br><small>{e(f.get('resource'))}</small></td>"
        f"<td>{e(', '.join(map(str, f.get('controls', []))))}</td><td>{e(f.get('evidence'))}"
        + (f"<details><summary>Fix</summary><pre>{e(f['fix'])}</pre></details>" if f.get("fix") else "")
        + "</td></tr>"
        for f in findings
    )
    fw = "".join(
        f"<tr><td>{e(x.get('name'))}</td><td>{e(x.get('passed'))}</td><td>{e(x.get('failed'))}</td>"
        f"<td>{e(x.get('skipped'))}</td><td>{_score(x.get('score'))}</td></tr>"
        for x in d.get("frameworks", [])
    )
    nc = "".join(f"<tr><td>{e(x.get('item'))}</td><td>{e(x.get('reason'))}</td></tr>" for x in d.get("not_checked", []))
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    m = d.get("meta") or {}
    run = f" &middot; run: ${e(m.get('cost_usd'))}, {e(m.get('seconds'))}s" if m else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Kubernetes security audit</title>
<style>{CSS}</style></head><body><main>
<h1>Kubernetes security audit</h1>
<div class="meta">{e(when)} &middot; {e(', '.join(map(str, d.get('targets', []))))} &middot; read-only{run}</div>
<div class="cards">{cards}</div>
<h2>Summary</h2><p>{e(d.get('summary'))}</p>
<h2>Frameworks</h2><table><tr><th>Framework</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Score</th></tr>{fw}</table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Controls</th><th>Evidence / fix</th></tr>{rows}</table>
<h2>Not checked</h2><table><tr><th>Item</th><th>Reason</th></tr>{nc}</table>
</main></body></html>"""


def _score(v) -> str:
    try:
        n = max(0.0, min(100.0, float(v)))
    except (TypeError, ValueError):
        return "n/a"
    return f'{n:.1f}% <div class="bar"><i style="width:{n}%"></i></div>'


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    open(dst, "w").write(render(json.load(open(src))))
