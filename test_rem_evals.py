"""Offline checks for the remediation evals: fixtures, the protected-field scorer, and the recorded model edits against the deny-lists (no scanners, no API)."""
import json
from pathlib import Path

import remediate as rm
from evals.run_remediation import protected_violations

D = Path("evals/remediation")
for d in sorted(D.iterdir()):
    exp = json.loads((d / "expected.json").read_text())
    assert ("expect_status" in exp) != ("expect_status_any" in exp), d.name
    assert any((d / "repo").rglob("*.yaml")), d.name

# protected-field scorer: hardening additions are fine, behaviour changes are not
A = "kind: Deployment\nmetadata: {name: a}\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n        - name: a\n          image: x:1\n          env: [{name: K, value: v}]\n"
assert protected_violations(A, A.replace("x:1\n", "x:1\n          securityContext: {allowPrivilegeEscalation: false}\n")) == []
assert protected_violations(A, A.replace("x:1", "x:2")) and protected_violations(A, A.replace("replicas: 2", "replicas: 9")) and protected_violations(A, A.replace("value: v", "value: w"))
assert protected_violations(A, A + "---\nkind: Service\n")

# replay the recorded model edits through the real deny-lists on the fixture files: accepted edits stay accepted, and a poisoned copy is always rejected
checked = 0
for d in sorted(D.iterdir()):
    rec = d / "recorded.json"
    if not rec.exists():
        continue
    edits = json.loads(rec.read_text())["edits"]
    files = {p.relative_to(d / "repo").as_posix(): p.read_text() for p in (d / "repo").rglob("*.y*ml")}
    changed, rejected = rm.apply_edits(files, edits)
    assert not rejected and bool(changed) == bool(edits), (d.name, rejected)
    for e in edits:
        for poison in ("          privileged: true\n", "          image: evil.example/x:1\n", "          command: [sh]\n"):
            assert rm.apply_edits(files, [{**e, "new": e["new"] + poison}])[1], (d.name, poison)
        checked += 1
print("remediation evals ok", checked)
