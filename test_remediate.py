"""Offline tests for Phase 5: what may be fixed, how edits are checked, the GitHub allow-list and the pipeline (fake model, fake scanner, fake GitHub)."""
import asyncio
import base64
import json
import tempfile
from pathlib import Path

import remediate as rm
from scan import fingerprint

DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.27
          resources:
            limits: { memory: 64Mi }
          securityContext:
            runAsNonRoot: true
"""
SC_OLD = "            runAsNonRoot: true\n"
SC_NEW = "            runAsNonRoot: true\n            readOnlyRootFilesystem: true\n"


def item(rule, res, scope="app", source="kubescape", sev="HIGH", title="t"):
    return {"fp": fingerprint(scope, rule, res), "scope": scope, "source": source, "rule": rule, "resource": res, "severity": sev, "title": title}


# --- remotes
assert rm.parse_remote("https://github.com/acme/app.git") == ("acme", "app") and rm.parse_remote("git@github.com:acme/app.git") == ("acme", "app")
assert rm.parse_remote("https://x-access-token:SECRET@github.com/acme/app") == ("acme", "app") and rm.parse_remote("https://gitlab.com/a/b") is None

# --- what may be fixed
with tempfile.TemporaryDirectory() as t:
    repo = Path(t) / "app"
    (repo / "k8s").mkdir(parents=True)
    (repo / "k8s" / "web.yaml").write_text(DEPLOY)
    (repo / "k8s" / "svc.yaml").write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n")
    (repo / "k8s" / "kustomization.yaml").write_text("resources:\n  - web.yaml\n")
    (repo / ".github").mkdir()
    (repo / ".github" / "ci.yaml").write_text(DEPLOY)
    (repo / "k8s" / "big.yaml").write_text(DEPLOY + "# " + "x" * 25000)
    items = [item("KSV-0014", "k8s/web.yaml", source="trivy config"), item("C-0017", "/Deployment/web"), item("KSV-0014", "k8s/svc.yaml", source="trivy config"),
             item("KSV-0001", ".github/ci.yaml", source="trivy config"), item("KSV-0001", "k8s/kustomization.yaml", source="trivy config"), item("KSV-0001", "k8s/big.yaml", source="trivy config"),
             item("C-0057", "/Deployment/web", scope="cluster-ctx"),                      # cluster item: never remediated here
             item("KSV-0011", "k8s/web.yaml", source="trivy config", sev="LOW"),            # below MEDIUM
             item("AA", "k8s/web.yaml", source="trivy fs"), item("KSV-0014", "../etc/x.yaml", source="trivy config")]
    c = rm.candidates(items, "app", repo)
    assert list(c) == ["k8s/web.yaml"] and sorted(i["rule"] for i in c["k8s/web.yaml"]) == ["C-0017", "KSV-0014"]   # kubescape item mapped to its file by Kind/name
    assert rm.candidates(items, "app", repo, min_sev="LOW")["k8s/web.yaml"].__len__() == 3
    assert rm.candidates(items, "other", repo) == {} and rm.find_files(repo, "Deployment", "web") == ["k8s/big.yaml", "k8s/web.yaml"]

# --- edits: exact, additive, validated; all-or-nothing per file
F = {"a.yaml": DEPLOY}
ok, rej = rm.apply_edits(F, [{"file": "a.yaml", "old": SC_OLD, "new": SC_NEW}])
assert not rej and "readOnlyRootFilesystem: true" in ok["a.yaml"]
bad = lambda e: rm.apply_edits(F, [{"file": "a.yaml", **e}])  # noqa: E731
assert bad({"old": "nope", "new": "x"})[1] and bad({"old": "", "new": "x"})[1] and bad({"old": SC_OLD, "new": SC_OLD})[1] and bad({"old": "name: web\n", "new": "x\n"})[1]  # not found / empty / no-op / twice
assert rm.apply_edits(F, [{"file": "b.yaml", "old": "x", "new": "y"}])[1] and bad({"old": SC_OLD, "new": "z" * 3000})[1]
assert "image" in bad({"old": "          image: nginx:1.27\n", "new": "          imagePullPolicy: Always\n"})[1][0]                    # removes image
assert "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "            privileged: true\n"})[1][0]
assert "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "            allowPrivilegeEscalation: true\n"})[1][0]
assert "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "          volumes: [{hostPath: {path: /}}]\n"})[1][0]
assert "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "            # fetch https://evil.example/x\n"})[1][0]
assert "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "          command: [sh]\n"})[1][0] and "not allowed" in bad({"old": SC_OLD, "new": SC_OLD + "            capabilities:\n              add: [NET_ADMIN]\n"})[1][0]
assert "capabilities: { drop: [ALL] }" in rm.apply_edits(F, [{"file": "a.yaml", "old": SC_OLD, "new": SC_OLD + "            capabilities: { drop: [ALL] }\n"}])[0]["a.yaml"]   # dropping ALL is the fix, not a violation
assert "not valid YAML" in bad({"old": SC_OLD, "new": SC_OLD + "            x: [unclosed\n"})[1][0]
two = rm.apply_edits({"a.yaml": DEPLOY, "b.yaml": DEPLOY}, [{"file": "a.yaml", "old": SC_OLD, "new": SC_NEW}, {"file": "b.yaml", "old": SC_OLD, "new": SC_OLD + "            privileged: true\n"}])
assert list(two[0]) == ["a.yaml"] and len(two[1]) == 1                                                       # a good file survives a bad one
assert "+            readOnlyRootFilesystem: true" in rm.unified(F, ok)

# --- structural guard: parsed documents, so flow-style YAML cannot smuggle changes past the line checks
from yamlguard import check_structure
ok_edit = lambda new: check_structure(DEPLOY, DEPLOY.replace(SC_OLD, new))  # noqa: E731
FULL = DEPLOY.replace("          resources:\n            limits: { memory: 64Mi }\n", "")
assert ok_edit(SC_NEW) is None and ok_edit(SC_OLD + "            capabilities: { drop: [ALL] }\n            seccompProfile: { type: RuntimeDefault }\n            runAsUser: 10001\n") is None
assert check_structure(DEPLOY, DEPLOY.replace("      containers:\n", "      automountServiceAccountToken: false\n      securityContext:\n        seccompProfile: { type: RuntimeDefault }\n      containers:\n")) is None
assert check_structure(DEPLOY, DEPLOY.replace("limits: { memory: 64Mi }", "limits: { memory: 64Mi, cpu: 200m }\n            requests: { cpu: 50m }")) is None   # adding limits is fine
bypass = {
    "sidecar (flow style)": DEPLOY + "        - {name: sidecar, image: evil.example/x:1, securityContext: {runAsNonRoot: true}}\n",
    "env var added": DEPLOY.replace("          image: nginx:1.27\n", "          image: nginx:1.27\n          env: [{name: JAVA_TOOL_OPTIONS, value: '-javaagent:/x.jar'}]\n"),
    "unlisted key imagePullPolicy": DEPLOY.replace("          image: nginx:1.27\n", "          image: nginx:1.27\n          imagePullPolicy: Always\n"),
    "image changed": DEPLOY.replace("nginx:1.27", "nginx:9"),
    "replicas added": DEPLOY.replace("spec:\n  template:", "spec:\n  replicas: 50\n  template:"),
    "serviceAccountName added": DEPLOY.replace("    spec:\n      containers:", "    spec:\n      serviceAccountName: cluster-admin-sa\n      containers:"),
    "secret volume": DEPLOY.replace("    spec:\n      containers:", "    spec:\n      volumes: [{name: s, secret: {secretName: db}}]\n      containers:"),
    "hostPath volume (flow)": DEPLOY.replace("    spec:\n      containers:", "    spec:\n      volumes: [{name: h, hostPath: {path: /}}]\n      containers:"),
    "mount over /etc": DEPLOY.replace("          image: nginx:1.27\n", "          image: nginx:1.27\n          volumeMounts: [{name: e, mountPath: /etc/nginx}]\n").replace("    spec:\n      containers:", "    spec:\n      volumes: [{name: e, emptyDir: {}}]\n      containers:"),
    "mount on a non-emptyDir": DEPLOY.replace("          image: nginx:1.27\n", "          image: nginx:1.27\n          volumeMounts: [{name: nope, mountPath: /data}]\n"),
    "privileged false->true via flow": DEPLOY.replace("securityContext:\n            runAsNonRoot: true", "securityContext: {runAsNonRoot: true, privileged: true}"),
    "weakens existing runAsNonRoot": DEPLOY.replace("            runAsNonRoot: true\n", "            runAsNonRoot: false\n"),
    "removes existing hardening": DEPLOY.replace("          securityContext:\n            runAsNonRoot: true\n", ""),
    "changes an existing limit": DEPLOY.replace("memory: 64Mi", "memory: 1Mi"),
    "capabilities add": DEPLOY.replace(SC_OLD, SC_OLD + "            capabilities: {add: [NET_ADMIN], drop: [ALL]}\n"),
    "adds a second document": DEPLOY + "---\nkind: ClusterRoleBinding\nmetadata: {name: x}\n",
    "container renamed": DEPLOY.replace("- name: web\n          image", "- name: web2\n          image"),
    "metadata label change": DEPLOY.replace("  name: web\n", "  name: web\n  labels: {a: b}\n"),
    "automount true": DEPLOY.replace("      containers:\n", "      automountServiceAccountToken: true\n      containers:\n"),
}
for name, text in bypass.items():
    assert check_structure(DEPLOY, text), f"structural guard accepted: {name}"
assert check_structure(DEPLOY, DEPLOY.replace(SC_OLD, SC_OLD + "            readOnlyRootFilesystem: true\n").replace("      containers:\n", "      volumes: [{name: tmp, emptyDir: {}}]\n      containers:\n").replace("          image: nginx:1.27\n", "          image: nginx:1.27\n          volumeMounts: [{name: tmp, mountPath: /tmp}]\n")) is None   # the real read-only-FS fix
assert check_structure("kind: Service\nmetadata: {name: a}\n", "kind: Service\nmetadata: {name: b}\n") and check_structure(DEPLOY, "{ not yaml") and check_structure("a: 1\n", "a: 1\n") is None
# and it is enforced on the real path: the three edits that used to be accepted are now rejected by apply_edits
for name in ("sidecar (flow style)", "env var added", "unlisted key imagePullPolicy"):
    old_img = "          image: nginx:1.27\n"
    edit = {"sidecar (flow style)": old_img + "        - {name: sidecar, image: evil.example/backdoor:1, securityContext: {runAsNonRoot: true, allowPrivilegeEscalation: false}}\n",
            "env var added": old_img + "          env: [{name: JAVA_TOOL_OPTIONS, value: '-javaagent:/x.jar'}]\n",
            "unlisted key imagePullPolicy": old_img + "          imagePullPolicy: Always\n"}[name]
    got, rej = rm.apply_edits(F, [{"file": "a.yaml", "old": old_img, "new": edit}])
    assert not got and rej, f"apply_edits accepted {name}"

# --- GitHub client: only the endpoints a draft PR needs
gh = rm.GitHub("tok", transport=lambda *a: (200, {}))
for m, p in [("DELETE", "/repos/o/r/git/refs/heads/x"), ("PUT", "/repos/o/r/pulls/1/merge"), ("PATCH", "/repos/o/r/pulls/1"), ("POST", "/repos/o/r/issues"),
             ("POST", "/repos/o/r/git/refs/../../x"), ("GET", "/user/repos"), ("PUT", "/repos/o/r/collaborators/x"), ("POST", "/repos/o/r/merges")]:
    try:
        gh.req(m, p)
        raise SystemExit(f"should be blocked: {m} {p}")
    except rm.GitHubError:
        pass
for m, p in [("GET", "/repos/o/r"), ("POST", "/repos/o/r/git/refs"), ("PUT", "/repos/o/r/contents/k8s/web.yaml"), ("POST", "/repos/o/r/pulls")]:
    gh.req(m, p)


class FakeGH:
    def __init__(self, remote_files, branch_exists=False, fail=None):
        self.calls, self.remote, self.branch_exists, self.fail = [], remote_files, branch_exists, fail

    def __call__(self, method, url, token, body):
        path = url.replace("https://api.github.com", "")
        self.calls.append((method, path.split("?")[0], body))
        assert token == "tok"
        if self.fail == path.split("?")[0].split("/")[-1] and method != "GET":
            return 422, {"message": "boom"}
        if method == "GET" and path == "/repos/o/r":
            return 200, {"default_branch": "main"}
        if method == "GET" and "/git/ref/heads/main" in path:
            return 200, {"object": {"sha": "BASE"}}
        if method == "GET" and "/git/ref/heads/" in path:
            return (200, {}) if self.branch_exists else (404, {})
        if method == "GET" and "/contents/" in path:
            f = path.split("/contents/")[1].split("?")[0]
            return (200, {"content": base64.b64encode(self.remote[f].encode()).decode(), "sha": "BLOB-" + f}) if f in self.remote else (404, {})
        if method == "POST" and path.endswith("/git/refs"):
            return 201, {}
        if method == "PUT":
            return 200, {}
        if method == "POST" and path.endswith("/pulls"):
            return 201, {"html_url": "https://github.com/o/r/pull/7"}
        raise AssertionError(f"unexpected {method} {path}")


def pr(fake, orig=None, changed=None):
    return rm.open_draft_pr(rm.GitHub("tok", transport=fake), "o", "r", orig or {"web.yaml": DEPLOY}, changed or {"web.yaml": DEPLOY + "# x\n"}, "security-agent/fix-1", "t", "b")


f = FakeGH({"web.yaml": DEPLOY})
assert pr(f) == "https://github.com/o/r/pull/7"
verbs = [(m, p.split("/")[-1]) for m, p, _ in f.calls if m != "GET"]
assert verbs == [("POST", "refs"), ("PUT", "web.yaml"), ("POST", "pulls")]                                    # branch, commit, PR; nothing else
assert [b for m, p, b in f.calls if p.endswith("/pulls")][0]["draft"] is True and [b for m, p, b in f.calls if m == "PUT"][0]["sha"] == "BLOB-web.yaml"
for name, fake, text in [("branch exists", FakeGH({"web.yaml": DEPLOY}, branch_exists=True), "already exists"), ("local differs", FakeGH({"web.yaml": DEPLOY + "# upstream\n"}), "differs"),
                         ("missing upstream", FakeGH({}), "differs"), ("commit fails", FakeGH({"web.yaml": DEPLOY}, fail="web.yaml"), "commit"), ("pr fails", FakeGH({"web.yaml": DEPLOY}, fail="pulls"), "open PR")]:
    try:
        pr(fake)
        raise SystemExit(f"{name}: should fail")
    except rm.GitHubError as e:
        assert text in str(e), (name, str(e))
        if name in ("local differs", "missing upstream", "branch exists"):
            assert not [1 for m, *_ in fake.calls if m != "GET"], f"{name}: wrote before checking"    # nothing created on the remote

# --- the pipeline, with a fake model and a fake scanner (no network, no LLM)
def make_repo(root):
    repo = Path(root) / "app"
    (repo / "k8s").mkdir(parents=True)
    (repo / "k8s" / "web.yaml").write_text(DEPLOY)
    return repo


ITEMS = [item("KSV-0014", "k8s/web.yaml", source="trivy config"), item("C-0017", "/Deployment/web")]
SCANNED = ["app|kubescape", "app|trivy config", "app|trivy fs"]


def fake_scan(extra=(), drop_sources=()):
    async def scan_fn(ctx, paths, out, timeout):
        text = (Path(paths[0]) / "k8s" / "web.yaml").read_text()
        its = [] if "readOnlyRootFilesystem: true" in text else list(ITEMS)
        its += list(extra)
        return {}, its, [s for s in SCANNED if s not in drop_sources]
    return scan_fn


def ask_with(edits, skipped=()):
    async def ask(files, by_file):
        return {"edits": edits, "skipped": list(skipped), "cost": 0.02}
    return ask


GOOD = [{"file": "k8s/web.yaml", "old": SC_OLD, "new": SC_NEW, "rules": ["KSV-0014", "C-0017"], "why": "read-only root fs", "risk": "medium"}]


def run(ask, scan_fn, mode="dry-run", gh=None, items=ITEMS, root_check=True):
    with tempfile.TemporaryDirectory() as t:
        repo, out = make_repo(t), Path(t) / "out"
        res = asyncio.run(rm.remediate_repo("app", repo, items, SCANNED, out, mode, ask=ask, scan_fn=scan_fn, gh=gh))
        if root_check:
            assert (repo / "k8s" / "web.yaml").read_text() == DEPLOY, "the user's checkout must never be modified"
        res["_files"] = {p.name: p.read_text() for p in (out / "remediation" / "app").glob("*")} if (out / "remediation" / "app").exists() else {}
        return res


r = run(ask_with(GOOD, [{"file": "k8s/web.yaml", "rule": "C-0013", "reason": "needs UID"}]), fake_scan())
assert r["status"] == "dry-run" and r["verification"] == {"resolved": 2, "introduced": 0, "resolved_rules": ["C-0017", "KSV-0014"]} and r["cost"] == 0.02
assert "+            readOnlyRootFilesystem: true" in r["_files"]["patch.diff"] and "Draft" in r["_files"]["pr-body.md"] and "Not fixed" in r["_files"]["pr-body.md"] and "pull" not in r["_files"]["pr-body.md"].lower().replace("pull request", "")
r = run(ask_with(GOOD), fake_scan(extra=[item("C-9999", "/Deployment/web")]))
assert r["status"] == "rejected" and "1 new items" in r["reason"] and "patch.diff" not in r["_files"]            # introduces something -> no patch
r = run(ask_with(GOOD), fake_scan(drop_sources=("app|kubescape", "app|trivy config")))
assert r["status"] == "rejected" and "0 targeted" in r["reason"]                                               # a failed re-scan must not look like a fix
r = run(ask_with([{**GOOD[0], "new": SC_OLD + "            privileged: true\n"}]), fake_scan())
assert r["status"] == "rejected" and "not allowed" in r["reason"]
r = run(ask_with([]), fake_scan())
assert r["status"] == "rejected" and "none" in r["reason"] and run(ask_with(GOOD), fake_scan(), items=[item("X", "k8s/web.yaml", scope="ctx")])["status"] == "skipped"
gh2 = FakeGH({"k8s/web.yaml": DEPLOY})
rm.origin_of = lambda repo: ("o", "r")
r = run(ask_with(GOOD), fake_scan(), mode="pr", gh=rm.GitHub("tok", transport=gh2))
assert r["status"] == "pr" and r["pr_url"].endswith("/pull/7") and [b for m, p, b in gh2.calls if p.endswith("/pulls")][0]["draft"] is True
assert [b for m, p, b in gh2.calls if p.endswith("/git/refs") and m == "POST"][0]["ref"].startswith("refs/heads/security-agent/fix-")
r = run(ask_with(GOOD), fake_scan(), mode="pr", gh=None)
assert r["status"] == "rejected" and "GITHUB_TOKEN" in r["reason"]
r = run(ask_with(GOOD), fake_scan(), mode="pr", gh=rm.GitHub("tok", transport=FakeGH({"k8s/web.yaml": DEPLOY}, branch_exists=True)))
assert r["status"] == "rejected" and "already exists" in r["reason"] and r["files"]                              # idempotent: same fix is not proposed twice
assert "@​" in rm.pr_body("app", [{"file": "f", "risk": "low", "why": "ping @someone", "rules": ["r"]}], {"f"}, {"resolved": 1, "introduced": 0, "resolved_rules": []}, [], []).replace("@", "@​")
print("remediate ok")
