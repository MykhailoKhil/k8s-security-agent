"""Offline tests for fingerprints and the run-to-run diff."""
import json
import tempfile
from pathlib import Path

from history import annotate, diff, load_previous, save_run
from scan import fingerprint, items_ks, items_rbac, items_trivy, norm_name, res_key

# --- resource keys are canonical across the many ID shapes and survive rollouts
assert res_key("/argo-rollouts/Deployment/argo-rollouts") == "argo-rollouts/Deployment/argo-rollouts"
assert res_key("apps/v1/demo-prod/ReplicaSet/demo-api-7dd5b476f9") == "demo-prod/ReplicaSet/demo-api" == res_key("apps/v1/demo-prod/ReplicaSet/demo-api-6d784c7d")
assert res_key("/v1/demo-staging/ServiceAccount/default") == "demo-staging/ServiceAccount/default"
assert res_key("path=1316107691/api=apps/v1//Deployment/k6-load") == "/Deployment/k6-load" == res_key("path=1518290449/api=apps/v1//Deployment/k6-load")
assert res_key("/ns/ServiceAccount/a/rbac.authorization.k8s.io/v1//ClusterRole/a/rbac.authorization.k8s.io/v1//ClusterRoleBinding/a") == "ns/ServiceAccount/a"
assert res_key("weird") == "weird"
assert norm_name("Pod", "demo-api-6d784c7d-4xj46") == "demo-api" and norm_name("Pod", "loki-0") == "loki-0" and norm_name("Deployment", "web-abcde") == "web-abcde"
assert fingerprint("c", "C-1", "a/b/c") == fingerprint("c", "C-1", "a/b/c") != fingerprint("d", "C-1", "a/b/c") != fingerprint("c", "C-2", "a/b/c")

# --- item extraction is deterministic and complete (no cap), independent of result ordering
ks = {"summaryDetails": {"controls": {"C-1": {"name": "x", "status": "failed", "scoreFactor": 8}}},
      "results": [{"resourceID": f"/ns/Deployment/d{i}", "controls": [{"controlID": "C-1", "status": {"status": "failed"}}]} for i in range(100)]}
assert len(items_ks(ks)) == 100 and items_ks(ks) == items_ks({**ks, "results": ks["results"][::-1]})
tv = {"Resources": [{"Kind": "ReplicaSet", "Name": "web-5d8b9c7f4", "Namespace": "shop", "Results": [{"Vulnerabilities": [{"Severity": "HIGH", "PkgName": "p", "VulnerabilityID": "CVE-1", "InstalledVersion": "1"}]}]},
                    {"Kind": "ClusterRole", "Name": "admin", "Namespace": None, "Results": [{"Misconfigurations": [{"ID": "KSV-1", "Severity": "LOW", "Status": "FAIL", "Title": "t"}]}]}]}
assert items_trivy(tv) == [("CVE-1", "shop/ReplicaSet/web:p", "HIGH", "p 1"), ("KSV-1", "/ClusterRole/admin", "LOW", "t")]    # no "None/" prefix, hash stripped
assert [i[0] for i in items_rbac({"admin_bindings": [{"binding": "b", "role": "cluster-admin"}], "argo_projects": [{"project": "p", "wildcard_destination": True, "wildcard_sources": False, "all_cluster_resources": False}]})] == ["ADMIN-BINDING", "ARGO-WILDCARD-PROJECT"]


# --- diff semantics
def item(rule, res, scope="c", source="kubescape", sev="HIGH", title="t"):
    return {"fp": fingerprint(scope, rule, res), "scope": scope, "source": source, "rule": rule, "resource": res, "severity": sev, "title": title}


def run(items, scanned=("c|kubescape",), time="20260101T000000Z"):
    return {"time": time, "scanned": list(scanned), "items": items}


a = run([item("C-1", "ns/Deployment/a"), item("C-1", "ns/Deployment/b"), item("C-2", "ns/Deployment/a", sev="LOW")])
b = run([item("C-1", "ns/Deployment/b"), item("C-3", "ns/Deployment/z", sev="CRITICAL"), item("C-2", "ns/Deployment/a", sev="LOW")], time="20260102T000000Z")
d = diff(a, b)
assert d["counts"] == {"new": 1, "fixed": 1, "persisting": 2} and d["new"][0]["rule"] == "C-3" and d["fixed"][0]["resources"] == ["c: ns/Deployment/a"]
assert d["previous"] == "20260101T000000Z" and diff(None, b) == {"previous": None, "items": 3}
assert diff(a, a)["counts"] == {"new": 0, "fixed": 0, "persisting": 3}

# a scan that did not run this time must not turn its items into "fixed"; a target with no previous scan must not be "new"
b2 = run([item("C-1", "ns/Deployment/b")], scanned=())
d2 = diff(a, b2)
assert d2["counts"]["fixed"] == 0 and d2["not_comparable"] == 2
b3 = run(a["items"] + [item("T-1", "x", scope="newrepo", source="trivy config")], scanned=("c|kubescape", "newrepo|trivy config"))
d3 = diff(a, b3)
assert d3["counts"]["new"] == 0 and d3["no_baseline"] == 1

# identity ignores LLM wording: same scanner items, differently worded/merged findings -> same diff
f1 = [{"title": "Privileged pods", "controls": ["C-1"], "severity": "HIGH"}]
f2 = [{"title": "Containers run with elevated rights", "controls": ["c-1", "C-2"], "severity": "MEDIUM"}]
assert diff(a, run(b["items"])) == diff(a, run(b["items"]))
assert annotate(f1, b["items"], a)[0]["change"] == {"status": "persisting", "items": 1, "new_items": 0}
assert annotate(f2, b["items"], a)[0]["change"]["status"] == "persisting" and annotate(f1, b["items"], None) == f1
assert annotate([{"controls": ["C-3"]}], b["items"], a)[0]["change"]["status"] == "new" and "change" not in annotate([{"controls": ["C-404"]}], b["items"], a)[0]
mixed = [item("C-1", "ns/Deployment/a"), item("C-1", "ns/Deployment/new")]
assert annotate([{"controls": ["C-1"]}], mixed, a)[0]["change"] == {"status": "partly new", "items": 2, "new_items": 1}

# --- persistence: latest run is loaded, corrupt files are skipped, old runs are pruned
with tempfile.TemporaryDirectory() as t:
    h = Path(t) / "history"
    assert load_previous(h) is None
    for i in range(5):
        save_run(h, {**run([item("C-1", f"r{i}")]), "time": f"2026010{i}T000000Z"}, keep=3)
    assert sorted(p.name for p in h.iterdir()) == [f"run-2026010{i}T000000Z.json" for i in (2, 3, 4)]
    (h / "run-20260109T000000Z.json").write_text("{ not json")
    (h / "run-20260108T000000Z.json").write_text(json.dumps({"no": "items"}))
    assert load_previous(h)["time"] == "20260104T000000Z"
print("history ok")
