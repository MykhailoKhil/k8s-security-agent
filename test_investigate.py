"""Offline tests for the Phase 3 tool layer: validation, redaction, RBAC lookup, budgets, verdict enforcement. No model calls."""
import asyncio
import json
import subprocess

import investigate as inv
from investigate import Budget, FakeReader, State, ToolError, finalize, investigate, make_tools, reduce_obj

meta = lambda n, ns=None: {"name": n, **({"namespace": ns} if ns else {})}  # noqa: E731
OBJS = [
    {"kind": "ConfigMap", "metadata": {**meta("cfg", "shop"), "managedFields": [1], "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}", "note": "x" * 900}}, "data": {"password": "hunter2"}},
    {"kind": "Deployment", "metadata": meta("web", "shop"), "status": {"a": 1}, "spec": {"template": {"spec": {
        "hostNetwork": True, "containers": [{"name": "c", "image": "i:1", "env": [{"name": "DB_PASSWORD", "value": "s3cr3t"}, {"name": "MODE", "value": "prod"}],
                                              "securityContext": {"privileged": True}}], "volumes": [{"name": "h", "hostPath": {"path": "/var/run"}}]}}}},
    {"kind": "Pod", "metadata": meta("web-abc-123", "shop"), "spec": {"containers": [{"name": "c", "image": "i:1", "securityContext": {"runAsNonRoot": True}}], "volumes": [{"name": "e", "emptyDir": {}}]}},
    {"kind": "NetworkPolicy", "metadata": meta("default-deny", "shop"), "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
    {"kind": "NetworkPolicy", "metadata": meta("allow-web", "shop"), "spec": {"podSelector": {"matchLabels": {"a": "web"}}, "ingress": [{}]}},
    {"kind": "ClusterRole", "metadata": meta("wild"), "rules": [{"verbs": ["*"], "resources": ["*"]}]},
    {"kind": "ClusterRole", "metadata": meta("pod-reader"), "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}]},
    {"kind": "ClusterRole", "metadata": meta("one-secret"), "rules": [{"verbs": ["get"], "resources": ["secrets"], "resourceNames": ["tls"]}]},
    {"kind": "ClusterRoleBinding", "metadata": meta("b1"), "roleRef": {"kind": "ClusterRole", "name": "wild"}, "subjects": [{"kind": "ServiceAccount", "name": "ci-bot", "namespace": "ci"}]},
    {"kind": "ClusterRoleBinding", "metadata": meta("b2"), "roleRef": {"kind": "ClusterRole", "name": "one-secret"}, "subjects": [{"kind": "Group", "name": "devs"}]},
    {"kind": "RoleBinding", "metadata": meta("rb", "dev"), "roleRef": {"kind": "ClusterRole", "name": "pod-reader"}, "subjects": [{"kind": "User", "name": "alice"}]},
]
R = FakeReader(OBJS)


def bad(fn, **a):
    try:
        fn(R, a)
    except ToolError:
        return True
    return False


# --- argument validation: nothing outside the allow-lists gets through
assert bad(inv.t_get_manifest, kind="Secret", namespace="shop", name="x")
assert bad(inv.t_get_manifest, kind="Pod; rm -rf", namespace="shop", name="x")
assert bad(inv.t_get_manifest, kind="Pod", namespace="shop", name="--all")
assert bad(inv.t_get_manifest, kind="Pod", namespace="shop", name="a b")
assert bad(inv.t_get_manifest, kind="Pod", namespace="", name="x")           # namespace required
assert bad(inv.t_get_manifest, kind="Pod", namespace="shop", name="x", cluster="other")
assert bad(inv.t_who_can, verb="get; id", resource="pods") and bad(inv.t_who_can, verb="get", resource="pods --as admin")
assert bad(inv.t_list_network_policies, namespace="../etc") and bad(inv.t_get_pod_security_context, namespace="shop", pod=None)
assert inv.t_get_manifest(R, dict(kind="Namespace", namespace="", name="shop")) == {"found": False}

# --- reduction and redaction
m = inv.t_get_manifest(R, dict(kind="ConfigMap", namespace="shop", name="cfg"))["manifest"]
assert m["data"]["password"].startswith("<redacted") and "hunter2" not in json.dumps(m)
assert "managedFields" not in m["metadata"] and "kubectl.kubernetes.io/last-applied-configuration" not in m["metadata"]["annotations"]
assert len(m["metadata"]["annotations"]["note"]) <= inv.MAX_STR + 1
d = inv.t_get_manifest(R, dict(kind="Deployment", namespace="shop", name="web"))["manifest"]
env = d["spec"]["template"]["spec"]["containers"][0]["env"]
assert env[0]["value"] == "<redacted>" and env[1]["value"] == "prod" and "status" not in d
assert len(inv.cap({"x": "y" * 20000})) < inv.MAX_CHARS + 50

# --- credentials hidden in args, URLs and odd env names never reach the model or the trace
leak = {"kind": "Pod", "metadata": {"name": "p", "annotations": {"note": "see postgres://svc:annot-pw@db/x and Bearer abcdef1234567890abcdef"}}, "spec": {"containers": [{
    "name": "c", "command": ["app", "--api-key=sk-live-123", "--password", "hunter2", "--db-host=db.internal", "--verbose"],
    "args": ["--db", "postgres://admin:pw123@db/x", "--token=tok-9", "password=inline-pw", "AKIAABCDEFGHIJKLMNOP", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
    "env": [{"name": "DATABASE_URL", "value": "postgres://admin:pw123@db/x"}, {"name": "API_KEY", "value": "sk-live-123"}, {"name": "MODE", "value": "prod"},
            {"name": "JWT", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlMTIz"}, {"name": "CERT", "value": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"}]}]}}
out = json.dumps(inv.reduce_obj(leak))
for secret in ("sk-live-123", "pw123", "annot-pw", "hunter2", "tok-9", "inline-pw", "AKIAABCDEFGHIJKLMNOP", "ghp_abcdefghij", "abcdef1234567890abcdef", "c2lnbmF0dXJl", "MIIBOgIBAAJB"):
    assert secret not in out, f"leaked: {secret}"
assert "--db-host=db.internal" in out and "--verbose" in out and '"value": "prod"' in out.replace('"value":"prod"', '"value": "prod"') and "postgres://<redacted>@db/x" in out   # benign data survives
R3 = FakeReader([leak | {"metadata": {"name": "p", "namespace": "shop"}}])
res = inv.cap(inv.t_get_manifest(R3, dict(kind="Pod", namespace="shop", name="p")))
assert "hunter2" not in res and "pw123" not in res and json.loads(res)["found"] is True        # still valid JSON after redaction
assert inv.scrub("kind: Deployment name: web image: nginx:1.27.1 --port=8080") == "kind: Deployment name: web image: nginx:1.27.1 --port=8080"

# --- the four tools on a fake cluster
np_ = inv.t_list_network_policies(R, dict(namespace="shop"))
assert np_["count"] == 2 and [p["default_deny_ingress"] for p in np_["policies"]] == [True, False]
assert inv.t_list_network_policies(R, dict(namespace="empty"))["count"] == 0
wc = inv.t_who_can(R, dict(verb="get", resource="secrets", namespace=""))
assert [x["subject"] for x in wc["cluster_wide"]] == ["ServiceAccount:ci/ci-bot", "Group:/devs"] and wc["cluster_wide"][1]["limit"] == "names:tls"
dp = inv.t_who_can(R, dict(verb="delete", resource="pods", namespace=""))
assert [x["subject"] for x in dp["cluster_wide"]] == ["ServiceAccount:ci/ci-bot"] and dp["namespaced"] == []   # alice only has get/list in 'dev'
rp = inv.t_who_can(R, dict(verb="list", resource="pods", namespace="dev"))
assert any(x["subject"] == "User:/alice" and x["namespace"] == "dev" for x in rp["namespaced"])
ps = inv.t_get_pod_security_context(R, dict(namespace="shop", pod="web"))   # resolves the pod by prefix
assert ps["source"] == "Pod web-abc-123" and ps["containers"][0]["securityContext"] == {"runAsNonRoot": True}
R2 = FakeReader([o for o in OBJS if o["kind"] != "Pod"])
ps = inv.t_get_pod_security_context(R2, dict(namespace="shop", pod="web"))   # falls back to the Deployment template
assert ps["source"] == "Deployment template" and ps["hostNetwork"] is True and ps["volumes"][0]["hostPath"] == "/var/run"
assert inv.t_get_pod_security_context(R, dict(namespace="shop", pod="nope")) == {"found": False}

# --- kubectl is only ever `get`, via an argv list, and never for Secrets
seen = []
orig = subprocess.run
subprocess.run = lambda argv, **kw: (seen.append(argv), subprocess.CompletedProcess(argv, 0, '{"items": []}', ""))[1]
try:
    kr = inv.KubectlReader(["c1"])
    for kind in inv.KINDS:
        kr.get("c1", kind, "shop" if inv.KINDS[kind][1] else "", "x")
        kr.list("c1", kind, "shop" if inv.KINDS[kind][1] else "")
finally:
    subprocess.run = orig
assert seen and all(isinstance(a, list) and a[:2] == ["kubectl", "--context"] and a[3] == "get" and a[-2:] == ["-o", "json"] for a in seen)
assert not any("secret" in " ".join(a).lower() for a in seen)
assert not any(w in a for a in seen for w in ("delete", "apply", "patch", "exec", "edit", "create"))


# --- budgets and tool wrappers
def call(tools, tool_name, /, **args):
    t = next(x for x in tools if x.name == tool_name)
    return asyncio.run(t.handler(args))


st = State(R, Budget(calls_per_finding=2, run_calls=3))
t0 = make_tools(st, 0)
r1 = call(t0, "list_network_policies", namespace="shop")
assert not r1.get("is_error") and "untrusted_cluster_data" in r1["content"][0]["text"]
call(t0, "get_manifest", kind="Pod", namespace="shop", name="web-abc-123")
r3 = call(t0, "get_manifest", kind="Pod", namespace="shop", name="web-abc-123")          # 3rd call on finding 0 -> over per-finding limit
assert r3["is_error"] and "budget exhausted" in r3["content"][0]["text"] and st.per[0]["hit"] and st.run_calls == 2
t1 = make_tools(st, 1)
call(t1, "who_can", verb="get", resource="pods", namespace="dev")                      # run call #3
r5 = call(t1, "who_can", verb="get", resource="pods", namespace="dev")                 # run limit hit even though finding 1 has calls left
assert r5["is_error"] and st.per[1]["hit"] and st.run_calls == 3
assert [e["ok"] for e in st.trace] == [True, True, False, True, False] and all("tool" in e and "args" in e for e in st.trace)
bad_call = call(make_tools(State(R, Budget()), 0), "get_manifest", kind="Secret", namespace="shop", name="x")
assert bad_call["is_error"]                                                              # ToolError surfaces as an error result, not an exception


# --- verdict enforcement: the code, not the model, decides what a verdict is worth
def fin(per, verdict, trace_result="", args=None, **over):
    s = State(R, Budget())
    s.per[0] = {"calls": per.get("calls", 1), "hit": per.get("hit", False), "ok": per.get("ok", 1)}
    if trace_result:
        s.trace.append({"finding": 0, "tool": "t", "args": args or {}, "ok": True, "result": trace_result})
    return finalize({"title": "t", "severity": "HIGH"}, 0, verdict, s)


good = {"verdict": "refuted", "evidence": "NetworkPolicy 'default-deny' exists in shop"}
assert fin({}, good, '{"name":"default-deny"}')["verified"] is False
assert fin({}, {**good, "verdict": "confirmed"}, '{"name":"default-deny"}')["verified"] is True
assert fin({"ok": 0}, good, '{"name":"default-deny"}')["verified"] == "unverified"                       # no successful tool call
assert fin({}, {"verdict": "refuted", "evidence": "all fine, nothing to see"}, '{"name":"something-else"}')["verified"] == "unverified"   # evidence not in tool results
assert fin({}, {"verdict": "confirmed", "evidence": "namespace dev has zero policies"}, '{"count":0}', args={"namespace": "dev"})["verified"] is True   # absence claim names what was queried
assert fin({"hit": True}, good, '{"name":"default-deny"}')["verified"] == "unverified"                    # budget hit wins
assert fin({}, {"verdict": "unverified", "evidence": "cannot tell"}, "")["verified"] == "unverified"
assert fin({}, None, "")["verified"] == "unverified" and fin({}, {"error": "MaxTurns"}, "")["verification_evidence"] == "MaxTurns"


# --- the loop: top-N by severity, cost budget, never raises
def mk(sev, n):
    return {"severity": sev, "title": f"f{n}", "resource": "r", "controls": [], "evidence": "e", "fix": ""}


async def fake_ask(finding, state, i):
    tools = make_tools(state, i)
    await next(t for t in tools if t.name == "list_network_policies").handler({"namespace": "shop"})
    return {"verdict": "refuted", "evidence": "NetworkPolicy default-deny present", "cost": 0.3}


fs = [mk("LOW", 0), mk("CRITICAL", 1), mk("MEDIUM", 2), mk("HIGH", 3), mk("CRITICAL", 4)]
out, trace = asyncio.run(investigate(fs, R, Budget(top_n=3, cost_usd=10), ask=fake_ask))
assert [f["verified"] for f in out] == ["unverified", False, "unverified", False, False]                  # top 3: two CRITICAL + HIGH
assert out[0]["verification_evidence"].startswith("not investigated") and trace["run_calls"] == 3 and len(trace["calls"]) == 3
out, trace = asyncio.run(investigate(fs, R, Budget(top_n=5, cost_usd=0.5), ask=fake_ask))                # $0.3 each: later ones hit the cost cap
assert any(f["verification_evidence"] == "cost budget exhausted" for f in out) and trace["cost_usd"] <= 0.5 + 0.3 * 3


async def boom(finding, state, i):
    return {"error": "ResultError: max turns"}   # what sdk_ask returns when the SDK raises


out, _ = asyncio.run(investigate([mk("HIGH", 0)], R, Budget(), ask=boom))
assert out[0]["verified"] == "unverified" and "max turns" in out[0]["verification_evidence"]
print("investigate ok")
