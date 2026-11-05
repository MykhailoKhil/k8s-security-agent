"""Deterministic scan stage: run every scanner in parallel, reduce the output to a small digest for the LLM.
The LLM never runs commands or reads raw scanner JSON (that was most of the tokens and wall time)."""
import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
KS_FRAMEWORKS = "nsa,mitre,cis-v1.12.0"
CAP = 40  # max items per list in the digest


async def run(argv: list[str], timeout: int) -> tuple[int, str]:
    p = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        return 124, f"timeout after {timeout}s"
    return p.returncode, out.decode(errors="replace")[-300:]


def jobs(contexts: list[str], paths: list[str], out: Path) -> list[tuple[str, str, list[str]]]:
    """(kind, label, argv) per scan; kind picks the reducer."""
    j = []
    for c in contexts:
        j += [
            ("ks", f"kubescape {c}", ["kubescape", "scan", "framework", KS_FRAMEWORKS, "--kube-context", c, "--format", "json", "--output", str(out / f"ks-{c}.json")]),
            ("pss", f"trivy pss {c}", ["trivy", "k8s", "--disable-node-collector", "--compliance", "k8s-pss-restricted-0.1", "--report", "summary", "--format", "json", "-o", str(out / f"pss-{c}.json"), "--quiet", c]),
            ("trivy", f"trivy k8s {c}", ["trivy", "k8s", "--disable-node-collector", "--scanners", os.environ.get("TRIVY_SCANNERS", "vuln,secret,misconfig"), "--severity", "CRITICAL,HIGH,MEDIUM", "--report", "all", "--format", "json", "-o", str(out / f"trivy-{c}.json"), "--quiet", c]),
        ]
    for p in paths:
        n = Path(p).name
        j += [
            ("ks", f"kubescape {n}", ["kubescape", "scan", "framework", "nsa,mitre", p, "--format", "json", "--output", str(out / f"ks-{n}.json")]),
            ("trivy", f"trivy config {n}", ["trivy", "config", p, "--skip-dirs", ".git,node_modules", "--format", "json", "-o", str(out / f"trivycfg-{n}.json"), "--quiet"]),
            ("trivy", f"trivy fs {n}", ["trivy", "fs", p, "--scanners", "secret,vuln", "--skip-dirs", ".git,node_modules", "--format", "json", "-o", str(out / f"trivyfs-{n}.json"), "--quiet"]),
        ]
    return j


def outfile(argv: list[str]) -> Path:
    for flag in ("--output", "-o"):
        if flag in argv:
            return Path(argv[argv.index(flag) + 1])
    raise ValueError("no output flag")


def sev_name(c: dict) -> str:
    s = c.get("severity")
    if isinstance(s, str) and s.upper() in SEV:
        return s.upper()
    f = c.get("scoreFactor", 0)
    return "CRITICAL" if f >= 9 else "HIGH" if f >= 7 else "MEDIUM" if f >= 4 else "LOW"


def reduce_ks(d: dict) -> dict:
    failed_res = defaultdict(list)
    for r in d.get("results", []):
        label = "/".join(r["resourceID"].strip("/").split("/")[:3])
        for c in r.get("controls", []):
            if c.get("status", {}).get("status") == "failed":
                failed_res[c["controlID"]].append(label)
    ctrls = d.get("summaryDetails", {}).get("controls", {})
    frameworks = []
    for fw in d.get("summaryDetails", {}).get("frameworks", []):
        cs = fw.get("controls", {})
        cnt = defaultdict(int)
        for v in cs.values():
            cnt[v.get("status", "unknown")] += 1
        frameworks.append({"name": fw.get("name"), "score": round(fw.get("complianceScore", 0), 1),
                           "passed": cnt["passed"], "failed": cnt["failed"],
                           "skipped": sum(v for k, v in cnt.items() if k not in ("passed", "failed"))})
    failed = [{"id": cid, "name": c.get("name"), "severity": sev_name(c),
               "resources": len(failed_res.get(cid, [])), "examples": sorted(set(failed_res.get(cid, [])))[:4]}
              for cid, c in ctrls.items() if c.get("status") == "failed"]
    failed.sort(key=lambda x: (SEV.index(x["severity"]), -x["resources"]))
    return {"frameworks": frameworks, "failed_controls": failed[:CAP]}


def reduce_trivy(d: dict) -> dict:
    items = []  # (resource label, Results list)
    rows = d.get("Resources") or d.get("Findings")  # key name differs between trivy versions
    if rows is not None:
        items = [(f"{f.get('Namespace', '')}/{f.get('Kind')}/{f.get('Name')}", f.get("Results") or []) for f in rows]
    else:
        items = [(r.get("Target", ""), [r]) for r in d.get("Results", [])]
    counts = {"vuln": defaultdict(int), "misconf": defaultdict(int)}
    vulns, misconf, secrets = {}, {}, []
    for label, results in items:
        for r in results:
            for v in r.get("Vulnerabilities") or []:
                s = v.get("Severity", "UNKNOWN")
                counts["vuln"][s] += 1
                if s in ("CRITICAL", "HIGH"):
                    vulns[(label, v.get("PkgName"), v.get("VulnerabilityID"))] = {
                        "resource": label, "pkg": v.get("PkgName"), "id": v.get("VulnerabilityID"),
                        "severity": s, "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion") or "none"}
            for m in r.get("Misconfigurations") or []:
                if m.get("Status") == "FAIL":
                    s = m.get("Severity", "UNKNOWN")
                    counts["misconf"][s] += 1
                    misconf.setdefault((m.get("ID"), s), {"id": m.get("ID"), "title": m.get("Title"), "severity": s, "resources": set()})["resources"].add(label)
            for sec in r.get("Secrets") or []:
                secrets.append({"resource": label, "rule": sec.get("RuleID"), "severity": sec.get("Severity"), "file": r.get("Target")})
    vl = sorted(vulns.values(), key=lambda x: (SEV.index(x["severity"]), x["resource"]))
    ml = sorted(misconf.values(), key=lambda x: (SEV.index(x["severity"]) if x["severity"] in SEV else 9, -len(x["resources"])))
    return {"vuln_counts": dict(counts["vuln"]), "misconfig_counts": dict(counts["misconf"]),
            "critical_high_vulns": vl[:CAP],
            "misconfigs": [{**m, "count": len(m["resources"]), "resources": sorted(m["resources"])[:4]} for m in ml[:CAP]],
            "secrets": secrets[:CAP]}


def reduce_pss(d: dict) -> dict:
    ctl = d.get("SummaryControls", [])
    return {"failed": [{"id": c["ID"], "name": c["Name"], "severity": c["Severity"], "fails": c["TotalFail"]} for c in ctl if c.get("TotalFail")],
            "passed_controls": sum(1 for c in ctl if not c.get("TotalFail")), "total_controls": len(ctl)}


REDUCERS = {"ks": reduce_ks, "trivy": reduce_trivy, "pss": reduce_pss}


async def kubectl_json(ctx: str, *args: str):
    p = await asyncio.create_subprocess_exec("kubectl", "--context", ctx, *args, "-o", "json",
                                             stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await p.communicate()
    return json.loads(out) if p.returncode == 0 and out else None


async def rbac_and_argo(ctx: str) -> dict:
    """Deterministic checks the scanners miss: who is cluster-admin, wildcard roles, Argo CD project scope."""
    crb, cr, projects, apps = await asyncio.gather(
        kubectl_json(ctx, "get", "clusterrolebindings"), kubectl_json(ctx, "get", "clusterroles"),
        kubectl_json(ctx, "get", "appprojects.argoproj.io", "-A"), kubectl_json(ctx, "get", "applications.argoproj.io", "-A"))
    res: dict = {}
    if crb and cr:
        wild = {r["metadata"]["name"] for r in cr["items"]
                if any("*" in x.get("verbs", []) and "*" in x.get("resources", []) for x in r.get("rules") or [])}
        res["admin_bindings"] = [
            {"binding": b["metadata"]["name"], "role": b["roleRef"]["name"],
             "subjects": [f"{s['kind']}:{s.get('namespace', '')}/{s['name']}" for s in b.get("subjects") or []][:5]}
            for b in crb["items"] if b["roleRef"]["name"] in wild]
    if projects:
        res["argo_projects"] = [
            {"project": p["metadata"]["name"], "wildcard_destination": any(d.get("server") == "*" or d.get("name") == "*" or d.get("namespace") == "*" for d in p["spec"].get("destinations", [])),
             "wildcard_sources": "*" in p["spec"].get("sourceRepos", []),
             "all_cluster_resources": any(x.get("kind") == "*" for x in p["spec"].get("clusterResourceWhitelist", []))}
            for p in projects["items"]]
    if apps:
        res["argo_apps_risky"] = [
            {"app": a["metadata"]["name"], "project": a["spec"].get("project"), "revision": a["spec"].get("source", {}).get("targetRevision")}
            for a in apps["items"] if a["spec"].get("project") == "default" or a["spec"].get("source", {}).get("targetRevision") in ("HEAD", "main", "master", None)][:CAP]
    return res


async def scan(contexts: list[str], paths: list[str], out: Path, timeout: int) -> dict:
    todo = jobs(contexts, paths, out)
    results = await asyncio.gather(*(run(argv, timeout) for _, _, argv in todo), *(rbac_and_argo(c) for c in contexts))
    digest = {"clusters": {}, "repos": {}, "not_checked": []}
    for (kind, label, argv), (rc, tail) in zip(todo, results):
        f = outfile(argv)
        # trivy exits non-zero only on errors here (no --exit-code); kubescape returns 0 unless a threshold is set
        if rc != 0 or not f.exists() or f.stat().st_size == 0:
            digest["not_checked"].append({"item": label, "reason": tail.strip().splitlines()[-1] if tail.strip() else f"exit {rc}"})
            continue
        key = label.split()[-1]
        bucket = digest["clusters"] if key in contexts else digest["repos"]
        bucket.setdefault(key, {})[label.rsplit(" ", 1)[0]] = REDUCERS[kind](json.loads(f.read_text()))
    for c, extra in zip(contexts, results[len(todo):]):
        digest["clusters"].setdefault(c, {})["rbac_and_argo"] = extra
    digest["not_checked"].append({"item": "node and control-plane CIS checks", "reason": "need a privileged node-collector pod; the audit identity is read-only"})
    digest["not_checked"].append({"item": "git history", "reason": "secrets removed from history are not scanned"})
    return digest
