"""Read-only Kubernetes security audit. Configured only by env vars (see .env.example).
Stage 1 (Python, parallel): run scanners, reduce to a digest. Stage 2 (one LLM call, no tools): triage -> findings.json. Stage 3: HTML."""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from render import render
from scan import scan

SCHEMA = """{"summary": "2-4 sentences", "targets": [str],
 "frameworks": [{"name": str, "passed": int, "failed": int, "skipped": int, "score": number|null}],
 "findings": [{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": str, "resource": str, "controls": [str], "evidence": str, "fix": str}],
 "not_checked": [{"item": str, "reason": str}]}"""

SYSTEM = f"""You are a Kubernetes security triage analyst. You get a JSON digest of scanner output (kubescape, trivy, RBAC/Argo checks) for clusters and repos.
Produce the audit result as ONE JSON object and nothing else (no markdown, no code fences), shape:
{SCHEMA}
Rules:
- Use only facts in the digest. In 'evidence' name a tool, control ID, resource or count ONLY if it appears in the digest; if unsure, say what the digest shows, not what you expect. Never claim a check passed unless the digest shows it. Copy framework numbers as given.
- Dedupe across tools and across clusters/repos; one finding per root cause, listing control IDs from all tools.
- Rank by severity x exploitability; at most 25 findings, most severe first. Merge many similar low items into one finding.
- Judge context: k3s-managed kube-system add-ons and node-exporter host access are expected: rate them LOW/MEDIUM and say so; do not hide them.
- Admin bindings: rate from the rbac_and_argo data (subjects, wildcard roles); say if a binding looks like a platform default.
- 'fix': a short YAML/patch or exact command; for image CVEs the target version if 'fixed' is known. Keep evidence to one sentence.
- not_checked: copy the digest's not_checked and add anything you could not assess."""


def split(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def clone(urls: list[str], dest: Path) -> list[str]:
    token = os.environ.get("GIT_TOKEN", "")
    paths = []
    for u in urls:
        target = dest / u.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
        auth = u.replace("https://", f"https://x-access-token:{token}@", 1) if token else u
        subprocess.run(["git", "clone", "--depth", "1", "-q", auth, str(target)], check=True)
        paths.append(str(target))
    return paths


def extract_json(text: str) -> dict:
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


async def main():
    t0 = time.time()
    contexts, paths = split("K8S_CONTEXTS"), split("AUDIT_PATHS")
    out = Path(os.environ.get("OUT_DIR", "out")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    paths += clone(split("AUDIT_REPOS"), out / "repos")
    if not (contexts or paths):
        sys.exit("set K8S_CONTEXTS and/or AUDIT_PATHS/AUDIT_REPOS (see .env.example)")

    digest = await scan(contexts, paths, out, int(os.environ.get("SCAN_TIMEOUT", "900")))
    digest_json = json.dumps(digest, separators=(",", ":"))
    (out / "digest.json").write_text(digest_json)
    print(f"scanned in {time.time() - t0:.0f}s, digest {len(digest_json) // 1000}KB", flush=True)

    opts = ClaudeAgentOptions(
        system_prompt=SYSTEM,
        tools=[],                                  # no tools: the model cannot touch the cluster or the shell
        setting_sources=[],                        # do not load user CLAUDE.md/skills (tokens)
        extra_args={"strict-mcp-config": None},    # do not load user MCP servers (tokens)
        max_turns=1,
        effort=os.environ.get("EFFORT", "low"),
        model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5"),
    )
    text = ""
    async for m in query(prompt=f"Targets: {contexts + paths}\nDigest:\n{digest_json}", options=opts):
        if isinstance(m, ResultMessage):
            text = m.result or ""
            print(f"llm done in {time.time() - t0:.0f}s total, cost ${m.total_cost_usd or 0:.3f}", flush=True)

    try:
        data = extract_json(text)
    except ValueError:
        (out / "llm-raw.txt").write_text(text)
        sys.exit(f"model did not return JSON; raw saved to {out / 'llm-raw.txt'}")
    (out / "findings.json").write_text(json.dumps(data, indent=2))
    (out / "report.html").write_text(render(data))
    print(f"report: {out / 'report.html'}")


asyncio.run(main())
