"""One LLM triage call: digest in, findings JSON out. No tools, no shell. Shared by agent.py and evals."""
import json
import os
import time

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

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


def extract_json(text: str) -> dict:
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


async def triage(digest_json: str, targets: list[str]) -> dict:
    """Returns {"text": raw reply, "cost_usd": float, "seconds": float}."""
    opts = ClaudeAgentOptions(
        system_prompt=SYSTEM,
        tools=[],                                  # no tools: the model cannot touch the cluster or the shell
        setting_sources=[],                        # do not load user CLAUDE.md/skills (tokens)
        extra_args={"strict-mcp-config": None},    # do not load user MCP servers (tokens)
        max_turns=1,
        effort=os.environ.get("EFFORT", "low"),
        model=os.environ.get("CLAUDE_MODEL") or "claude-sonnet-5-5",
    )
    t0, text, cost = time.time(), "", 0.0
    async for m in query(prompt=f"Targets: {targets}\nDigest:\n{digest_json}", options=opts):
        if isinstance(m, ResultMessage):
            text, cost = m.result or "", m.total_cost_usd or 0.0
    return {"text": text, "cost_usd": cost, "seconds": time.time() - t0}
