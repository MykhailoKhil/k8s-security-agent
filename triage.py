"""One LLM triage call: digest in, findings JSON out. No tools, no shell. Shared by agent.py and evals."""
import json
import os
import time

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

SCHEMA = """{"summary": "2-4 sentences", "targets": [str],
 "frameworks": [{"name": str, "passed": int, "failed": int, "skipped": int, "score": number|null}],
 "findings": [{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": str, "resource": str, "controls": [str], "evidence": str, "fix": str, "confidence": "high|medium|low"}],
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
- confidence: "high" = the digest shows it directly (a failed control, a CVE with a version, a named binding); "medium" = you inferred severity or impact from context (for example judged it an expected platform default); "low" = the digest is partial, a scanner failed, or you are extrapolating. Never use "high" for a claim the digest does not show.
- not_checked: copy the digest's not_checked and add anything you could not assess."""


FINDING_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["summary", "targets", "frameworks", "findings", "not_checked"],
    "properties": {
        "summary": {"type": "string"},
        "targets": {"type": "array", "items": {"type": "string"}},
        "frameworks": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["name", "passed", "failed", "skipped", "score"],
            "properties": {"name": {"type": "string"}, "passed": {"type": "integer"}, "failed": {"type": "integer"},
                           "skipped": {"type": "integer"}, "score": {"type": ["number", "null"]}}}},
        "findings": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["severity", "title", "resource", "controls", "evidence", "fix", "confidence"],
            "properties": {"severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}, "title": {"type": "string"}, "resource": {"type": "string"},
                           "controls": {"type": "array", "items": {"type": "string"}}, "evidence": {"type": "string"}, "fix": {"type": "string"},
                           "confidence": {"enum": ["high", "medium", "low"]}}}},
        "not_checked": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["item", "reason"],
            "properties": {"item": {"type": "string"}, "reason": {"type": "string"}}}},
    },
}


def extract_json(text: str) -> dict:
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


async def triage(digest_json: str, targets: list[str]) -> dict:
    """Returns {"text": raw reply, "cost_usd": float, "seconds": float}."""
    opts = ClaudeAgentOptions(
        system_prompt=SYSTEM,
        tools=[],                                  # no tools: the model cannot touch the cluster or the shell
        setting_sources=[],                        # do not load user CLAUDE.md/skills (tokens)
        extra_args={"strict-mcp-config": None},    # do not load user MCP servers (tokens)
        max_turns=3,                               # structured output may take a 2nd turn to return the object
        output_format={"type": "json_schema", "schema": FINDING_SCHEMA},
        effort=os.environ.get("EFFORT", "low"),
        model=os.environ.get("CLAUDE_MODEL") or "claude-sonnet-5-5",
    )
    t0, text, cost, turns, usage = time.time(), "", 0.0, 0, {}
    async for m in query(prompt=f"Targets: {targets}\nDigest:\n{digest_json}", options=opts):
        if isinstance(m, ResultMessage):
            # structured_output is the schema-validated object; fall back to the text reply
            text = json.dumps(m.structured_output) if m.structured_output else (m.result or "")
            cost, turns, usage = m.total_cost_usd or 0.0, m.num_turns, m.usage or {}
    return {"text": text, "cost_usd": cost, "seconds": time.time() - t0, "turns": turns,
            "output_tokens": usage.get("output_tokens"), "input_tokens": usage.get("input_tokens")}
