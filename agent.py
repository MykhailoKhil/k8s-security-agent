"""Read-only Kubernetes security audit. Configured only by env vars (see .env.example).
Stage 1 (Python, parallel): run scanners, reduce to a digest. Stage 2 (one LLM call, no tools): triage -> findings.json. Stage 3: HTML."""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from render import render
from scan import scan
from triage import extract_json, triage


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

    r = await triage(digest_json, contexts + paths)
    text = r["text"]
    print(f"llm done in {time.time() - t0:.0f}s total, cost ${r['cost_usd']:.3f}", flush=True)

    try:
        data = extract_json(text)
    except ValueError:
        (out / "llm-raw.txt").write_text(text)
        sys.exit(f"model did not return JSON; raw saved to {out / 'llm-raw.txt'}")
    data["meta"] = {"cost_usd": round(r["cost_usd"], 3), "seconds": round(time.time() - t0)}  # set by code, not the model
    (out / "findings.json").write_text(json.dumps(data, indent=2))
    (out / "report.html").write_text(render(data))
    print(f"report: {out / 'report.html'}")


asyncio.run(main())
