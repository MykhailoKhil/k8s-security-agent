"""Safe cloning of AUDIT_REPOS: https only, no credentials in URLs, the token never in argv, config or logs, and the
target directory can never leave the repos folder."""
import base64
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")   # no '.', '..' or leading dot/dash
TOKEN_HOSTS = {"github.com"}                                  # the only host that ever receives GIT_TOKEN


class CloneError(Exception):
    """Message is safe to print: it never contains the token."""


def parse_url(url: str) -> tuple[str, str]:
    """Returns (host, directory name) or raises CloneError."""
    u = urlsplit(url.strip())
    if u.scheme != "https" or not u.hostname:
        raise CloneError("AUDIT_REPOS entries must be https:// URLs")
    if u.username or u.password or "@" in u.netloc:
        raise CloneError("AUDIT_REPOS URLs must not contain credentials; use GIT_TOKEN")
    name = u.path.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    if not NAME_RE.match(name):
        raise CloneError(f"cannot derive a safe directory name from {u.hostname}{u.path[:60]!r}")
    return u.hostname.lower(), name


def git_env(host: str, token: str) -> dict:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https", "GIT_CONFIG_NOSYSTEM": "1"}
    if token and host in TOKEN_HOSTS:   # passed through the environment: not in argv (ps), not in .git/config, not in a traceback
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=f"http.https://{host}/.extraheader", GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {basic}")
    return env


def clone(urls: list[str], dest: Path, token: str = "", run=subprocess.run) -> list[str]:
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    paths = []
    for u in urls:
        host, name = parse_url(u)
        target = dest / name
        if target.resolve().parent != dest:          # belt and braces: never remove or write outside the repos folder
            raise CloneError("clone target escapes the repos directory")
        shutil.rmtree(target, ignore_errors=True)    # our own scratch dir; a persisted OUT_DIR must not break the next clone
        try:
            run(["git", "clone", "--depth", "1", "--no-tags", "-q", "--", u.strip(), str(target)], check=True, capture_output=True, text=True, env=git_env(host, token), timeout=600)
        except subprocess.CalledProcessError as e:
            msg = (e.stderr or "").strip().splitlines()[-1:] or ["git clone failed"]
            raise CloneError(f"git clone of {host}/{name} failed: {scrub(msg[0], token)}") from None   # `from None`: no traceback with the command
        except subprocess.TimeoutExpired:
            raise CloneError(f"git clone of {host}/{name} timed out") from None
        paths.append(str(target))
    return paths


def scrub(text: str, token: str) -> str:
    for secret in filter(None, (token, base64.b64encode(f"x-access-token:{token}".encode()).decode() if token else "")):
        text = text.replace(secret, "<redacted>")
    return text[:200]
