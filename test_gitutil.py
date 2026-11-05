"""Offline tests for safe cloning (fake `git`, no network)."""
import base64
import subprocess
import tempfile
from pathlib import Path

from gitutil import CloneError, clone, git_env, parse_url, scrub

TOKEN = "ghp_TOPSECRET1234567890"
B64 = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()

assert parse_url("https://github.com/acme/app.git") == ("github.com", "app") and parse_url("https://github.com/acme/app/") == ("github.com", "app")
assert parse_url("https://GitLab.example.com/a/b.c_d-e") == ("gitlab.example.com", "b.c_d-e")
for bad in ["http://github.com/a/b", "git@github.com:a/b.git", "ssh://git@github.com/a/b", "file:///etc", "ext::sh -c id", "/local/path", "https://user:pw@github.com/a/b", "https://x@github.com/a/b",
            "https://github.com/a/..", "https://github.com/a/.", "https://github.com/a/../..", "https://github.com/a/.hidden", "https://github.com/a/-rf", "https://github.com/a/b c", "https://github.com/", "https://",
            "https://github.com/a/" + "x" * 150, "https://github.com/a/b%2f..", "-https://github.com/a/b"]:
    try:
        parse_url(bad)
        raise SystemExit(f"should be rejected: {bad}")
    except CloneError:
        pass

# the token travels only in the environment, only to github.com
e = git_env("github.com", TOKEN)
assert TOKEN not in str(e.get("GIT_CONFIG_KEY_0")) and B64 in e["GIT_CONFIG_VALUE_0"] and e["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader" and e["GIT_ALLOW_PROTOCOL"] == "https"
assert "GIT_CONFIG_VALUE_0" not in git_env("evil.example.com", TOKEN) and "GIT_CONFIG_VALUE_0" not in git_env("github.com", "")


class Fake:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.fail:
            raise self.fail
        Path(argv[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, "", "")


with tempfile.TemporaryDirectory() as t:
    dest = Path(t) / "repos"
    f = Fake()
    out = clone(["https://github.com/acme/app", "https://other.example.com/x/lib.git"], dest, TOKEN, run=f)
    assert [Path(p).name for p in out] == ["app", "lib"] and all(Path(p).parent == dest.resolve() for p in out)
    argv0, kw0 = f.calls[0]
    assert TOKEN not in " ".join(argv0) and B64 not in " ".join(argv0) and "--" in argv0 and argv0[-2] == "https://github.com/acme/app"      # not in argv; `--` stops option injection
    assert B64 in kw0["env"]["GIT_CONFIG_VALUE_0"] and "GIT_CONFIG_VALUE_0" not in f.calls[1][1]["env"]                                     # header for github only
    # a re-run replaces its own directory
    (dest / "app" / "stale.txt").write_text("x")
    clone(["https://github.com/acme/app"], dest, TOKEN, run=Fake())
    assert not (dest / "app" / "stale.txt").exists()
    # path traversal: nothing outside the repos folder is touched, and the failure happens before any delete
    canary = Path(t) / "CANARY"
    canary.write_text("keep")
    (dest / "keep").mkdir()
    for evil in ["https://github.com/a/..", "https://github.com/a/../..", "https://github.com/a/."]:
        try:
            clone([evil], dest, TOKEN, run=Fake())
            raise SystemExit("should fail")
        except CloneError:
            pass
    assert canary.exists() and (dest / "keep").exists()
    # failures never carry the token (message, cause or context)
    err = subprocess.CalledProcessError(128, ["git", "clone", "https://x-access-token:%s@github.com/a/b" % TOKEN], stderr=f"fatal: unable to access 'https://x-access-token:{TOKEN}@github.com/a/b/': {B64} 403")
    try:
        clone(["https://github.com/acme/private"], dest, TOKEN, run=Fake(err))
        raise SystemExit("should fail")
    except CloneError as ex:
        assert TOKEN not in str(ex) and B64 not in str(ex) and "<redacted>" in str(ex) and ex.__cause__ is None and ex.__suppress_context__
    try:
        clone(["https://github.com/acme/slow"], dest, TOKEN, run=Fake(subprocess.TimeoutExpired("git", 1)))
        raise SystemExit("should fail")
    except CloneError as ex:
        assert "timed out" in str(ex) and TOKEN not in str(ex)
assert scrub(f"a {TOKEN} b {B64}", TOKEN) == "a <redacted> b <redacted>" and scrub("x" * 500, "")[:5] == "xxxxx" and len(scrub("x" * 500, "")) == 200
print("gitutil ok")
