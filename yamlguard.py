"""Structural guard for remediation edits.

A patched manifest may only ADD allow-listed hardening to a workload's pod spec. Everything else must be identical to the
original after parsing: container names/order, images, commands, args, env, ports, labels, replicas, other documents.
Line-based deny-lists miss flow-style YAML (`- {name: x, image: evil}`), so this works on the parsed documents."""
import copy

import yaml

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
RESOURCE_KEYS = {"cpu", "memory", "ephemeral-storage"}
SENSITIVE_MOUNTS = ("/etc", "/proc", "/sys", "/dev", "/bin", "/sbin", "/usr", "/lib", "/var/run/secrets", "/run/secrets", "/var/run/docker.sock")


def pod_spec(doc) -> dict | None:
    if not isinstance(doc, dict):
        return None
    kind, spec = doc.get("kind"), doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    if kind in WORKLOAD_KINDS:
        return (spec.get("template") or {}).get("spec")
    return None


def posint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def seccomp_ok(v) -> bool:
    return isinstance(v, dict) and set(v) <= {"type", "localhostProfile"} and (v.get("type") == "RuntimeDefault" or (v.get("type") == "Localhost" and isinstance(v.get("localhostProfile"), str)))


def apparmor_ok(v) -> bool:
    return isinstance(v, dict) and v.get("type") == "RuntimeDefault" and set(v) == {"type"}


# keys of a securityContext that may be added, with the only values that are accepted
SC_VALID = {"runAsNonRoot": lambda v: v is True, "allowPrivilegeEscalation": lambda v: v is False, "readOnlyRootFilesystem": lambda v: v is True,
            "privileged": lambda v: v is False, "runAsUser": posint, "runAsGroup": posint, "seccompProfile": seccomp_ok, "appArmorProfile": apparmor_ok}


def sc_problem(b: dict | None, a: dict | None, pod_level: bool, where: str) -> str | None:
    b, a = b or {}, a or {}
    if not isinstance(a, dict):
        return f"{where}.securityContext is not a mapping"
    valid = dict(SC_VALID, **({"fsGroup": posint} if pod_level else {}))
    for k in b:
        if k not in a:
            return f"{where}.securityContext removes `{k}`"
    for k, v in a.items():
        if k == "capabilities":
            bc = b.get("capabilities") or {}
            if not isinstance(v, dict) or not isinstance(v.get("drop", []), list) or any(not isinstance(x, str) for x in v.get("drop", [])):
                return f"{where}.securityContext.capabilities is not a plain drop list"
            if v.get("add") != bc.get("add") or set(v) - {"drop", "add"} or not set(bc.get("drop", [])) <= set(v.get("drop", [])):
                return f"{where}.securityContext.capabilities may only add to `drop`"
        elif k in b:
            if v != b[k]:
                return f"{where}.securityContext changes the existing `{k}`"
        elif k in valid:
            if not valid[k](v):
                return f"{where}.securityContext.{k}: value not allowed"
        else:
            return f"{where}.securityContext adds `{k}`, which is not an allowed hardening key"
    return None


def res_problem(b: dict | None, a: dict | None, where: str) -> str | None:
    b, a = b or {}, a or {}
    if not isinstance(a, dict):
        return f"{where}.resources is not a mapping"
    for k, v in a.items():
        if k not in ("requests", "limits"):
            if v != b.get(k):
                return f"{where}.resources changes `{k}`"
            continue
        if not isinstance(v, dict) or set(v) - RESOURCE_KEYS or any(isinstance(x, bool) or not isinstance(x, (str, int, float)) for x in v.values()):
            return f"{where}.resources.{k} may only set cpu, memory or ephemeral-storage"
        bk = b.get(k) or {}
        if any(r not in v or v[r] != bk[r] for r in bk):
            return f"{where}.resources.{k} changes or removes an existing value"
    return None if all(k in a for k in b) else f"{where}.resources removes `{[k for k in b if k not in a][0]}`"


def volume_problem(b: list | None, a: list | None) -> str | None:
    b, a = b or [], a or []
    if not isinstance(a, list):
        return "volumes is not a list"
    names_b = {v.get("name"): v for v in b}
    for v in a:
        if not isinstance(v, dict):
            return "volumes contains a non-mapping"
        if v.get("name") in names_b:
            if v != names_b[v["name"]]:
                return f"changes the existing volume `{v['name']}`"
        elif set(v) != {"name", "emptyDir"} or not (v["emptyDir"] is None or (isinstance(v["emptyDir"], dict) and set(v["emptyDir"]) <= {"medium", "sizeLimit"} and v["emptyDir"].get("medium", "") in ("", "Memory"))):
            return f"adds volume `{v.get('name')}` that is not a plain emptyDir"
    if not set(names_b) <= {v.get("name") for v in a}:
        return "removes a volume"
    return None


def mount_problem(b: list | None, a: list | None, empty_dirs: set, where: str) -> str | None:
    b, a = b or [], a or []
    if not isinstance(a, list):
        return f"{where}.volumeMounts is not a list"
    existing = [m for m in a if m in b]
    if len(existing) != len(b):
        return f"{where}.volumeMounts changes or removes an existing mount"
    for m in (m for m in a if m not in b):
        p = m.get("mountPath") if isinstance(m, dict) else None
        if not isinstance(m, dict) or set(m) - {"name", "mountPath", "readOnly", "subPath"} or m.get("name") not in empty_dirs or not isinstance(p, str) or not p.startswith("/"):
            return f"{where}.volumeMounts adds a mount that is not a path on an emptyDir volume"
        if p == "/" or any(p == s or p.startswith(s + "/") for s in SENSITIVE_MOUNTS) or ".." in p.split("/"):
            return f"{where}.volumeMounts mounts over a sensitive path: {p}"
    return None


def first_diff(b, a, path="") -> str | None:
    if type(b) is not type(a):
        return path or "/"
    if isinstance(b, dict):
        for k in sorted(set(b) | set(a), key=str):
            if k not in b or k not in a:
                return f"{path}/{k}"
            d = first_diff(b[k], a[k], f"{path}/{k}")
            if d:
                return d
        return None
    if isinstance(b, list):
        if len(b) != len(a):
            return path or "/"
        for i, (x, y) in enumerate(zip(b, a)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    return None if b == a else path


def doc_problem(b, a) -> str | None:
    bps = pod_spec(b)
    if bps is None:
        d = first_diff(b, a)
        return f"changes a document that is not a workload ({d})" if d else None
    a = copy.deepcopy(a)
    aps = pod_spec(a)
    if not isinstance(aps, dict) or a.get("kind") != b.get("kind"):
        return "removes or restructures the pod spec"

    def restore(d_a: dict, d_b: dict, key: str):
        if key in d_b:
            d_a[key] = d_b[key]
        else:
            d_a.pop(key, None)

    if aps.get("automountServiceAccountToken") != bps.get("automountServiceAccountToken") and aps.get("automountServiceAccountToken") is not False:
        return "automountServiceAccountToken may only be set to false"
    restore(aps, bps, "automountServiceAccountToken")
    p = sc_problem(bps.get("securityContext"), aps.get("securityContext"), True, "pod")
    if p:
        return p
    restore(aps, bps, "securityContext")
    p = volume_problem(bps.get("volumes"), aps.get("volumes"))
    if p:
        return p
    empty_dirs = {v["name"] for v in (aps.get("volumes") or []) if isinstance(v, dict) and "emptyDir" in v}
    restore(aps, bps, "volumes")
    for key in ("containers", "initContainers"):
        bl, al = bps.get(key) or [], aps.get(key) or []
        if [c.get("name") for c in bl] != [c.get("name") for c in al if isinstance(c, dict)] or len(bl) != len(al):
            return f"{key}: containers were added, removed, renamed or reordered"
        for bc, ac in zip(bl, al):
            where = f"{key}[{bc.get('name')}]"
            p = (sc_problem(bc.get("securityContext"), ac.get("securityContext"), False, where) or res_problem(bc.get("resources"), ac.get("resources"), where)
                 or mount_problem(bc.get("volumeMounts"), ac.get("volumeMounts"), empty_dirs, where))
            if p:
                return p
            for k in ("securityContext", "resources", "volumeMounts"):
                restore(ac, bc, k)
    d = first_diff(b, a)
    return f"changes `{d}`, which is not an allowed hardening field" if d else None


def check_structure(before: str, after: str) -> str | None:
    """None if `after` only adds allow-listed hardening to `before`; otherwise the reason."""
    try:
        docs_b, docs_a = list(yaml.safe_load_all(before)), list(yaml.safe_load_all(after))
    except yaml.YAMLError:
        return "not valid YAML"
    if len(docs_b) != len(docs_a):
        return "the number of YAML documents changed"
    for i, (b, a) in enumerate(zip(docs_b, docs_a)):
        try:
            p = doc_problem(b, a)
        except (AttributeError, TypeError, KeyError):   # a shape this guard does not understand is not safe to accept
            p = "has a structure the safety check cannot analyse"
        if p:
            return f"document {i + 1}: {p}"
    return None
