from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB hard cap on input size

# Used in the CG040 port-binding check. Stored as a constant with a localized
# bandit suppression so the rest of the file stays clean.
_BIND_ALL_INTERFACES = "0.0.0.0"  # nosec B104  # noqa: S104


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    service: str | None = None


# --- file loading -----------------------------------------------------------


def _read_compose(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"File too large ({size} bytes; limit {MAX_FILE_BYTES}).")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Compose root must be a mapping.")
    return data


def analyze_file(path: Path) -> list[Finding]:
    """Analyze a docker-compose file. Pure-stdlib + safe_load; no network, no shell."""
    data = _read_compose(path)
    services = data.get("services") or {}
    if not isinstance(services, dict):
        return []

    findings: list[Finding] = []
    for name, raw in services.items():
        if not isinstance(raw, dict):
            continue
        findings.extend(_check_service(str(name), raw))
    return findings


def _check_service(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    out.extend(_check_privileged(name, svc))
    out.extend(_check_namespaces(name, svc))
    out.extend(_check_capabilities(name, svc))
    out.extend(_check_cap_drop(name, svc))
    out.extend(_check_no_new_privs(name, svc))
    out.extend(_check_read_only(name, svc))
    out.extend(_check_user(name, svc))
    out.extend(_check_userns(name, svc))
    out.extend(_check_image(name, svc))
    out.extend(_check_volumes(name, svc))
    out.extend(_check_devices(name, svc))
    out.extend(_check_env_secrets(name, svc))
    out.extend(_check_ports(name, svc))
    out.extend(_check_resource_limits(name, svc))
    out.extend(_check_security_opt_unconfined(name, svc))
    return out


# --- CG001 / CG002 / CG003 / CG005: privilege & namespace flags -------------


def _check_privileged(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("privileged") is True:
        return [
            Finding("CG001", Severity.HIGH, "privileged: true grants near-root host access", name)
        ]
    return []


def _check_namespaces(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    if svc.get("network_mode") == "host":
        out.append(
            Finding("CG002", Severity.HIGH, "network_mode: host bypasses network isolation", name)
        )
    if svc.get("pid") == "host":
        out.append(Finding("CG003", Severity.HIGH, "pid: host shares the host PID namespace", name))
    if svc.get("ipc") == "host":
        out.append(Finding("CG005", Severity.HIGH, "ipc: host shares the host IPC namespace", name))
    return out


# --- CG004 / CG011: dangerous Linux capabilities ----------------------------

# Severity for caps in cap_add. Anything not listed is ignored (low risk caps
# like NET_BIND_SERVICE, CHOWN — common and usually fine).
_CAP_SEVERITY: dict[str, Severity] = {
    # Effectively root.
    "SYS_ADMIN": Severity.HIGH,
    "ALL": Severity.HIGH,
    # Powerful subsystem caps.
    "NET_ADMIN": Severity.HIGH,
    "SYS_PTRACE": Severity.HIGH,
    "SYS_MODULE": Severity.HIGH,
    "SYS_RAWIO": Severity.HIGH,
    "SYS_BOOT": Severity.HIGH,
    "MAC_ADMIN": Severity.HIGH,
    "MAC_OVERRIDE": Severity.HIGH,
    # Notable but narrower.
    "SYS_TIME": Severity.MEDIUM,
    "DAC_READ_SEARCH": Severity.MEDIUM,
    "DAC_OVERRIDE": Severity.MEDIUM,
    "AUDIT_CONTROL": Severity.MEDIUM,
    "AUDIT_WRITE": Severity.MEDIUM,
}


def _check_capabilities(name: str, svc: dict[str, Any]) -> list[Finding]:
    caps = svc.get("cap_add") or []
    if not isinstance(caps, list):
        return []
    out: list[Finding] = []
    for c in caps:
        if not isinstance(c, str):
            continue
        norm = c.upper().removeprefix("CAP_")
        sev = _CAP_SEVERITY.get(norm)
        if sev is not None:
            out.append(Finding("CG004", sev, f"cap_add: {c!r} grants a powerful capability", name))
    return out


def _check_cap_drop(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Defense-in-depth: when cap_add is used, expect cap_drop: [ALL]."""
    cap_add = svc.get("cap_add") or []
    if not isinstance(cap_add, list) or not cap_add:
        return []
    cap_drop = svc.get("cap_drop") or []
    if isinstance(cap_drop, list):
        dropped = {str(c).upper().removeprefix("CAP_") for c in cap_drop if isinstance(c, str)}
        if "ALL" in dropped:
            return []
    return [
        Finding(
            "CG011",
            Severity.LOW,
            "cap_add is used without cap_drop: [ALL] (defense-in-depth)",
            name,
        )
    ]


# --- CG006 / CG007: hardening flags missing ---------------------------------


def _has_no_new_privs(svc: dict[str, Any]) -> bool:
    opts = svc.get("security_opt") or []
    if not isinstance(opts, list):
        return False
    for o in opts:
        if not isinstance(o, str):
            continue
        normalized = o.replace(" ", "").lower()
        if normalized in {"no-new-privileges:true", "no-new-privileges=true"}:
            return True
    return False


def _check_no_new_privs(name: str, svc: dict[str, Any]) -> list[Finding]:
    if _has_no_new_privs(svc):
        return []
    return [
        Finding(
            "CG006",
            Severity.LOW,
            "missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)",
            name,
        )
    ]


def _check_read_only(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("read_only") is True:
        return []
    return [Finding("CG007", Severity.LOW, "read_only filesystem not enabled", name)]


# --- CG008 / CG009: identity & user namespace ------------------------------


def _check_user(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Flag explicit `user: root` / `user: 0` / `user: 0:0`."""
    user = svc.get("user")
    if user is None:
        return []
    user_str = str(user).strip()
    uid = user_str.split(":", 1)[0]
    if uid in {"root", "0"}:
        return [
            Finding(
                "CG008",
                Severity.HIGH,
                f"user is set to root ({user_str!r}) — drop privileges with a non-zero UID",
                name,
            )
        ]
    return []


def _check_userns(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("userns_mode") == "host":
        return [
            Finding(
                "CG009",
                Severity.HIGH,
                "userns_mode: host disables user-namespace remapping (UID 0 maps to host root)",
                name,
            )
        ]
    return []


# --- CG010: image pinning ---------------------------------------------------


def _check_image(name: str, svc: dict[str, Any]) -> list[Finding]:
    image = svc.get("image")
    if not isinstance(image, str):
        return []
    if "@sha256:" in image:
        return []
    if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
        return [
            Finding("CG010", Severity.MEDIUM, f"image {image!r} is unpinned (use a digest)", name)
        ]
    return []


# --- CG020 / CG021: dangerous mounts ----------------------------------------

# Sensitive host paths. Tuple is (rw_severity, ro_severity).
_SENSITIVE_PATHS: dict[str, tuple[Severity, Severity]] = {
    # rw or ro of these can leak/clobber host identity files.
    "/": (Severity.HIGH, Severity.HIGH),
    "/etc": (Severity.HIGH, Severity.HIGH),
    "/root": (Severity.HIGH, Severity.HIGH),
    # Kernel/system surfaces — rw is dangerous, ro is concerning.
    "/boot": (Severity.HIGH, Severity.MEDIUM),
    "/sys": (Severity.HIGH, Severity.MEDIUM),
    "/proc": (Severity.HIGH, Severity.MEDIUM),
    "/dev": (Severity.HIGH, Severity.MEDIUM),
    "/usr": (Severity.HIGH, Severity.MEDIUM),
    "/lib": (Severity.HIGH, Severity.MEDIUM),
    "/lib64": (Severity.HIGH, Severity.MEDIUM),
    "/sbin": (Severity.HIGH, Severity.MEDIUM),
    "/bin": (Severity.HIGH, Severity.MEDIUM),
    # User data — broad impact, lower per-mount risk.
    "/var": (Severity.MEDIUM, Severity.LOW),
    "/home": (Severity.MEDIUM, Severity.LOW),
}


def _parse_volume(vol: object) -> tuple[str | None, str | None, str | None]:
    """Return (source, target, mode) for short or long compose volume forms."""
    if isinstance(vol, str):
        parts = vol.split(":")
        src = parts[0] if len(parts) >= 1 else None
        tgt = parts[1] if len(parts) >= 2 else None
        mode = parts[2] if len(parts) >= 3 else None
        return src, tgt, mode
    if isinstance(vol, dict):
        src = vol.get("source") if isinstance(vol.get("source"), str) else None
        tgt = vol.get("target") if isinstance(vol.get("target"), str) else None
        mode = "ro" if vol.get("read_only") is True else "rw"
        return src, tgt, mode
    return None, None, None


def _check_volumes(name: str, svc: dict[str, Any]) -> list[Finding]:
    raw = svc.get("volumes") or []
    if not isinstance(raw, list):
        return []
    # Match longest path prefix first so '/etc/foo' matches '/etc' before '/'.
    sorted_paths = sorted(_SENSITIVE_PATHS.items(), key=lambda kv: -len(kv[0]))
    out: list[Finding] = []
    for vol in raw:
        src, _tgt, mode = _parse_volume(vol)
        if src == "/var/run/docker.sock":
            out.append(
                Finding("CG020", Severity.HIGH, "docker.sock mount enables container escape", name)
            )
            continue
        if not src or not src.startswith("/"):
            continue
        for sensitive_path, (rw_sev, ro_sev) in sorted_paths:
            if src == sensitive_path or src.startswith(sensitive_path + "/"):
                ro = mode in {"ro", "readonly"}
                sev = ro_sev if ro else rw_sev
                qualifier = "read-only" if ro else "writable"
                out.append(
                    Finding(
                        "CG021",
                        sev,
                        f"{qualifier} mount of sensitive host path {src!r}",
                        name,
                    )
                )
                break
    return out


# --- CG022: device passthrough ----------------------------------------------


def _check_devices(name: str, svc: dict[str, Any]) -> list[Finding]:
    raw = svc.get("devices") or []
    if not isinstance(raw, list):
        return []
    out: list[Finding] = []
    for dev in raw:
        host_dev: str | None = None
        if isinstance(dev, str):
            host_dev = dev.split(":", 1)[0].strip() or None
        elif isinstance(dev, dict):
            src = dev.get("source")
            host_dev = src if isinstance(src, str) else None
        if host_dev and host_dev.startswith("/dev/"):
            out.append(
                Finding(
                    "CG022",
                    Severity.HIGH,
                    f"host device {host_dev!r} passed into container — kernel surface exposure",
                    name,
                )
            )
    return out


# --- CG030: secrets in environment variables --------------------------------

_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"
)


def _iter_env(env: object) -> Iterator[tuple[str, str]]:
    """Yield (key, value) pairs from compose env (list or dict form)."""
    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                yield k, v
    elif isinstance(env, dict):
        for k, v in env.items():
            if isinstance(k, str):
                yield k, "" if v is None else str(v)


def _check_env_secrets(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for k, v in _iter_env(svc.get("environment")):
        if not _SECRET_KEY_PATTERN.search(k):
            continue
        stripped = v.strip()
        if not stripped or stripped.startswith("${"):
            continue
        out.append(
            Finding(
                "CG030",
                Severity.MEDIUM,
                f"env var {k!r} looks like a secret with an inline value (use secrets/.env)",
                name,
            )
        )
    return out


# --- CG040: port binding ----------------------------------------------------


def _port_host_ip(port: object) -> str | None:
    """Return host_ip for a port spec, or None if unspecified (= 0.0.0.0)."""
    if isinstance(port, str):
        parts = port.split(":")
        if len(parts) == 3:
            return parts[0]
        return None
    if isinstance(port, dict):
        ip = port.get("host_ip")
        return ip if isinstance(ip, str) else None
    return None


def _check_ports(name: str, svc: dict[str, Any]) -> list[Finding]:
    raw = svc.get("ports") or []
    if not isinstance(raw, list):
        return []
    out: list[Finding] = []
    for p in raw:
        ip = _port_host_ip(p)
        if ip is None or ip == _BIND_ALL_INTERFACES:
            out.append(
                Finding(
                    "CG040",
                    Severity.MEDIUM,
                    f"port {p!r} published on all interfaces (use a '127.0.0.1:' prefix)",
                    name,
                )
            )
    return out


# --- CG050: resource limits -------------------------------------------------


def _check_resource_limits(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("mem_limit") or svc.get("cpus"):
        return []
    deploy = svc.get("deploy")
    if isinstance(deploy, dict):
        resources = deploy.get("resources")
        if isinstance(resources, dict):
            limits = resources.get("limits")
            if isinstance(limits, dict) and (limits.get("memory") or limits.get("cpus")):
                return []
    return [
        Finding(
            "CG050",
            Severity.LOW,
            "no memory or CPU limit set (one runaway container can OOM the host)",
            name,
        )
    ]


# --- CG060: AppArmor / seccomp disabled -------------------------------------


def _check_security_opt_unconfined(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Flag security_opt: ['apparmor=unconfined'] or ['seccomp=unconfined']."""
    opts = svc.get("security_opt") or []
    if not isinstance(opts, list):
        return []
    out: list[Finding] = []
    for o in opts:
        if not isinstance(o, str):
            continue
        # Compose accepts both 'key=value' and 'key:value'. Normalize.
        normalized = o.strip().replace("=", ":").lower()
        if normalized == "apparmor:unconfined":
            out.append(
                Finding("CG060", Severity.HIGH, f"security_opt disables AppArmor ({o!r})", name)
            )
        elif normalized == "seccomp:unconfined":
            out.append(
                Finding(
                    "CG060",
                    Severity.HIGH,
                    f"security_opt disables the seccomp filter ({o!r})",
                    name,
                )
            )
    return out
