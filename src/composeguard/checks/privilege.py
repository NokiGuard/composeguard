"""Process-privilege and namespace checks (CG001-CG009, CG011)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

# --- CG001 / CG002 / CG003 / CG005: privilege & namespace flags -------------


def _check_privileged(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("privileged") is True:
        return [
            Finding(
                "CG001",
                Severity.CRITICAL,
                "privileged: true disables all isolation — trivial full host compromise",
                name,
            )
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

# Severity for caps in cap_add, graded by how directly the cap converts to
# host compromise. Anything not listed is ignored (low risk caps like
# NET_BIND_SERVICE, CHOWN — common and usually fine).
_CAP_SEVERITY: dict[str, Severity] = {
    # Effectively root on the host: SYS_ADMIN is the kitchen-sink cap; ALL
    # includes it; SYS_MODULE loads arbitrary kernel code.
    "SYS_ADMIN": Severity.CRITICAL,
    "ALL": Severity.CRITICAL,
    "SYS_MODULE": Severity.CRITICAL,
    # Powerful subsystem caps with known escape or takeover paths.
    "NET_ADMIN": Severity.HIGH,
    "SYS_PTRACE": Severity.HIGH,
    "SYS_RAWIO": Severity.HIGH,
    "SYS_BOOT": Severity.HIGH,
    "MAC_ADMIN": Severity.HIGH,
    "MAC_OVERRIDE": Severity.HIGH,
    # DAC_READ_SEARCH enables the classic open_by_handle_at host-file-read
    # escape ("shocker"); BPF allows loading eBPF programs (kernel surface).
    "DAC_READ_SEARCH": Severity.HIGH,
    "BPF": Severity.HIGH,
    # Notable but narrower.
    "SYS_TIME": Severity.MEDIUM,
    "DAC_OVERRIDE": Severity.MEDIUM,
    "AUDIT_CONTROL": Severity.MEDIUM,
    "AUDIT_WRITE": Severity.MEDIUM,
    "PERFMON": Severity.MEDIUM,
    "SYS_CHROOT": Severity.MEDIUM,
    "SETUID": Severity.MEDIUM,
    "SETGID": Severity.MEDIUM,
    "NET_RAW": Severity.MEDIUM,
    "CHECKPOINT_RESTORE": Severity.MEDIUM,
    # Info-leak only (kernel log exposes pointers).
    "SYSLOG": Severity.LOW,
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


# --- CG070 / CG071 / CG072: more shared namespaces (overflow band) ----------


def _check_cgroup(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("cgroup") == "host":
        return [
            Finding(
                "CG070",
                Severity.HIGH,
                "cgroup: host joins the host cgroup namespace (resource controls exposed)",
                name,
            )
        ]
    return []


def _check_uts(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("uts") == "host":
        return [
            Finding(
                "CG071",
                Severity.MEDIUM,
                "uts: host shares the host UTS namespace (hostname/domain writable)",
                name,
            )
        ]
    return []


def _check_container_namespace_sharing(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Flag network_mode / pid joined to another container's namespace."""
    out: list[Finding] = []
    for field in ("network_mode", "pid"):
        value = svc.get(field)
        if isinstance(value, str) and value.startswith(("container:", "service:")):
            out.append(
                Finding(
                    "CG072",
                    Severity.MEDIUM,
                    f"{field}: {value!r} shares another container's namespace "
                    "(lateral movement between services)",
                    name,
                )
            )
    return out


# --- CG073: dangerous sysctls -------------------------------------------------

# Docker only accepts namespaced sysctls (net.*, IPC kernel.msg*/sem/shm*,
# fs.mqueue.*), so escape-relevant kernel.* keys can never appear in a working
# compose file. The flaggable set is deliberately tiny.
_DANGEROUS_SYSCTLS: dict[str, str] = {
    "net.ipv4.ip_unprivileged_port_start": "0",
    "net.ipv4.ip_forward": "1",
}


def _iter_sysctls(sysctls: object) -> list[tuple[str, str]]:
    if isinstance(sysctls, list):
        return [
            tuple(item.split("=", 1))  # type: ignore[misc]
            for item in sysctls
            if isinstance(item, str) and "=" in item
        ]
    if isinstance(sysctls, dict):
        return [(str(k), str(v)) for k, v in sysctls.items()]
    return []


def _check_sysctls(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for key, value in _iter_sysctls(svc.get("sysctls")):
        k, v = key.strip(), value.strip()
        if _DANGEROUS_SYSCTLS.get(k) == v:
            out.append(
                Finding(
                    "CG073",
                    Severity.LOW,
                    f"sysctl {k}={v} weakens network hardening",
                    name,
                )
            )
    return out


CHECKS: tuple[CheckFn, ...] = (
    _check_privileged,
    _check_namespaces,
    _check_capabilities,
    _check_cap_drop,
    _check_no_new_privs,
    _check_read_only,
    _check_user,
    _check_userns,
    _check_cgroup,
    _check_uts,
    _check_container_namespace_sharing,
    _check_sysctls,
)
