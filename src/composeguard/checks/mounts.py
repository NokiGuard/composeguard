"""Dangerous mounts and device passthrough (CG020-CG029)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

# --- CG020: container-engine socket exposure ---------------------------------

# Engine control sockets, in normalized form (/var/run collapsed to /run —
# they are the same directory on modern systems). Access to any of these is
# root on the host via the engine API.
_ENGINE_SOCKETS = (
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "/run/balena-engine.sock",
    "/run/balena.sock",
)


def _normalize_host_path(src: str) -> str:
    """Collapse trailing slashes and the /var/run -> /run alias."""
    norm = src.rstrip("/") or "/"
    if norm == "/var/run" or norm.startswith("/var/run/"):
        norm = norm.removeprefix("/var")
    return norm


def _engine_socket_hit(src: str) -> str | None:
    """Return the exposed socket path if src is a socket or a parent dir of one."""
    norm = _normalize_host_path(src)
    for sock in _ENGINE_SOCKETS:
        if norm == sock or sock.startswith(norm + "/"):
            return sock
    return None


# --- CG021: sensitive host paths ----------------------------------------------

# Sensitive host paths. Tuple is (rw_severity, ro_severity).
_SENSITIVE_PATHS: dict[str, tuple[Severity, Severity]] = {
    # Writable / is the whole host; even ro leaks every credential on it.
    "/": (Severity.CRITICAL, Severity.HIGH),
    # rw or ro of these can leak/clobber host identity files.
    "/etc": (Severity.HIGH, Severity.HIGH),
    "/root": (Severity.HIGH, Severity.HIGH),
    # All containers' writable layers, volumes, and secrets live here.
    "/var/lib/docker": (Severity.HIGH, Severity.HIGH),
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
        if not src or not src.startswith("/"):
            continue
        sock = _engine_socket_hit(src)
        if sock is not None:
            out.append(
                Finding(
                    "CG020",
                    Severity.CRITICAL,
                    f"mount of {src!r} exposes the container engine socket ({sock}) — "
                    "root on the host via the engine API; read-only does not help",
                    name,
                )
            )
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

# Device prefixes graded by what access to them yields. Checked
# longest-prefix-first; unmatched /dev paths default to MEDIUM.
_DEVICE_SEVERITY: tuple[tuple[str, Severity, str], ...] = (
    # Raw memory: direct host physical-memory access.
    ("/dev/mem", Severity.CRITICAL, "raw host memory access"),
    ("/dev/kmem", Severity.CRITICAL, "raw host memory access"),
    ("/dev/port", Severity.CRITICAL, "raw I/O port access"),
    # Raw disks / volume managers: read or rewrite the host filesystem.
    ("/dev/sd", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/hd", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/nvme", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/vd", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/xvd", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/mapper/", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/dm-", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/loop", Severity.HIGH, "raw disk access — host filesystem compromise"),
    ("/dev/md", Severity.HIGH, "raw disk access — host filesystem compromise"),
    # Kernel subsystem endpoints: real attack surface, not instant compromise.
    ("/dev/kvm", Severity.MEDIUM, "hypervisor interface exposure"),
    ("/dev/net/tun", Severity.MEDIUM, "network tunnel interface exposure"),
    ("/dev/fuse", Severity.MEDIUM, "userspace filesystem interface exposure"),
    # Common peripherals (GPU, sound, serial, camera): low risk, common in
    # homelab media/IoT stacks.
    ("/dev/dri", Severity.LOW, "peripheral passthrough"),
    ("/dev/snd", Severity.LOW, "peripheral passthrough"),
    ("/dev/ttyUSB", Severity.LOW, "peripheral passthrough"),
    ("/dev/ttyACM", Severity.LOW, "peripheral passthrough"),
    ("/dev/video", Severity.LOW, "peripheral passthrough"),
    ("/dev/bus/usb", Severity.LOW, "peripheral passthrough"),
    ("/dev/usb", Severity.LOW, "peripheral passthrough"),
    ("/dev/input", Severity.LOW, "peripheral passthrough"),
    ("/dev/hidraw", Severity.LOW, "peripheral passthrough"),
)

_DEVICE_DEFAULT = (Severity.MEDIUM, "kernel surface exposure")


def _grade_device(host_dev: str) -> tuple[Severity, str]:
    for prefix, sev, why in sorted(_DEVICE_SEVERITY, key=lambda t: -len(t[0])):
        if host_dev.startswith(prefix):
            return sev, why
    return _DEVICE_DEFAULT


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
            sev, why = _grade_device(host_dev)
            out.append(
                Finding(
                    "CG022",
                    sev,
                    f"host device {host_dev!r} passed into container — {why}",
                    name,
                )
            )
    return out


# --- CG023: device cgroup rules -----------------------------------------------


def _check_device_cgroup_rules(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Flag permissive device_cgroup_rules (e.g. 'a *:* rwm').

    With the default CAP_MKNOD, an all-devices rule lets the container mknod
    and open any host block device — equivalent to raw disk passthrough.
    """
    rules = svc.get("device_cgroup_rules") or []
    if not isinstance(rules, list):
        return []
    out: list[Finding] = []
    for rule in rules:
        if not isinstance(rule, str):
            continue
        stripped = rule.strip()
        if stripped.startswith("a") or "*:*" in stripped:
            out.append(
                Finding(
                    "CG023",
                    Severity.CRITICAL,
                    f"device_cgroup_rules {rule!r} allows access to all host devices",
                    name,
                )
            )
        else:
            out.append(
                Finding(
                    "CG023",
                    Severity.MEDIUM,
                    f"device_cgroup_rules {rule!r} widens device access beyond the default",
                    name,
                )
            )
    return out


CHECKS: tuple[CheckFn, ...] = (
    _check_volumes,
    _check_devices,
    _check_device_cgroup_rules,
)
