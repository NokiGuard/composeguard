"""Dangerous mounts and device passthrough (CG020-CG029)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

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


CHECKS: tuple[CheckFn, ...] = (
    _check_volumes,
    _check_devices,
)
