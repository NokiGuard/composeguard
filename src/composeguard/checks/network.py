"""Network exposure checks (CG040-CG049)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

# Used in the CG040 port-binding check. Stored as a constant with a localized
# bandit suppression so the rest of the file stays clean.
_BIND_ALL_INTERFACES = "0.0.0.0"  # nosec B104  # noqa: S104

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


CHECKS: tuple[CheckFn, ...] = (_check_ports,)
