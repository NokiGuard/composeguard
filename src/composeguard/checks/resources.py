"""Resource limits / availability checks (CG050-CG059)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

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


CHECKS: tuple[CheckFn, ...] = (_check_resource_limits,)
