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


# --- CG051: OOM killer disabled ----------------------------------------------


def _check_oom_kill_disable(name: str, svc: dict[str, Any]) -> list[Finding]:
    if svc.get("oom_kill_disable") is True:
        return [
            Finding(
                "CG051",
                Severity.LOW,
                "oom_kill_disable: true lets a leaking container stall the host under OOM",
                name,
            )
        ]
    return []


# --- CG052: logging disabled ---------------------------------------------------


def _check_logging_disabled(name: str, svc: dict[str, Any]) -> list[Finding]:
    logging = svc.get("logging")
    if isinstance(logging, dict) and logging.get("driver") == "none":
        return [
            Finding(
                "CG052",
                Severity.LOW,
                "logging driver 'none' discards all container logs (no audit trail)",
                name,
            )
        ]
    return []


CHECKS: tuple[CheckFn, ...] = (
    _check_resource_limits,
    _check_oom_kill_disable,
    _check_logging_disabled,
)
