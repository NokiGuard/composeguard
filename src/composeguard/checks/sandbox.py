"""MAC / sandbox bypass checks (CG060-CG069)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

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


CHECKS: tuple[CheckFn, ...] = (_check_security_opt_unconfined,)
