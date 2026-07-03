"""Rule registry: each module contributes a CHECKS tuple of check callables.

Order matters for output stability — it mirrors the original _check_service
call order (privilege → image → mounts → secrets → network → resources →
sandbox), so per-service finding ordering is deterministic.
"""

from __future__ import annotations

from composeguard.checks import image, mounts, network, privilege, resources, sandbox, secrets
from composeguard.models import CheckFn

ALL_CHECKS: tuple[CheckFn, ...] = (
    *privilege.CHECKS,
    *image.CHECKS,
    *mounts.CHECKS,
    *secrets.CHECKS,
    *network.CHECKS,
    *resources.CHECKS,
    *sandbox.CHECKS,
)
