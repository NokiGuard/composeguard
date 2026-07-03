"""Image / supply-chain checks (CG010-CG019)."""

from __future__ import annotations

from typing import Any

from composeguard.models import CheckFn, Finding, Severity

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


CHECKS: tuple[CheckFn, ...] = (_check_image,)
