from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from composeguard.checks import ALL_CHECKS

# Finding/Severity are re-exported for backwards compatibility: `analyzer` was
# the original home of the whole engine, and cli.py / tests / external callers
# import these from here. __all__ marks them exported for mypy strict
# (no_implicit_reexport) and for CodeQL's unused-import analysis alike.
from composeguard.models import Finding, Severity

__all__ = ["MAX_FILE_BYTES", "Finding", "Severity", "analyze_file"]

MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB hard cap on input size


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
    for check in ALL_CHECKS:
        out.extend(check(name, svc))
    return out
