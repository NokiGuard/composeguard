"""Secrets pasted into configuration (CG030-CG039)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from composeguard.models import CheckFn, Finding, Severity

# --- CG030: secrets in environment variables --------------------------------

_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"
)


def _iter_env(env: object) -> Iterator[tuple[str, str]]:
    """Yield (key, value) pairs from compose env (list or dict form)."""
    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                yield k, v
    elif isinstance(env, dict):
        for k, v in env.items():
            if isinstance(k, str):
                yield k, "" if v is None else str(v)


def _check_env_secrets(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for k, v in _iter_env(svc.get("environment")):
        if not _SECRET_KEY_PATTERN.search(k):
            continue
        stripped = v.strip()
        if not stripped or stripped.startswith("${"):
            continue
        out.append(
            Finding(
                "CG030",
                Severity.MEDIUM,
                f"env var {k!r} looks like a secret with an inline value (use secrets/.env)",
                name,
            )
        )
    return out


CHECKS: tuple[CheckFn, ...] = (_check_env_secrets,)
