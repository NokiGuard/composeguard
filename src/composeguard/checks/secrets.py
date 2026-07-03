"""Secrets pasted into configuration (CG030-CG039)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from composeguard.models import CheckFn, Finding, Severity

_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"
)

# Known token shapes. A value matching one of these is a confirmed-format
# credential regardless of what the key is called — graded above the
# key-name-only heuristic.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub token", re.compile(r"^gh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub token", re.compile(r"^github_pat_[A-Za-z0-9_]{20,}")),
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("API secret key", re.compile(r"^sk-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"^xox[abposr]-")),
    ("GitLab token", re.compile(r"^glpat-[A-Za-z0-9_-]{20,}")),
    ("JWT", re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def _match_token(value: str) -> str | None:
    for label, pattern in _TOKEN_PATTERNS:
        if pattern.search(value):
            return label
    return None


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


def _is_placeholder(value: str) -> bool:
    # ${VAR} and $VAR interpolations are resolved by compose, not literals.
    # This also skips literal values that happen to start with '$' (e.g.
    # bcrypt hashes) — accepted tradeoff to avoid noisy false positives.
    return not value or value.startswith("$")


# --- CG030 / CG031: secrets in environment variables --------------------------


def _check_env_secrets(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for k, v in _iter_env(svc.get("environment")):
        stripped = v.strip()
        if _is_placeholder(stripped):
            continue
        token = _match_token(stripped)
        if token is not None:
            out.append(
                Finding(
                    "CG031",
                    Severity.HIGH,
                    f"env var {k!r} contains what looks like a {token} (use secrets/.env)",
                    name,
                )
            )
        elif _SECRET_KEY_PATTERN.search(k):
            out.append(
                Finding(
                    "CG030",
                    Severity.MEDIUM,
                    f"env var {k!r} looks like a secret with an inline value (use secrets/.env)",
                    name,
                )
            )
    return out


# --- CG032: secrets in build args ----------------------------------------------


def _check_build_args(name: str, svc: dict[str, Any]) -> list[Finding]:
    """Flag secrets in build.args — they are baked into image layers forever."""
    build = svc.get("build")
    if not isinstance(build, dict):
        return []
    out: list[Finding] = []
    for k, v in _iter_env(build.get("args")):
        stripped = v.strip()
        if _is_placeholder(stripped):
            continue
        token = _match_token(stripped)
        if token is not None:
            out.append(
                Finding(
                    "CG032",
                    Severity.HIGH,
                    f"build arg {k!r} contains what looks like a {token} — "
                    "build args are baked into image layers",
                    name,
                )
            )
        elif _SECRET_KEY_PATTERN.search(k):
            out.append(
                Finding(
                    "CG032",
                    Severity.MEDIUM,
                    f"build arg {k!r} looks like a secret — build args are baked into image layers",
                    name,
                )
            )
    return out


CHECKS: tuple[CheckFn, ...] = (
    _check_env_secrets,
    _check_build_args,
)
