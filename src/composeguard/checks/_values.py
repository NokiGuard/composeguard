"""Helpers for turning untrusted YAML values into strings safely."""

from __future__ import annotations


def scalar_str(value: object) -> str | None:
    """Return a string for YAML scalars, None for anything else.

    Never str()/repr() a container from untrusted YAML: aliases let a few
    hundred bytes describe a billion-element structure ("billion laughs"),
    and safe_load builds it cheaply by sharing references — it's only
    stringifying that expands it.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    return None
