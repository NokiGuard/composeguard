"""Shared fixtures for rule tests."""

from __future__ import annotations

from pathlib import Path

# A baseline "fully hardened" service — useful so each rule test can layer
# one insecure setting on top without tripping CG006/CG007/CG050.
HARDENED_SERVICE = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    cpus: 0.5
"""


def write_compose(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "compose.yml"
    p.write_text(body, encoding="utf-8")
    return p
