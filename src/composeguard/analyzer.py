from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB hard cap on input size


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    service: str | None = None


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
        findings.extend(_check_service(name, raw))
    return findings


def _check_service(name: str, svc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []

    if svc.get("privileged") is True:
        out.append(Finding("CG001", Severity.CRITICAL, "privileged: true grants near-root host access", name))

    if svc.get("network_mode") == "host":
        out.append(Finding("CG002", Severity.HIGH, "network_mode: host bypasses network isolation", name))

    if svc.get("pid") == "host":
        out.append(Finding("CG003", Severity.HIGH, "pid: host shares the host PID namespace", name))

    image = svc.get("image")
    if isinstance(image, str) and "@sha256:" not in image and (image.endswith(":latest") or ":" not in image):
        out.append(Finding("CG010", Severity.MEDIUM, f"image '{image}' is unpinned (use a digest)", name))

    volumes = svc.get("volumes") or []
    if isinstance(volumes, list):
        for vol in volumes:
            src = vol.split(":", 1)[0] if isinstance(vol, str) else None
            if src == "/var/run/docker.sock":
                out.append(Finding("CG020", Severity.CRITICAL, "docker.sock mount enables container escape", name))

    return out
