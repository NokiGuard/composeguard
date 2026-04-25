from __future__ import annotations

from pathlib import Path

import pytest

from composeguard.analyzer import MAX_FILE_BYTES, Severity, analyze_file


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "compose.yml"
    p.write_text(body, encoding="utf-8")
    return p


def test_flags_privileged(tmp_path: Path) -> None:
    p = _write(tmp_path, "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n")
    findings = analyze_file(p)
    assert any(f.rule_id == "CG001" and f.severity is Severity.CRITICAL for f in findings)


def test_flags_docker_socket_mount(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "services:\n  app:\n    image: nginx@sha256:abc\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    )
    findings = analyze_file(p)
    assert any(f.rule_id == "CG020" for f in findings)


def test_flags_unpinned_image(tmp_path: Path) -> None:
    p = _write(tmp_path, "services:\n  app:\n    image: nginx:latest\n")
    findings = analyze_file(p)
    assert any(f.rule_id == "CG010" for f in findings)


def test_clean_file_yields_no_findings(tmp_path: Path) -> None:
    p = _write(tmp_path, "services:\n  app:\n    image: nginx@sha256:abc\n")
    assert analyze_file(p) == []


def test_rejects_oversized_file(tmp_path: Path) -> None:
    p = tmp_path / "big.yml"
    p.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        analyze_file(p)


def test_rejects_non_mapping_root(tmp_path: Path) -> None:
    p = _write(tmp_path, "- not\n- a\n- mapping\n")
    with pytest.raises(ValueError, match="mapping"):
        analyze_file(p)
