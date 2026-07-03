from __future__ import annotations

from pathlib import Path

import pytest

from composeguard.cli import main


def test_cli_exits_nonzero_on_critical(tmp_path: Path) -> None:
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    rc = main([str(p)])
    assert rc == 1


def test_fail_on_critical_trips_on_critical(tmp_path: Path) -> None:
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    assert main([str(p), "--fail-on", "critical"]) == 1


def test_fail_on_critical_ignores_high(tmp_path: Path) -> None:
    """A high finding must not trip the gate when --fail-on is critical."""
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    ipc: host\n", encoding="utf-8"
    )
    assert main([str(p), "--fail-on", "critical"]) == 0


def test_cli_exits_zero_on_clean(tmp_path: Path) -> None:
    p = tmp_path / "compose.yml"
    p.write_text("services:\n  app:\n    image: nginx@sha256:abc\n", encoding="utf-8")
    assert main([str(p)]) == 0


def test_color_always_emits_ansi(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    main([str(p), "--color", "always"])
    out = capsys.readouterr().out
    assert "\033[" in out
    assert "\033[95m" in out  # critical = bold bright-magenta


def test_color_never_emits_no_ansi(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    main([str(p), "--color", "never"])
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "CRITICAL" in out
