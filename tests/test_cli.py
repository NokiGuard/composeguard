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


def test_unreadable_file_exits_2_and_continues(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("services:\n  a: [\n", encoding="utf-8")
    good = tmp_path / "good.yml"
    good.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    rc = main([str(bad), str(tmp_path / "missing.yml"), str(good), "--color", "never"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "Invalid YAML" in captured.err
    assert "missing.yml" in captured.err
    assert "CG001" in captured.out  # later files are still analyzed
    assert "2 file(s) could not be analyzed" in captured.out


def test_ignore_drops_findings_and_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "compose.yml"
    p.write_text(
        "services:\n  app:\n    image: nginx@sha256:abc\n    privileged: true\n", encoding="utf-8"
    )
    rc = main([str(p), "--ignore", "cg001,CG006", "--ignore", "CG007,CG050", "--color", "never"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CG0" not in out
    assert "0 finding(s)" in out
    assert "4 ignored via --ignore" in out


def test_ignore_rejects_malformed_rule_id(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["compose.yml", "--ignore", "CG01,privileged"])
    assert exc.value.code == 2
    assert "invalid rule id(s): CG01, PRIVILEGED" in capsys.readouterr().err
