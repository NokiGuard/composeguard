"""Per-rule tests for the v0.3 rule set (recalibrations + new rules)."""

from __future__ import annotations

from pathlib import Path

from composeguard.analyzer import Finding, Severity, analyze_file
from tests.helpers import HARDENED_SERVICE
from tests.helpers import write_compose as _write


def _findings(tmp_path: Path, snippet: str, rule_id: str) -> list[Finding]:
    p = _write(tmp_path, HARDENED_SERVICE + snippet)
    return [f for f in analyze_file(p) if f.rule_id == rule_id]


# --- CG004: capability tiers -------------------------------------------------


def _cap_findings(tmp_path: Path, cap: str) -> list[Finding]:
    snippet = f"    cap_add:\n      - {cap}\n    cap_drop:\n      - ALL\n"
    return _findings(tmp_path, snippet, "CG004")


def test_sys_module_capability_is_critical(tmp_path: Path) -> None:
    findings = _cap_findings(tmp_path, "SYS_MODULE")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_dac_read_search_capability_is_high(tmp_path: Path) -> None:
    # The classic "shocker" open_by_handle_at escape cap.
    findings = _cap_findings(tmp_path, "DAC_READ_SEARCH")
    assert findings and findings[0].severity is Severity.HIGH


def test_bpf_capability_is_high(tmp_path: Path) -> None:
    findings = _cap_findings(tmp_path, "BPF")
    assert findings and findings[0].severity is Severity.HIGH


def test_setuid_capability_is_medium(tmp_path: Path) -> None:
    findings = _cap_findings(tmp_path, "SETUID")
    assert findings and findings[0].severity is Severity.MEDIUM


def test_net_raw_capability_is_medium(tmp_path: Path) -> None:
    findings = _cap_findings(tmp_path, "NET_RAW")
    assert findings and findings[0].severity is Severity.MEDIUM


def test_syslog_capability_is_low(tmp_path: Path) -> None:
    findings = _cap_findings(tmp_path, "SYSLOG")
    assert findings and findings[0].severity is Severity.LOW
