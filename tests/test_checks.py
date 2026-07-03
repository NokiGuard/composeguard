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


# --- CG020: engine socket exposure --------------------------------------------


def _volume_findings(tmp_path: Path, volume: str, rule_id: str = "CG020") -> list[Finding]:
    return _findings(tmp_path, f"    volumes:\n      - {volume}\n", rule_id)


def test_docker_sock_is_critical(tmp_path: Path) -> None:
    findings = _volume_findings(tmp_path, "/var/run/docker.sock:/var/run/docker.sock")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_run_docker_sock_variant_flagged(tmp_path: Path) -> None:
    assert _volume_findings(tmp_path, "/run/docker.sock:/var/run/docker.sock")


def test_docker_sock_trailing_slash_flagged(tmp_path: Path) -> None:
    assert _volume_findings(tmp_path, "/var/run/docker.sock/:/sock")


def test_containerd_sock_flagged(tmp_path: Path) -> None:
    assert _volume_findings(tmp_path, "/run/containerd/containerd.sock:/sock")


def test_podman_sock_flagged(tmp_path: Path) -> None:
    assert _volume_findings(tmp_path, "/var/run/podman/podman.sock:/sock")


def test_run_dir_mount_exposes_sockets(tmp_path: Path) -> None:
    # Mounting /run (or /var/run) hands over every engine socket in it.
    assert _volume_findings(tmp_path, "/run:/host-run")
    assert _volume_findings(tmp_path, "/var/run:/host-run")


def test_readonly_docker_sock_still_critical(tmp_path: Path) -> None:
    # ro on a socket bind mount does not prevent API calls through it.
    findings = _volume_findings(tmp_path, "/var/run/docker.sock:/var/run/docker.sock:ro")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_long_form_readonly_docker_sock_still_critical(tmp_path: Path) -> None:
    snippet = (
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /var/run/docker.sock\n"
        "        target: /var/run/docker.sock\n"
        "        read_only: true\n"
    )
    findings = _findings(tmp_path, snippet, "CG020")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_unrelated_socket_not_flagged_as_engine(tmp_path: Path) -> None:
    assert not _volume_findings(tmp_path, "/run/mysqld/mysqld.sock:/sock")


# --- CG021: sensitive path recalibration ---------------------------------------


def test_root_mount_writable_is_critical(tmp_path: Path) -> None:
    findings = _volume_findings(tmp_path, "/:/host", "CG021")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_root_mount_readonly_is_high(tmp_path: Path) -> None:
    findings = _volume_findings(tmp_path, "/:/host:ro", "CG021")
    assert findings and findings[0].severity is Severity.HIGH


def test_var_lib_docker_readonly_is_high(tmp_path: Path) -> None:
    findings = _volume_findings(tmp_path, "/var/lib/docker:/d:ro", "CG021")
    assert findings and findings[0].severity is Severity.HIGH


def test_nonroot_absolute_path_not_flagged_as_root(tmp_path: Path) -> None:
    # An absolute path outside the sensitive set must not match the '/' entry.
    assert not _volume_findings(tmp_path, "/opt/data:/data", "CG021")


# --- CG022: device severity tiers ----------------------------------------------


def _device_findings(tmp_path: Path, device: str) -> list[Finding]:
    return _findings(tmp_path, f"    devices:\n      - {device}\n", "CG022")


def test_dev_mem_is_critical(tmp_path: Path) -> None:
    findings = _device_findings(tmp_path, "/dev/mem:/dev/mem")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_nvme_disk_is_high(tmp_path: Path) -> None:
    findings = _device_findings(tmp_path, "/dev/nvme0n1:/dev/nvme0n1")
    assert findings and findings[0].severity is Severity.HIGH


def test_fuse_is_medium(tmp_path: Path) -> None:
    findings = _device_findings(tmp_path, "/dev/fuse:/dev/fuse")
    assert findings and findings[0].severity is Severity.MEDIUM


def test_gpu_dri_is_low(tmp_path: Path) -> None:
    findings = _device_findings(tmp_path, "/dev/dri:/dev/dri")
    assert findings and findings[0].severity is Severity.LOW


def test_unknown_device_defaults_medium(tmp_path: Path) -> None:
    findings = _device_findings(tmp_path, "/dev/weird0:/dev/weird0")
    assert findings and findings[0].severity is Severity.MEDIUM


# --- CG023: device_cgroup_rules -------------------------------------------------


def test_all_devices_cgroup_rule_is_critical(tmp_path: Path) -> None:
    findings = _findings(tmp_path, '    device_cgroup_rules:\n      - "a *:* rwm"\n', "CG023")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_wildcard_major_minor_cgroup_rule_is_critical(tmp_path: Path) -> None:
    findings = _findings(tmp_path, '    device_cgroup_rules:\n      - "c *:* rwm"\n', "CG023")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_narrow_cgroup_rule_is_medium(tmp_path: Path) -> None:
    findings = _findings(tmp_path, '    device_cgroup_rules:\n      - "c 189:1 rw"\n', "CG023")
    assert findings and findings[0].severity is Severity.MEDIUM


def test_no_cgroup_rules_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE)
    assert not any(f.rule_id == "CG023" for f in analyze_file(p))


# --- CG030 / CG031: env secrets --------------------------------------------------


def _env_findings(tmp_path: Path, env_line: str, rule_id: str) -> list[Finding]:
    return _findings(tmp_path, f"    environment:\n      {env_line}\n", rule_id)


def test_unbraced_var_reference_not_flagged(tmp_path: Path) -> None:
    # $DB_PASSWORD (no braces) is interpolation, not an inline secret.
    assert not _env_findings(tmp_path, "DB_PASSWORD: $DB_PASSWORD", "CG030")


def test_github_token_value_is_cg031_high(tmp_path: Path) -> None:
    findings = _env_findings(tmp_path, "GH: ghp_abcdefghijklmnopqrstuv123456", "CG031")
    assert findings and findings[0].severity is Severity.HIGH


def test_aws_key_id_value_is_cg031(tmp_path: Path) -> None:
    assert _env_findings(tmp_path, "CLOUD: AKIAIOSFODNN7EXAMPLE", "CG031")


def test_sk_prefixed_key_is_cg031(tmp_path: Path) -> None:
    assert _env_findings(tmp_path, "LLM: sk-ant-abcdefghijklmnopqrstuvwx", "CG031")


def test_slack_token_is_cg031(tmp_path: Path) -> None:
    assert _env_findings(tmp_path, "CHAT: xoxb-1234-abcd", "CG031")


def test_gitlab_token_is_cg031(tmp_path: Path) -> None:
    assert _env_findings(tmp_path, "CI: glpat-abcdefghijklmnopqrst", "CG031")


def test_jwt_value_is_cg031(tmp_path: Path) -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123DEF"
    assert _env_findings(tmp_path, f"SESSION: {jwt}", "CG031")


def test_pem_private_key_is_cg031(tmp_path: Path) -> None:
    snippet = '    environment:\n      CERT: "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."\n'
    assert _findings(tmp_path, snippet, "CG031")


def test_token_value_suppresses_cg030(tmp_path: Path) -> None:
    # A secret-looking key with a token-shaped value reports CG031 only.
    line = "GITHUB_TOKEN: ghp_abcdefghijklmnopqrstuv123456"
    assert _env_findings(tmp_path, line, "CG031")
    assert not _env_findings(tmp_path, line, "CG030")


def test_non_token_value_not_cg031(tmp_path: Path) -> None:
    assert not _env_findings(tmp_path, "VALUE: eyJnotajwt", "CG031")


# --- CG032: build args -----------------------------------------------------------


def test_build_arg_token_is_high(tmp_path: Path) -> None:
    snippet = (
        "    build:\n      context: .\n      args:\n        GH: ghp_abcdefghijklmnopqrstuv123456\n"
    )
    findings = _findings(tmp_path, snippet, "CG032")
    assert findings and findings[0].severity is Severity.HIGH


def test_build_arg_secret_key_is_medium(tmp_path: Path) -> None:
    snippet = "    build:\n      context: .\n      args:\n        API_KEY: hunter2\n"
    findings = _findings(tmp_path, snippet, "CG032")
    assert findings and findings[0].severity is Severity.MEDIUM


def test_build_arg_list_form_detected(tmp_path: Path) -> None:
    snippet = "    build:\n      context: .\n      args:\n        - DB_PASSWORD=hunter2\n"
    assert _findings(tmp_path, snippet, "CG032")


def test_build_string_form_clean(tmp_path: Path) -> None:
    assert not _findings(tmp_path, "    build: ./app\n", "CG032")


def test_build_arg_placeholder_clean(tmp_path: Path) -> None:
    snippet = "    build:\n      context: .\n      args:\n        API_KEY: ${API_KEY}\n"
    assert not _findings(tmp_path, snippet, "CG032")
