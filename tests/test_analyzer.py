from __future__ import annotations

from pathlib import Path

import pytest

from composeguard.analyzer import MAX_FILE_BYTES, Severity, analyze_file

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


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "compose.yml"
    p.write_text(body, encoding="utf-8")
    return p


# --- baseline ---------------------------------------------------------------


def test_hardened_baseline_is_clean(tmp_path: Path) -> None:
    assert analyze_file(_write(tmp_path, HARDENED_SERVICE)) == []


# --- CG001 / CG002 / CG003 / CG005 -----------------------------------------


def test_flags_privileged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    privileged: true\n")
    findings = analyze_file(p)
    assert any(f.rule_id == "CG001" and f.severity is Severity.HIGH for f in findings)


def test_flags_host_network(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    network_mode: host\n")
    assert any(f.rule_id == "CG002" for f in analyze_file(p))


def test_flags_host_pid(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    pid: host\n")
    assert any(f.rule_id == "CG003" for f in analyze_file(p))


def test_flags_host_ipc(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    ipc: host\n")
    assert any(f.rule_id == "CG005" for f in analyze_file(p))


# --- CG004: capabilities ---------------------------------------------------


def test_flags_sys_admin_capability_as_high(tmp_path: Path) -> None:
    p = _write(
        tmp_path, HARDENED_SERVICE + "    cap_add:\n      - SYS_ADMIN\n    cap_drop:\n      - ALL\n"
    )
    findings = [f for f in analyze_file(p) if f.rule_id == "CG004"]
    assert any(f.severity is Severity.HIGH for f in findings)


def test_flags_sys_time_capability_as_medium(tmp_path: Path) -> None:
    p = _write(
        tmp_path, HARDENED_SERVICE + "    cap_add:\n      - SYS_TIME\n    cap_drop:\n      - ALL\n"
    )
    findings = [f for f in analyze_file(p) if f.rule_id == "CG004"]
    assert any(f.severity is Severity.MEDIUM for f in findings)


def test_capability_with_cap_prefix_normalized(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        HARDENED_SERVICE + "    cap_add:\n      - CAP_SYS_ADMIN\n    cap_drop:\n      - ALL\n",
    )
    assert any(f.rule_id == "CG004" for f in analyze_file(p))


def test_harmless_capability_not_flagged(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        HARDENED_SERVICE + "    cap_add:\n      - NET_BIND_SERVICE\n    cap_drop:\n      - ALL\n",
    )
    assert not any(f.rule_id == "CG004" for f in analyze_file(p))


# --- CG011: cap_drop discipline -------------------------------------------


def test_cap_add_without_cap_drop_all_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    cap_add:\n      - NET_BIND_SERVICE\n")
    assert any(f.rule_id == "CG011" for f in analyze_file(p))


def test_cap_add_with_cap_drop_all_is_clean(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        HARDENED_SERVICE + "    cap_add:\n      - NET_BIND_SERVICE\n    cap_drop:\n      - ALL\n",
    )
    assert not any(f.rule_id == "CG011" for f in analyze_file(p))


def test_no_cap_add_no_cap_drop_finding(tmp_path: Path) -> None:
    # CG011 should only fire when cap_add is set; otherwise it's noise.
    p = _write(tmp_path, HARDENED_SERVICE)
    assert not any(f.rule_id == "CG011" for f in analyze_file(p))


# --- CG008 / CG009: identity & user namespace ----------------------------


def test_user_root_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + '    user: "root"\n')
    findings = [f for f in analyze_file(p) if f.rule_id == "CG008"]
    assert findings and findings[0].severity is Severity.HIGH


def test_user_zero_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + '    user: "0"\n')
    assert any(f.rule_id == "CG008" for f in analyze_file(p))


def test_user_zero_colon_zero_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + '    user: "0:0"\n')
    assert any(f.rule_id == "CG008" for f in analyze_file(p))


def test_user_nonzero_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + '    user: "1000:1000"\n')
    assert not any(f.rule_id == "CG008" for f in analyze_file(p))


def test_user_unset_is_clean(tmp_path: Path) -> None:
    # Don't infer rootful from a missing user directive — the image default
    # may or may not be root and we don't inspect images.
    p = _write(tmp_path, HARDENED_SERVICE)
    assert not any(f.rule_id == "CG008" for f in analyze_file(p))


def test_userns_mode_host_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    userns_mode: host\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG009"]
    assert findings and findings[0].severity is Severity.HIGH


# --- CG006 / CG007 ----------------------------------------------------------


def test_missing_no_new_privileges_flagged(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    mem_limit: 256m
"""
    assert any(f.rule_id == "CG006" for f in analyze_file(_write(tmp_path, body)))


def test_missing_read_only_flagged(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
"""
    assert any(f.rule_id == "CG007" for f in analyze_file(_write(tmp_path, body)))


# --- CG010: image pinning --------------------------------------------------


def test_flags_unpinned_latest(tmp_path: Path) -> None:
    p = _write(tmp_path, "services:\n  app:\n    image: nginx:latest\n")
    assert any(f.rule_id == "CG010" for f in analyze_file(p))


def test_flags_unpinned_no_tag(tmp_path: Path) -> None:
    p = _write(tmp_path, "services:\n  app:\n    image: nginx\n")
    assert any(f.rule_id == "CG010" for f in analyze_file(p))


def test_pinned_digest_not_flagged_for_image(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE)
    assert not any(f.rule_id == "CG010" for f in analyze_file(p))


def test_image_with_registry_port_not_misclassified(tmp_path: Path) -> None:
    # Registry port (registry:5000) should not look like a tag.
    digest = "sha256:" + "0" * 64
    body = f"services:\n  app:\n    image: registry.local:5000/nginx@{digest}\n"
    p = _write(tmp_path, body)
    assert not any(f.rule_id == "CG010" for f in analyze_file(p))


# --- CG020 / CG021: mounts -------------------------------------------------


def test_flags_docker_socket_mount(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        HARDENED_SERVICE + "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    )
    assert any(f.rule_id == "CG020" for f in analyze_file(p))


def test_flags_etc_mount_writable_as_high(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    volumes:\n      - /etc:/host-etc\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG021"]
    assert any(f.severity is Severity.HIGH for f in findings)


def test_flags_etc_mount_readonly_as_high(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    volumes:\n      - /etc:/host-etc:ro\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG021"]
    assert any(f.severity is Severity.HIGH for f in findings)


def test_flags_var_mount_writable_as_medium(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    volumes:\n      - /var/log:/x\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG021"]
    assert any(f.severity is Severity.MEDIUM for f in findings)


def test_flags_etc_subpath_via_longest_prefix(tmp_path: Path) -> None:
    # /etc/passwd matches /etc, not /
    p = _write(tmp_path, HARDENED_SERVICE + "    volumes:\n      - /etc/passwd:/x:ro\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG021"]
    assert findings
    assert any("/etc/passwd" in f.message for f in findings)


def test_flags_long_form_volume_with_read_only(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + (
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /etc\n"
        "        target: /host-etc\n"
        "        read_only: true\n"
    )
    findings = [f for f in analyze_file(_write(tmp_path, body)) if f.rule_id == "CG021"]
    assert any(f.severity is Severity.HIGH for f in findings)


def test_named_volume_not_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    volumes:\n      - data:/var/lib/data\n")
    assert not any(f.rule_id == "CG021" for f in analyze_file(p))


# --- CG022: device passthrough -----------------------------------------------


def test_flags_host_device_passthrough(tmp_path: Path) -> None:
    p = _write(tmp_path, HARDENED_SERVICE + "    devices:\n      - /dev/kvm:/dev/kvm\n")
    findings = [f for f in analyze_file(p) if f.rule_id == "CG022"]
    assert findings and findings[0].severity is Severity.HIGH


def test_flags_long_form_device_passthrough(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + (
        "    devices:\n      - source: /dev/sda1\n        target: /dev/sda1\n"
    )
    assert any(f.rule_id == "CG022" for f in analyze_file(_write(tmp_path, body)))


def test_no_devices_clean(tmp_path: Path) -> None:
    assert not any(f.rule_id == "CG022" for f in analyze_file(_write(tmp_path, HARDENED_SERVICE)))


# --- CG060: AppArmor / seccomp disabled --------------------------------------


def test_flags_apparmor_unconfined(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    mem_limit: 256m
    security_opt:
      - no-new-privileges:true
      - apparmor=unconfined
"""
    findings = [f for f in analyze_file(_write(tmp_path, body)) if f.rule_id == "CG060"]
    assert findings and findings[0].severity is Severity.HIGH


def test_flags_seccomp_unconfined_colon_form(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    mem_limit: 256m
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
"""
    assert any(f.rule_id == "CG060" for f in analyze_file(_write(tmp_path, body)))


def test_default_security_opt_not_flagged(tmp_path: Path) -> None:
    # The hardened baseline only has no-new-privileges:true — should not match.
    assert not any(f.rule_id == "CG060" for f in analyze_file(_write(tmp_path, HARDENED_SERVICE)))


# --- CG030: secrets in env -------------------------------------------------


def test_flags_inline_password_env_dict(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + "    environment:\n      DB_PASSWORD: hunter2\n"
    assert any(f.rule_id == "CG030" for f in analyze_file(_write(tmp_path, body)))


def test_flags_inline_api_key_env_list(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + "    environment:\n      - API_KEY=sk_live_abc\n"
    assert any(f.rule_id == "CG030" for f in analyze_file(_write(tmp_path, body)))


def test_env_var_reference_not_flagged(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + "    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n"
    assert not any(f.rule_id == "CG030" for f in analyze_file(_write(tmp_path, body)))


def test_empty_secret_value_not_flagged(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + '    environment:\n      DB_PASSWORD: ""\n'
    assert not any(f.rule_id == "CG030" for f in analyze_file(_write(tmp_path, body)))


def test_non_secret_key_not_flagged(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + "    environment:\n      LOG_LEVEL: debug\n"
    assert not any(f.rule_id == "CG030" for f in analyze_file(_write(tmp_path, body)))


# --- CG040: port binding ---------------------------------------------------


def test_flags_short_port_without_host_ip(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + '    ports:\n      - "8080:80"\n'
    assert any(f.rule_id == "CG040" for f in analyze_file(_write(tmp_path, body)))


def test_flags_explicit_all_interfaces(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + '    ports:\n      - "0.0.0.0:8080:80"\n'
    assert any(f.rule_id == "CG040" for f in analyze_file(_write(tmp_path, body)))


def test_localhost_port_binding_not_flagged(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + '    ports:\n      - "127.0.0.1:8080:80"\n'
    assert not any(f.rule_id == "CG040" for f in analyze_file(_write(tmp_path, body)))


def test_long_form_port_with_host_ip_not_flagged(tmp_path: Path) -> None:
    body = HARDENED_SERVICE + (
        '    ports:\n      - target: 80\n        published: 8080\n        host_ip: "127.0.0.1"\n'
    )
    assert not any(f.rule_id == "CG040" for f in analyze_file(_write(tmp_path, body)))


# --- CG050: resource limits ------------------------------------------------


def test_flags_missing_resource_limits(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    security_opt:
      - no-new-privileges:true
"""
    assert any(f.rule_id == "CG050" for f in analyze_file(_write(tmp_path, body)))


def test_v3_deploy_limits_satisfy_check(tmp_path: Path) -> None:
    body = """\
services:
  app:
    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000
    read_only: true
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
"""
    assert not any(f.rule_id == "CG050" for f in analyze_file(_write(tmp_path, body)))


# --- input-handling guards -------------------------------------------------


def test_rejects_oversized_file(tmp_path: Path) -> None:
    p = tmp_path / "big.yml"
    p.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        analyze_file(p)


def test_rejects_non_mapping_root(tmp_path: Path) -> None:
    p = _write(tmp_path, "- not\n- a\n- mapping\n")
    with pytest.raises(ValueError, match="mapping"):
        analyze_file(p)


def test_empty_file_yields_no_findings(tmp_path: Path) -> None:
    p = _write(tmp_path, "")
    assert analyze_file(p) == []
