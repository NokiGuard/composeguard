# CLAUDE.md — composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations. Python 3.12 CLI built secure-by-default. `BRIEF.md` is the original (frozen) spec; the shipped rule set has since grown well beyond it — this file's rule table is the authoritative list.

## Severity scheme

Four levels: `low`, `medium`, `high`, `critical`. Compare via `Severity.rank` (LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3), not by name. Grading principle: severity = criticality × exploitability — `critical` is reserved for configurations that hand over the host outright (privileged mode, engine sockets, SYS_ADMIN, raw memory devices, all-device cgroup rules).

The CLI's `--fail-on` defaults to `high`; CRITICAL outranks HIGH, so the default CI gate fails on both. LOW and MEDIUM findings are surfaced but do not fail CI by default.

## Implemented rules

| ID | Severity | What it flags |
|---|---|---|
| CG001 | critical | `privileged: true` |
| CG002 | high | `network_mode: host` |
| CG003 | high | `pid: host` |
| CG004 | critical / high / medium / low | dangerous Linux capabilities in `cap_add`. critical: SYS_ADMIN, ALL, SYS_MODULE; high: NET_ADMIN, SYS_PTRACE, SYS_RAWIO, SYS_BOOT, MAC_*, DAC_READ_SEARCH ("shocker" escape), BPF; medium: SYS_TIME, DAC_OVERRIDE, AUDIT_*, PERFMON, SYS_CHROOT, SETUID, SETGID, NET_RAW, CHECKPOINT_RESTORE; low: SYSLOG |
| CG005 | high | `ipc: host` |
| CG006 | low | missing `security_opt: no-new-privileges:true` |
| CG007 | low | missing `read_only: true` |
| CG008 | high | explicit `user: root` / `user: "0"` / `user: "0:0"` |
| CG009 | high | `userns_mode: host` |
| CG010 | medium | unpinned image (`:latest` or no tag; digests always pass). Skipped when `build:` is set — `image:` then just names the built result |
| CG011 | low | `cap_add` is set without `cap_drop: [ALL]` (defense-in-depth) |
| CG020 | critical | container-engine socket exposure: docker.sock (`/var/run` and `/run` forms), containerd, podman, CRI-O, balena sockets, and parent-dir mounts (`/run`, `/var/run`, `/run/containerd`, …) that contain them. Socket filenames also match under any prefix, so rootless/per-user engines (`/run/user/1000/docker.sock`, `${XDG_RUNTIME_DIR}/…`, `~/.docker/run/docker.sock`) are caught. Fires on read-only mounts too — ro does not block socket API calls |
| CG021 | critical … low | mount of sensitive host path. `/` = critical writable / high ro; `/etc`, `/root`, `/var/lib/docker` = high (rw or ro); kernel/system paths (`/sys`, `/proc`, `/dev`, `/usr`, `/lib*`, `/sbin`, `/bin`, `/boot`) = high writable / medium read-only; `/var`, `/home` = medium writable / low read-only. Paths are lexically normalized first (`..`, `//`), and short-form mode is parsed as a comma list (`ro,z` is read-only) |
| CG022 | critical / high / medium / low | host device passed via `devices:`, tiered: `/dev/mem`, `/dev/kmem`, `/dev/port` = critical; raw disks (`/dev/sd*`, `/dev/hd*`, `/dev/nvme*`, `/dev/vd*`, `/dev/xvd*`, `/dev/mapper/*`, `/dev/dm-*`, `/dev/loop*`, `/dev/md*`) = high; `/dev/kvm`, `/dev/net/tun`, `/dev/fuse` = medium; peripherals (`/dev/dri*`, `/dev/snd*`, `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/video*`, `/dev/usb*`, `/dev/bus/usb*`, `/dev/input*`, `/dev/hidraw*`, `/dev/nvidia*`, `/dev/serial/*`, `/dev/ttyS*`, `/dev/ttyAMA*`, `/dev/gpiomem`, `/dev/apex_*`) = low; anything else under `/dev/` = medium |
| CG023 | critical / medium | `device_cgroup_rules`: type `a` or `*:*` major:minor = critical (all-device access with default CAP_MKNOD); any other rule = medium |
| CG030 | medium | secret-looking env var key (PASSWORD/SECRET/TOKEN/API_KEY/etc.) with an inline value, or any env value embedding a password in a URL (`postgres://u:pw@db`). Keys ending `_FILE`/`_PATH`/`_DIR` (secret references) and flag values (`true`/`false`/`yes`/`no`/`on`/`off`) are not flagged. Values starting with `$` (`${VAR}` or `$VAR` interpolation) are placeholders, not flagged — this also skips literal `$…` values like bcrypt hashes (accepted tradeoff). Suppressed when CG031 fires on the same var |
| CG031 | high | env value matching a known token shape regardless of key name: GitHub (`gh[pousr]_`, `github_pat_`), AWS key IDs (`AKIA`/`ASIA`), `sk-…` API keys, Slack `xox*`, GitLab `glpat-`, JWTs, PEM private-key blocks |
| CG032 | high / medium | same secret detection applied to `build.args` (token shape = high, key-name or URL-password match = medium) — build args are baked into image layers |
| CG040 | medium | port published to all interfaces: no `host_ip`, `0.0.0.0`, or IPv6 `::` (short form `":::8080:80"` included; bracketed hosts like `[::1]` parse correctly) |
| CG050 | low | no memory or CPU limit set |
| CG051 | low | `oom_kill_disable: true` |
| CG052 | low | `logging: { driver: none }` (audit-trail loss) |
| CG060 | high | `security_opt` disables AppArmor (`apparmor=unconfined`) or seccomp (`seccomp=unconfined`) |
| CG061 | high | `security_opt` disables SELinux label confinement (`label:disable` / `label=disable`) |
| CG070 | high | `cgroup: host` |
| CG071 | medium | `uts: host` |
| CG072 | medium | `network_mode:` or `pid:` joined to another container (`container:…` / `service:…`) |
| CG073 | low | dangerous-but-namespaced sysctls: `net.ipv4.ip_unprivileged_port_start=0`, `net.ipv4.ip_forward=1`. Deliberately tiny set — Docker rejects non-namespaced sysctls, so `kernel.*` escape vectors can't appear in a working compose file |

Note: CG011 lives in the capability logic (privilege band) despite its ID — a pre-existing ID/band mismatch, kept for stability.

## Git workflow

This folder is its own git repository — pushes go to `NokiGuard/composeguard`. Commit and push after every meaningful unit of work (new rule, bug fix, doc change, dep bump). Do not run `git` from the workspace root for this project.

## How to run things

`uv` is the package manager. Everything else runs through it.

```bash
uv sync --all-extras --dev          # install deps incl. dev tools
uv run pytest                        # tests + coverage gate (80%)
uv run pytest tests/test_analyzer.py::test_flags_privileged   # single test
uv run ruff check .                  # lint
uv run ruff format .                 # format
uv run mypy                          # strict type check
uv run bandit -r src -c pyproject.toml   # SAST on our code
uv run composeguard <file.yml>       # invoke the CLI from source
```

For pip-audit, audit only locked runtime deps (the dev tooling pulls in
`pip` transitively, which would contaminate the audit set):

```bash
uv export --frozen --format requirements-txt --no-emit-project --no-default-groups --no-hashes -o runtime-reqs.txt
uv run pip-audit --strict -r runtime-reqs.txt
```

CI (`.github/workflows/ci.yml`) runs lint → typecheck → test → bandit → pip-audit; CodeQL runs separately. Pre-commit (`.pre-commit-config.yaml`) wires the same checks plus gitleaks.

## Architecture

Single-purpose CLI; the core is small.

```
src/composeguard/
├── cli.py        # argparse, exit-code logic, --fail-on threshold, --ignore, ANSI coloring
├── models.py     # Severity, Finding, CheckFn type alias
├── analyzer.py   # YAML loading + orchestration loop; re-exports Severity/Finding
└── checks/       # one module per rule band, each exposing a CHECKS tuple
    ├── __init__.py   # ALL_CHECKS = concatenation of every module's CHECKS
    ├── _values.py    # scalar_str: safe stringification of untrusted YAML values
    ├── privilege.py  # CG001-CG009, CG011, CG070-CG073
    ├── image.py      # CG010
    ├── mounts.py     # CG020-CG023
    ├── secrets.py    # CG030-CG032
    ├── network.py    # CG040
    ├── resources.py  # CG050-CG052
    └── sandbox.py    # CG060-CG061
```

`analyzer.analyze_file(path)` is the single entry point used by `cli.main`. It returns `list[Finding]`; each `Finding` has a stable `rule_id` (`CG###`), a `Severity`, a `message`, and a service name. Import `Severity`/`Finding` from `composeguard.analyzer` (backwards-compatible re-export) or `composeguard.models`. The CLI exits 1 when any finding meets or exceeds `--fail-on` (default `high`), and 2 when any input file could not be analyzed (missing, unreadable, invalid YAML) — this is the contract callers (CI users) depend on, so don't break it without bumping the major version.

## Security invariants (do not violate)

This tool parses YAML from untrusted sources (random GitHub repos, forum posts). The following hold across every change and are reflected in `SECURITY.md`:

- **`yaml.safe_load` only** — never `yaml.load`, never custom loaders that resolve tags.
- **1 MiB input cap** (`MAX_FILE_BYTES` in `analyzer.py`). Reject larger files before parsing.
- **Never `str()`/`repr()`/f-string a non-scalar YAML value.** YAML aliases let a ~500-byte file describe a 10⁹-element structure; `safe_load` builds it cheaply by sharing references, and stringifying is what expands it (billion laughs). Use `checks._values.scalar_str`, which returns `None` for containers. `test_alias_bomb_does_not_expand` guards this.
- **Parse failures are `ValueError`s, not crashes.** `_read_compose` converts YAML, UTF-8 and nesting-depth errors; the CLI reports them on stderr, keeps going, and exits 2.
- **No network calls.** No `requests`, `httpx`, `urllib.request` etc.
- **No subprocess execution.** No `subprocess`, `os.system`, shell-outs.
- **Read-only file access** to user-supplied paths. No writes outside `tmp_path` in tests.

If a feature seems to need any of these, stop and discuss with the user first.

## Adding a new rule

1. Write a `_check_*(name, svc) -> list[Finding]` function in the right `checks/` module and add it to that module's `CHECKS` tuple. Severity-graded rules use a module-level lookup table (see `_CAP_SEVERITY`, `_SENSITIVE_PATHS`, `_DEVICE_SEVERITY`, `_TOKEN_PATTERNS`).
2. Pick the next free `CG###` id. Convention:
   - `CG001–CG009`: process-privilege / namespace flags (`privileged`, host namespaces, `user:root`, `userns_mode`, hardening flags) — **full**; overflow goes to CG070+
   - `CG010–CG019`: image / supply-chain (unpinned tags, missing digest, `:latest`)
   - `CG020–CG029`: dangerous mounts and device passthrough (engine sockets, sensitive host paths, `devices:`, `device_cgroup_rules`)
   - `CG030–CG039`: secrets in configuration (env vars, build args)
   - `CG040–CG049`: network exposure (ports, host_ip)
   - `CG050–CG059`: resource limits / availability / operational hygiene (limits, OOM, logging)
   - `CG060–CG069`: MAC / sandbox bypass (AppArmor, seccomp, SELinux)
   - `CG070–CG079`: namespace / cgroup / kernel-tunable sharing (overflow of the full CG001–009 band)
3. Assign severity by criticality × exploitability: `critical` = hands over the host outright; `high` = strong escape/takeover surface; `medium` = meaningful weakening; `low` = hygiene/defense-in-depth. Rules that fire on the *absence* of hardening (like CG006/CG007/CG050) must be low, or the tool becomes too noisy to gate CI.
4. Add a positive test (rule fires, with the expected severity) and a negative test (rule does not fire on a clean config) in `tests/test_checks.py`. The `HARDENED_SERVICE` constant in `tests/helpers.py` is the negative-baseline; the new rule must not fire on it — prefer rules that only fire on explicitly-present misconfiguration. If you add a new missing-X rule, update `HARDENED_SERVICE` in the same commit.
5. If the rule changes CLI behavior or output, update `tests/test_cli.py`, the rule table here, the rule list in `README.md`, and the bad/good fixtures in `examples/` (regenerate `examples/README.md` output by actually running the CLI — don't hand-edit).

## Distribution

Two install paths, both pinned to a tag:

- `pipx install "git+https://github.com/NokiGuard/composeguard.git@vX.Y.Z"`
- `curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/vX.Y.Z/scripts/install.sh | sh` (script tries `uv tool install`, falls back to `pipx`)

When cutting a release, three files must agree on the version, then push the tag:

1. `[project].version` in `pyproject.toml`
2. `__version__` in `src/composeguard/__init__.py`
3. default `VERSION` in `scripts/install.sh`
4. the documented install URLs in `README.md` (the `@vX.Y.Z` and `/vX.Y.Z/` parts)
5. run `uv lock` so `uv.lock` reflects the new project version

Then `git tag -a vX.Y.Z -m "..."` and `git push origin vX.Y.Z`. CI will build on the tag; create a release with `gh release create vX.Y.Z --generate-notes`.
