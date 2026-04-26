# CLAUDE.md — composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations. Python 3.12 CLI built secure-by-default. `BRIEF.md` is the original spec — all of its rules are implemented as of CG001–CG060, plus five additional checks beyond the brief.

## Severity scheme

Three levels only: `low`, `medium`, `high`. Compare via `Severity.rank` (LOW=0, MEDIUM=1, HIGH=2), not by name. The CLI's `--fail-on` defaults to `high`, so LOW and MEDIUM findings are surfaced but do not fail CI by default.

## Implemented rules

| ID | Severity | What it flags |
|---|---|---|
| CG001 | high | `privileged: true` |
| CG002 | high | `network_mode: host` |
| CG003 | high | `pid: host` |
| CG004 | high / medium | dangerous Linux capabilities in `cap_add` (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, SYS_BOOT, MAC_*=high; SYS_TIME, DAC_*, AUDIT_*=medium) |
| CG005 | high | `ipc: host` |
| CG006 | low | missing `security_opt: no-new-privileges:true` |
| CG007 | low | missing `read_only: true` |
| CG008 | high | explicit `user: root` / `user: "0"` / `user: "0:0"` |
| CG009 | high | `userns_mode: host` |
| CG010 | medium | unpinned image (`:latest` or no digest) |
| CG011 | low | `cap_add` is set without `cap_drop: [ALL]` (defense-in-depth) |
| CG020 | high | `/var/run/docker.sock` mount |
| CG021 | high / medium / low | mount of sensitive host path. `/`, `/etc`, `/root` = high (rw or ro); kernel/system paths (`/sys`, `/proc`, `/dev`, `/usr`, `/lib*`, `/sbin`, `/bin`, `/boot`) = high writable / medium read-only; `/var`, `/home` = medium writable / low read-only |
| CG022 | high | host device passed into container via `devices:` |
| CG030 | medium | secret-looking env var (PASSWORD/SECRET/TOKEN/API_KEY/etc.) with an inline value (vs. `${VAR}` placeholder) |
| CG040 | medium | port published to all interfaces (no `host_ip` or `0.0.0.0`) |
| CG050 | low | no memory or CPU limit set |
| CG060 | high | `security_opt` disables AppArmor (`apparmor=unconfined`) or seccomp (`seccomp=unconfined`) |

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
├── cli.py        # argparse, exit-code logic, --fail-on threshold, ANSI coloring
├── analyzer.py   # YAML loading + per-service rule checks; emits Finding objects
└── checks/       # (placeholder) split rules out once analyzer.py grows past ~20 rules
```

`analyzer.analyze_file(path)` is the single entry point used by `cli.main`. It returns `list[Finding]`; each `Finding` has a stable `rule_id` (`CG###`), a `Severity`, a `message`, and a service name. The CLI exits non-zero when any finding meets or exceeds `--fail-on` (default `high`) — this is the contract callers (CI users) depend on, so don't break it without bumping the major version.

## Security invariants (do not violate)

This tool parses YAML from untrusted sources (random GitHub repos, forum posts). The following hold across every change and are reflected in `SECURITY.md`:

- **`yaml.safe_load` only** — never `yaml.load`, never custom loaders that resolve tags.
- **1 MiB input cap** (`MAX_FILE_BYTES` in `analyzer.py`). Reject larger files before parsing.
- **No network calls.** No `requests`, `httpx`, `urllib.request` etc.
- **No subprocess execution.** No `subprocess`, `os.system`, shell-outs.
- **Read-only file access** to user-supplied paths. No writes outside `tmp_path` in tests.

If a feature seems to need any of these, stop and discuss with the user first.

## Adding a new rule

1. Append a check to `_check_service` in `analyzer.py` (or pull rules into `checks/` once there are >~20).
2. Pick the next free `CG###` id. Convention so far:
   - `CG001–CG009`: process-privilege / namespace flags (`privileged`, host namespaces, `user:root`, `userns_mode`, hardening flags)
   - `CG010–CG019`: image / supply-chain (unpinned tags, missing digest, `:latest`)
   - `CG020–CG029`: dangerous mounts and device passthrough (docker.sock, sensitive host paths, `devices:`)
   - `CG030–CG039`: secrets in configuration
   - `CG040–CG049`: network exposure (ports, host_ip)
   - `CG050–CG059`: resource limits / availability
   - `CG060–CG069`: MAC / sandbox bypass (AppArmor, seccomp)
3. Add a positive test (rule fires) and a negative test (rule does not fire on a clean config) in `tests/test_analyzer.py`. The `HARDENED_SERVICE` constant is the negative-baseline; the new rule must not fire on it.
4. If the rule changes CLI behavior or output, update `tests/test_cli.py` and the rule list in `README.md` and the bad/good fixtures in `examples/`.

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
