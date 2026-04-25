# CLAUDE.md — composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations. Python 3.12 CLI built secure-by-default. The user-facing rule list lives in `BRIEF.md`; treat it as the backlog of rule IDs to implement.

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
uv run pip-audit --strict --disable-pip  # vuln-scan deps
uv run composeguard <file.yml>       # invoke the CLI from source
```

CI (`.github/workflows/ci.yml`) runs the same lint → typecheck → test → bandit → pip-audit pipeline; CodeQL runs separately. Pre-commit (`.pre-commit-config.yaml`) wires the same checks plus gitleaks.

## Architecture

Single-purpose CLI; the core is small.

```
src/composeguard/
├── cli.py        # argparse, exit-code logic, --fail-on threshold
├── analyzer.py   # YAML loading + per-service rule checks; emits Finding objects
└── checks/       # (placeholder) split rules out as the analyzer grows
```

`analyzer.analyze_file(path)` is the single entry point used by `cli.main`. It returns `list[Finding]`; each `Finding` has a stable `rule_id` (`CG###`), a `Severity`, a `message`, and a service name. The CLI exits non-zero when any finding meets or exceeds `--fail-on` (default `high`) — this is the contract callers (CI users) depend on, so don't break it without bumping the major version.

Severity ordering: `info < low < medium < high < critical`. Compare via `Severity.rank`, not name.

## Security invariants (do not violate)

This tool parses YAML from untrusted sources (random GitHub repos, forum posts). The following hold across every change and are reflected in `SECURITY.md`:

- **`yaml.safe_load` only** — never `yaml.load`, never custom loaders that resolve tags.
- **1 MiB input cap** (`MAX_FILE_BYTES` in `analyzer.py`). Reject larger files before parsing.
- **No network calls.** No `requests`, `httpx`, `urllib.request` etc.
- **No subprocess execution.** No `subprocess`, `os.system`, shell-outs.
- **Read-only file access** to user-supplied paths. No writes outside `tmp_path` in tests.

If a feature seems to need any of these, stop and discuss with the user first.

## Adding a new rule

1. Append a check to `_check_service` in `analyzer.py` (or pull rules into `checks/` once there are >~10).
2. Pick the next free `CG###` id. Convention so far:
   - `CG001–CG009`: privilege/namespace flags (`privileged`, `network_mode: host`, `pid: host`, capabilities, `security_opt`)
   - `CG010–CG019`: image/supply-chain (unpinned tags, missing digest, `:latest`)
   - `CG020–CG029`: dangerous mounts (docker.sock, sensitive host paths)
   - `CG030+`: secrets, ports, resource limits — open ranges
3. Add a positive test (rule fires) and a negative test (rule does not fire on a clean config) in `tests/test_analyzer.py`.
4. If the rule changes CLI behavior or output, update `tests/test_cli.py` and the rule list in `README.md`.

## Distribution

Two install paths, both pinned to a tag:

- `pipx install "git+https://github.com/NokiGuard/composeguard.git@vX.Y.Z"`
- `curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/vX.Y.Z/scripts/install.sh | sh` (script tries `uv tool install`, falls back to `pipx`)

When cutting a release: bump `[project].version` in `pyproject.toml` *and* `__version__` in `src/composeguard/__init__.py` *and* the default `VERSION` in `scripts/install.sh` — they must agree, then tag `vX.Y.Z`.
