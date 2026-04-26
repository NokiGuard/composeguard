# composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations
before deployment. Built for homelabbers who copy-paste Compose files from
GitHub and forums and rarely audit them.

## What it catches

18 rules across the most common docker-compose security issues:

- `privileged: true`, dangerous capabilities, and `cap_add` without `cap_drop: [ALL]`
- Docker socket mounts (`/var/run/docker.sock`) — container escape risk
- Host network / PID / IPC namespaces, and `userns_mode: host`
- Explicit `user: root` / `user: "0"`
- Host devices passed into containers (`/dev/...`)
- AppArmor or seccomp disabled via `security_opt`
- Missing `read_only`, missing `no-new-privileges:true`
- Unpinned images (`:latest`, no digest)
- Secrets pasted inline in environment variables
- Ports published on all interfaces (no `host_ip` / `0.0.0.0`)
- Missing CPU/memory limits
- Writable mounts of sensitive host paths (`/`, `/etc`, `/root`, kernel/system surfaces)

Three severity levels (`high`, `medium`, `low`); see [`CLAUDE.md`](CLAUDE.md) for
the rule-by-rule severity table.

## Install

### Prerequisites

You need either [`uv`](https://docs.astral.sh/uv/) (recommended) or
[`pipx`](https://pipx.pypa.io/) on your machine. Both will set up
`composeguard` in an isolated environment so it doesn't pollute your
system Python.

**Install `uv` on Linux / macOS:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

`uv` will also fetch Python 3.12 on demand if your system Python is
older — no separate Python install needed.

### Install composeguard

Pick **one** of these:

```bash
# A. Curl install script (review first, then run):
curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/v0.2.0/scripts/install.sh -o install.sh
less install.sh
sh install.sh

# B. Direct via uv:
uv tool install "git+https://github.com/NokiGuard/composeguard.git@v0.2.0"

# C. Direct via pipx:
pipx install "git+https://github.com/NokiGuard/composeguard.git@v0.2.0"
```

All three install the same thing. The script just picks `uv` if
available, otherwise `pipx`.

### Verify the install

`composeguard` is installed onto your `PATH` (typically `~/.local/bin`),
so you call it by name from **any** directory — no `./composeguard` and
no need to be inside the repo:

```bash
composeguard --version
composeguard /path/to/docker-compose.yml
```

If `composeguard --version` reports "command not found" right after
install, your tool bin dir isn't on `PATH` yet. Fix it once with:

```bash
uv tool update-shell    # if you used uv
pipx ensurepath         # if you used pipx
```

…then open a new shell.

## Usage

```bash
composeguard docker-compose.yml
composeguard --fail-on medium service-a/compose.yml service-b/compose.yml
composeguard --color never compose.yml > findings.txt    # plain output
```

Exit code is non-zero when a finding meets or exceeds `--fail-on`
(default: `high`), making it suitable for CI gates. Severity is colored
when stdout is a TTY (override with `--color always|never`; honors
`NO_COLOR`).

See [`examples/`](examples/) for a side-by-side bad/good homelab stack
and an annotated walk-through of what the tool flags.

## Security

This tool parses untrusted YAML. See [SECURITY.md](SECURITY.md) for the
threat model and how to report vulnerabilities.
