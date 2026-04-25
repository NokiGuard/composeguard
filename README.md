# composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations
before deployment. Built for homelabbers who copy-paste Compose files from
GitHub and forums and rarely audit them.

## What it catches

- `privileged: true` and dangerous capabilities
- Docker socket mounts (`/var/run/docker.sock`) — container escape risk
- Host network / PID / IPC namespaces
- Missing `read_only`, missing `no-new-privileges`
- Unpinned images (`:latest`, no digest)
- Secrets in environment variables
- Exposed ports on `0.0.0.0` when a reverse proxy is present
- Missing CPU/memory limits
- Writable mounts of sensitive host paths (`/etc`, `/`, `/root`)

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
curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/v0.1.1/scripts/install.sh -o install.sh
less install.sh
sh install.sh

# B. Direct via uv:
uv tool install "git+https://github.com/NokiGuard/composeguard.git@v0.1.1"

# C. Direct via pipx:
pipx install "git+https://github.com/NokiGuard/composeguard.git@v0.1.1"
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
