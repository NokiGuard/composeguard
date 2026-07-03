# composeguard

Static analyzer for `docker-compose.yml` that flags insecure configurations
before deployment. Built for homelabbers who copy-paste Compose files from
GitHub and forums and rarely audit them.

## What it catches

28 rules across the most common docker-compose security issues:

- `privileged: true`, dangerous capabilities (tiered SYS_ADMIN → SYSLOG), and `cap_add` without `cap_drop: [ALL]`
- Container-engine socket exposure — docker.sock in both `/var/run` and `/run` forms, containerd/podman/balena sockets, and parent-dir mounts that contain them (read-only doesn't help)
- Host network / PID / IPC / UTS / cgroup namespaces, `userns_mode: host`, and joining another container's namespace (`container:` / `service:`)
- Explicit `user: root` / `user: "0"`
- Host devices passed into containers, tiered by risk — `/dev/mem` is critical, raw disks are high, GPU/USB peripherals are low
- Permissive `device_cgroup_rules` (`a *:* rwm`)
- AppArmor, seccomp, or SELinux disabled via `security_opt`
- Missing `read_only`, missing `no-new-privileges:true`
- Unpinned images (`:latest`, no digest)
- Secrets pasted inline in environment variables or `build.args` — including token-shape detection (GitHub/AWS/Slack/GitLab tokens, JWTs, PEM keys) regardless of the variable name
- Ports published on all interfaces (IPv4 `0.0.0.0` and IPv6 `::`)
- Missing CPU/memory limits, OOM killer disabled, logging driver `none`
- Dangerous mounts of sensitive host paths (`/`, `/etc`, `/root`, `/var/lib/docker`, kernel/system surfaces)
- Relaxed network sysctls (`net.ipv4.ip_unprivileged_port_start=0`)

Four severity levels (`critical`, `high`, `medium`, `low`), graded by how
directly the issue converts to host compromise; see [`CLAUDE.md`](CLAUDE.md)
for the rule-by-rule severity table.

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
curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/v0.3.0/scripts/install.sh -o install.sh
less install.sh
sh install.sh

# B. Direct via uv:
uv tool install "git+https://github.com/NokiGuard/composeguard.git@v0.3.0"

# C. Direct via pipx:
pipx install "git+https://github.com/NokiGuard/composeguard.git@v0.3.0"
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
(default: `high`, which also fails on `critical`), making it suitable
for CI gates. Severity is colored when stdout is a TTY (override with
`--color always|never`; honors `NO_COLOR`).

See [`examples/`](examples/) for a side-by-side bad/good homelab stack
and an annotated walk-through of what the tool flags.

## Security

This tool parses untrusted YAML. See [SECURITY.md](SECURITY.md) for the
threat model and how to report vulnerabilities.
