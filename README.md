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

### Recommended: pipx from a tagged release

```bash
pipx install "git+https://github.com/NokiGuard/composeguard.git@v0.1.0"
```

### Curl install script

Inspect the script first, then run it:

```bash
curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/v0.1.0/scripts/install.sh -o install.sh
less install.sh
sh install.sh
```

The installer pulls a pinned tag and installs into an isolated venv via
`uv tool install` (preferred) or `pipx`.

## Usage

```bash
composeguard docker-compose.yml
composeguard --fail-on medium service-a/compose.yml service-b/compose.yml
```

Exit code is non-zero when a finding meets or exceeds `--fail-on`
(default: `high`), making it suitable for CI gates.

See [`examples/`](examples/) for a side-by-side bad/good homelab stack
and an annotated walk-through of what the tool flags.

## Security

This tool parses untrusted YAML. See [SECURITY.md](SECURITY.md) for the
threat model and how to report vulnerabilities.
