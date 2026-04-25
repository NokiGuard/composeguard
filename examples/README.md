# Examples

Two compose files demonstrating the same homelab stack — one full of issues,
one hardened.

| File | Findings | Exit code (default `--fail-on high`) |
|---|---|---|
| [`insecure-compose.yml`](insecure-compose.yml) | 27 | `1` |
| [`hardened-compose.yml`](hardened-compose.yml) | 0 | `0` |

## Run it

From the repo root:

```bash
uv run composeguard examples/insecure-compose.yml
uv run composeguard examples/hardened-compose.yml
```

Or if installed via pipx / `uv tool install`:

```bash
composeguard examples/insecure-compose.yml
```

## What `composeguard` says about the bad file

```
LOW      examples/insecure-compose.yml::proxy    CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::proxy    CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::proxy    CG010  image 'nginx:latest' is unpinned (use a digest)
HIGH     examples/insecure-compose.yml::proxy    CG021  read-only mount of sensitive host path '/etc'
MEDIUM   examples/insecure-compose.yml::proxy    CG040  port '80:80' published on all interfaces (use a '127.0.0.1:' prefix)
MEDIUM   examples/insecure-compose.yml::proxy    CG040  port '443:443' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::proxy    CG050  no memory or CPU limit set (one runaway container can OOM the host)
CRITICAL examples/insecure-compose.yml::manager  CG001  privileged: true grants near-root host access
LOW      examples/insecure-compose.yml::manager  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::manager  CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::manager  CG010  image 'portainer/portainer-ce' is unpinned (use a digest)
CRITICAL examples/insecure-compose.yml::manager  CG020  docker.sock mount enables container escape
MEDIUM   examples/insecure-compose.yml::manager  CG040  port '9000:9000' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::manager  CG050  no memory or CPU limit set (one runaway container can OOM the host)
HIGH     examples/insecure-compose.yml::monitor  CG002  network_mode: host bypasses network isolation
HIGH     examples/insecure-compose.yml::monitor  CG003  pid: host shares the host PID namespace
HIGH     examples/insecure-compose.yml::monitor  CG005  ipc: host shares the host IPC namespace
CRITICAL examples/insecure-compose.yml::monitor  CG004  cap_add: 'SYS_ADMIN' grants a powerful capability
LOW      examples/insecure-compose.yml::monitor  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::monitor  CG007  read_only filesystem not enabled
LOW      examples/insecure-compose.yml::monitor  CG050  no memory or CPU limit set (one runaway container can OOM the host)
LOW      examples/insecure-compose.yml::db       CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::db       CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::db       CG030  env var 'POSTGRES_PASSWORD' looks like a secret with an inline value (use secrets/.env)
MEDIUM   examples/insecure-compose.yml::db       CG030  env var 'API_KEY' looks like a secret with an inline value (use secrets/.env)
MEDIUM   examples/insecure-compose.yml::db       CG040  port '5432:5432' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::db       CG050  no memory or CPU limit set (one runaway container can OOM the host)

27 finding(s) across 1 file(s).
```

### What it caught, by service

| Service | Highlights |
|---|---|
| `proxy` | `nginx:latest` (CG010), `/etc` mounted into the container (CG021), 80/443 bound to all interfaces (CG040) |
| `manager` | `privileged: true` + `docker.sock` mount — either alone is a root-equivalent escape path (CG001 + CG020) |
| `monitor` | host network/PID/IPC namespaces and `SYS_ADMIN` — sandbox effectively off (CG002, CG003, CG005, CG004) |
| `db` | passwords and API keys pasted as inline env vars (CG030), 5432 published on all interfaces (CG040) |

The `LOW` findings (CG006/CG007/CG050) fire on every service in the bad file because the hardened defaults aren't set — by default they don't fail the run, but they show up as a punch list.

## What `composeguard` says about the hardened file

```
0 finding(s) across 1 file(s).
```

Exit code `0`. Same workload, same services, all rules satisfied.

## Use it as a CI gate

```bash
# Block merges if any HIGH or CRITICAL finding exists (default).
composeguard compose.yml

# Stricter — only criticals fail the build, lower-severity findings are
# reported but allowed.
composeguard --fail-on critical compose.yml
```
