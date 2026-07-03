# Examples

Two compose files demonstrating the same homelab stack — one full of issues,
one hardened. The bad file exercises every rule the tool currently ships.

| File | Findings | Exit code (default `--fail-on high`) |
|---|---|---|
| [`insecure-compose.yml`](insecure-compose.yml) | 49 | `1` |
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
LOW      examples/insecure-compose.yml::proxy  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::proxy  CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::proxy  CG010  image 'nginx:latest' is unpinned (use a digest)
HIGH     examples/insecure-compose.yml::proxy  CG021  read-only mount of sensitive host path '/etc'
MEDIUM   examples/insecure-compose.yml::proxy  CG040  port '80:80' published on all interfaces (use a '127.0.0.1:' prefix)
MEDIUM   examples/insecure-compose.yml::proxy  CG040  port '443:443' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::proxy  CG050  no memory or CPU limit set (one runaway container can OOM the host)
HIGH     examples/insecure-compose.yml::proxy  CG060  security_opt disables AppArmor ('apparmor=unconfined')
CRITICAL examples/insecure-compose.yml::manager  CG001  privileged: true disables all isolation — trivial full host compromise
LOW      examples/insecure-compose.yml::manager  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::manager  CG007  read_only filesystem not enabled
HIGH     examples/insecure-compose.yml::manager  CG070  cgroup: host joins the host cgroup namespace (resource controls exposed)
MEDIUM   examples/insecure-compose.yml::manager  CG010  image 'portainer/portainer-ce' is unpinned (use a digest)
CRITICAL examples/insecure-compose.yml::manager  CG020  mount of '/var/run/docker.sock' exposes the container engine socket (/run/docker.sock) — root on the host via the engine API; read-only does not help
MEDIUM   examples/insecure-compose.yml::manager  CG040  port '9000:9000' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::manager  CG050  no memory or CPU limit set (one runaway container can OOM the host)
HIGH     examples/insecure-compose.yml::monitor  CG002  network_mode: host bypasses network isolation
HIGH     examples/insecure-compose.yml::monitor  CG003  pid: host shares the host PID namespace
HIGH     examples/insecure-compose.yml::monitor  CG005  ipc: host shares the host IPC namespace
CRITICAL examples/insecure-compose.yml::monitor  CG004  cap_add: 'SYS_ADMIN' grants a powerful capability
LOW      examples/insecure-compose.yml::monitor  CG011  cap_add is used without cap_drop: [ALL] (defense-in-depth)
LOW      examples/insecure-compose.yml::monitor  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::monitor  CG007  read_only filesystem not enabled
HIGH     examples/insecure-compose.yml::monitor  CG008  user is set to root ('0') — drop privileges with a non-zero UID
HIGH     examples/insecure-compose.yml::monitor  CG009  userns_mode: host disables user-namespace remapping (UID 0 maps to host root)
MEDIUM   examples/insecure-compose.yml::monitor  CG071  uts: host shares the host UTS namespace (hostname/domain writable)
LOW      examples/insecure-compose.yml::monitor  CG073  sysctl net.ipv4.ip_unprivileged_port_start=0 weakens network hardening
LOW      examples/insecure-compose.yml::monitor  CG050  no memory or CPU limit set (one runaway container can OOM the host)
LOW      examples/insecure-compose.yml::media  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::media  CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::media  CG010  image 'jellyfin/jellyfin' is unpinned (use a digest)
LOW      examples/insecure-compose.yml::media  CG022  host device '/dev/dri/renderD128' passed into container — peripheral passthrough
LOW      examples/insecure-compose.yml::media  CG050  no memory or CPU limit set (one runaway container can OOM the host)
LOW      examples/insecure-compose.yml::db  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::db  CG007  read_only filesystem not enabled
CRITICAL examples/insecure-compose.yml::db  CG023  device_cgroup_rules 'a *:* rwm' allows access to all host devices
MEDIUM   examples/insecure-compose.yml::db  CG030  env var 'POSTGRES_PASSWORD' looks like a secret with an inline value (use secrets/.env)
MEDIUM   examples/insecure-compose.yml::db  CG030  env var 'API_KEY' looks like a secret with an inline value (use secrets/.env)
HIGH     examples/insecure-compose.yml::db  CG031  env var 'GITHUB_TOKEN' contains what looks like a GitHub token (use secrets/.env)
MEDIUM   examples/insecure-compose.yml::db  CG040  port '5432:5432' published on all interfaces (use a '127.0.0.1:' prefix)
LOW      examples/insecure-compose.yml::db  CG050  no memory or CPU limit set (one runaway container can OOM the host)
LOW      examples/insecure-compose.yml::db  CG051  oom_kill_disable: true lets a leaking container stall the host under OOM
LOW      examples/insecure-compose.yml::db  CG052  logging driver 'none' discards all container logs (no audit trail)
LOW      examples/insecure-compose.yml::ci  CG006  missing security_opt 'no-new-privileges:true' (lets setuid binaries escalate)
LOW      examples/insecure-compose.yml::ci  CG007  read_only filesystem not enabled
MEDIUM   examples/insecure-compose.yml::ci  CG072  network_mode: 'service:db' shares another container's namespace (lateral movement between services)
MEDIUM   examples/insecure-compose.yml::ci  CG032  build arg 'NPM_TOKEN' looks like a secret — build args are baked into image layers
LOW      examples/insecure-compose.yml::ci  CG050  no memory or CPU limit set (one runaway container can OOM the host)
HIGH     examples/insecure-compose.yml::ci  CG061  security_opt disables SELinux label confinement ('label=disable')

49 finding(s) across 1 file(s).
```

When stdout is a TTY the severity column is colored (CRITICAL = bold
magenta, HIGH = bold red, MEDIUM = yellow, LOW = grey).

### What it caught, by service

| Service | Highlights |
|---|---|
| `proxy` | `nginx:latest` (CG010), `/etc` mounted into the container (CG021), 80/443 bound to all interfaces (CG040), AppArmor disabled (CG060) |
| `manager` | `privileged: true` + `docker.sock` mount — either alone is root on the host, so both are CRITICAL (CG001 + CG020); plus the host cgroup namespace (CG070) |
| `monitor` | host network/PID/IPC/UTS namespaces, `SYS_ADMIN` (CRITICAL) without `cap_drop: [ALL]`, explicit `user: 0`, `userns_mode: host`, and an unprivileged-port sysctl — sandbox effectively off (CG002–CG011, CG071, CG073) |
| `media` | host GPU device passed into the container (CG022) — deliberately LOW: `/dev/dri` passthrough is common for media stacks and comparatively benign, so it no longer fails a default CI gate |
| `db` | passwords pasted as inline env vars (CG030), a real GitHub-token shape (CG031, HIGH regardless of the key name), an all-devices cgroup rule (CG023, CRITICAL), OOM killer and logging both turned off (CG051/CG052) |
| `ci` | registry token baked into image layers via `build.args` (CG032), SELinux confinement off (CG061), and piggybacking on the db's network namespace (CG072) |

The `LOW` findings (CG006/CG007/CG011/CG050) fire on every service in the
bad file because the hardened defaults aren't set — by default they
don't fail the run, but they show up as a punch list.

## What `composeguard` says about the hardened file

```
0 finding(s) across 1 file(s).
```

Exit code `0`. Same workload, same services, all rules satisfied.

## Use it as a CI gate

```bash
# Default: any HIGH or CRITICAL finding fails the build (LOW + MEDIUM are reported).
composeguard compose.yml

# Strictest — every finding fails the build.
composeguard --fail-on low compose.yml

# Loosest — only CRITICAL (root-on-host issues) fails the build.
composeguard --fail-on critical compose.yml
```
