A CLI that statically analyzes docker-compose.yml files and flags insecure configurations before deployment. Homelabbers copy-paste Compose files from GitHub/forums constantly and rarely audit them. Your tool would catch:

privileged: true, dangerous capabilities (SYS_ADMIN, NET_ADMIN where not needed)
Docker socket mounts (/var/run/docker.sock) — container escape risk
Host network mode, host PID/IPC namespaces
Missing read_only, missing no-new-privileges
Images without pinned digests, :latest tags
Secrets in environment variables (API keys, passwords)
Exposed ports on 0.0.0.0 vs 127.0.0.1 when a reverse proxy is present
Missing resource limits (memory/CPU — homelab OOM killer fodder)
Writable volumes mounted from sensitive host paths (/etc, /, /root)