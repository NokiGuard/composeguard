# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately via GitHub Security Advisories:
<https://github.com/NokiGuard/composeguard/security/advisories/new>

We aim to acknowledge reports within 5 business days and to ship a fix or
mitigation for confirmed issues within 30 days, depending on severity.

## Supported versions

Only the latest minor release of `composeguard` receives security updates
during the 0.x series.

## Threat model

`composeguard` parses `docker-compose.yml` files which may come from
untrusted sources. The tool is designed with these guarantees:

- YAML is parsed with `yaml.safe_load` only.
- Input files are size-capped (see `MAX_FILE_BYTES`).
- No network calls are made.
- No subprocess execution.
- File access is read-only and limited to user-supplied paths.

If you find a way to violate any of these guarantees, please report it.
