#!/usr/bin/env sh
# composeguard installer
#
# This script installs composeguard into an isolated venv using either
# `uv tool install` (preferred) or `pipx`. It pins to a specific tag so
# that curl-piping is reproducible.
#
# Review before running:
#   curl -fsSL https://raw.githubusercontent.com/NokiGuard/composeguard/v0.1.1/scripts/install.sh -o install.sh
#   less install.sh
#   sh install.sh

set -eu

REPO="${COMPOSEGUARD_REPO:-NokiGuard/composeguard}"
VERSION="${COMPOSEGUARD_VERSION:-v0.1.1}"
SOURCE="git+https://github.com/${REPO}.git@${VERSION}"

log() { printf '[composeguard] %s\n' "$1" >&2; }
die() { log "error: $1"; exit 1; }

case "$VERSION" in
    v[0-9]*) ;;
    *) die "VERSION must be a tag like v0.1.0 (got: ${VERSION})" ;;
esac

if command -v uv >/dev/null 2>&1; then
    log "installing ${SOURCE} via uv tool install"
    uv tool install --force "${SOURCE}"
elif command -v pipx >/dev/null 2>&1; then
    log "installing ${SOURCE} via pipx"
    pipx install --force "${SOURCE}"
else
    die "neither 'uv' nor 'pipx' found. Install one first:
  https://docs.astral.sh/uv/getting-started/installation/
  https://pipx.pypa.io/stable/installation/"
fi

if command -v composeguard >/dev/null 2>&1; then
    log "installed: $(composeguard --version)"
else
    log "installed, but 'composeguard' is not on PATH yet."
    log "ensure your tool bin dir is on PATH (uv: ~/.local/bin, pipx: pipx ensurepath)."
fi
