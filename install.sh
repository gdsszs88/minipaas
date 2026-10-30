#!/usr/bin/env bash
set -euo pipefail

repo="${MINIPAAS_REPO:-gdsszs88/minipaas}"
url="https://raw.githubusercontent.com/${repo}/main/deploy/minipaas-cli.sh"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"
install -m 0755 "$tmp" /usr/local/bin/minipaas
exec /usr/local/bin/minipaas install "$@"
