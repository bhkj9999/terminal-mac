#!/bin/bash
# Downloads gvproxy for macOS from the official gvisor-tap-vsock release and verifies its SHA-256.
#   bash scripts/fetch-gvproxy.sh [destination]      (default: ~/.local/bin/gvproxy)
set -euo pipefail
version=v0.9.0
sha256=e2a6825ba789fe588828b418c09aaf16525dec6d8cb2d16c94e72535dd4606be
dest="${1:-$HOME/.local/bin/gvproxy}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fL --progress-bar "https://github.com/containers/gvisor-tap-vsock/releases/download/$version/gvproxy-darwin" -o "$tmp"
echo "$sha256  $tmp" | shasum -a 256 -c - >/dev/null || { echo 'Checksum mismatch; nothing was installed.' >&2; exit 1; }
mkdir -p "$(dirname "$dest")"
install -m 755 "$tmp" "$dest"
echo "Installed $dest"
