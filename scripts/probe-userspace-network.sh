#!/bin/bash
# Checks userspace networking without a VM: starts gvproxy, plays the part of a guest NIC, and opens a TCP
# connection to 192.168.127.254:PORT, which must reach a listener on this Mac's 127.0.0.1:PORT.
# Run it with the VPN connected to see whether the VPN client interferes.
#   bash scripts/probe-userspace-network.sh /path/to/gvproxy
set -euo pipefail
gvproxy="${1:-${TERMINAL_MAC_GVPROXY:-}}"
[[ -x "$gvproxy" ]] || { echo 'Usage: probe-userspace-network.sh /path/to/gvproxy' >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d /tmp/tm-probe.XXXXXX)"
pid=""
trap '[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT
port=$((20000 + RANDOM % 20000))
"$gvproxy" -listen-vfkit "unixgram://$work/gv.sock" -ssh-port -1 >"$work/gv.log" 2>&1 &
pid=$!
for _ in $(seq 1 50); do [[ -S "$work/gv.sock" ]] && break; sleep 0.1; done
[[ -S "$work/gv.sock" ]] || { echo 'gvproxy did not start:' >&2; cat "$work/gv.log" >&2; exit 1; }
python3 -I "$here/probe-userspace-network.py" "$work/gv.sock" "$work/vm.sock" "$port"
