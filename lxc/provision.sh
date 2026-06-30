#!/usr/bin/env bash
# Creates and configures a caddy LXC on Proxmox VE. Run on the host as root.
set -euo pipefail
VMID="${1:?Usage: $0 <vmid> [options]}"
# TODO: pct create / config / install caddy. Mirror jellyfin/lxc/provision.sh.
echo "[provision] caddy LXC $VMID — not yet implemented"
