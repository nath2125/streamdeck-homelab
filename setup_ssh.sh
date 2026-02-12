#!/bin/bash
# Stream Deck SSH Setup Script
# Generates SSH keys and prepares access to all monitored hosts
#
# Usage: Edit the HOSTS array below with your infrastructure IPs,
# then run: bash setup_ssh.sh

set -e

KEY_FILE="$HOME/.ssh/id_ed25519"
CONFIG_FILE="$(dirname "$0")/config.json"

# Auto-extract hosts from config.json if it exists, otherwise use examples
if [ -f "$CONFIG_FILE" ] && command -v python3 &>/dev/null; then
    mapfile -t HOSTS < <(python3 -c "
import json
with open('$CONFIG_FILE') as f:
    config = json.load(f)
for name, entry in config.get('hosts', {}).items():
    ip = entry.get('ip', entry) if isinstance(entry, dict) else entry
    user = entry.get('ssh_user', '') if isinstance(entry, dict) else ''
    print(f'{ip}|{user}|{name}')
" 2>/dev/null)
else
    echo "No config.json found. Create one from config.example.json first."
    echo "  cp config.example.json config.json"
    echo "  # Edit config.json with your host IPs"
    exit 1
fi

echo "=== Stream Deck SSH Setup ==="
echo

# Step 1: Generate SSH key if needed
if [ -f "$KEY_FILE" ]; then
    echo "[OK] SSH key already exists: $KEY_FILE"
else
    echo "[*] Generating SSH key..."
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "streamdeck@$(hostname)"
    echo "[OK] SSH key generated."
fi

echo
echo "=== Your public key ==="
echo
cat "${KEY_FILE}.pub"
echo
echo "=== Copy this key to each host ==="
echo
echo "For Linux hosts:"
echo "  ssh-copy-id -i ${KEY_FILE}.pub <user>@<HOST_IP>"
echo
echo "For pfSense/OPNsense, add the public key via the web UI:"
echo "  System > User Manager > <user> > Authorized Keys"
echo
echo "Hosts from your config.json:"
for entry in "${HOSTS[@]}"; do
    IFS='|' read -r ip user name <<< "$entry"
    user=${user:-root}
    echo "  - $ip ($name) -> ssh-copy-id -i ${KEY_FILE}.pub ${user}@${ip}"
done

# Step 2: Scan host keys
echo
echo "=== Scanning host keys ==="
mkdir -p "$HOME/.ssh"
for entry in "${HOSTS[@]}"; do
    IFS='|' read -r ip user name <<< "$entry"
    echo -n "  Scanning $ip ($name)... "
    if ssh-keyscan -T 3 "$ip" >> "$HOME/.ssh/known_hosts" 2>/dev/null; then
        echo "OK"
    else
        echo "UNREACHABLE (will retry later)"
    fi
done

# Deduplicate known_hosts
sort -u "$HOME/.ssh/known_hosts" -o "$HOME/.ssh/known_hosts" 2>/dev/null || true

echo
echo "=== Done ==="
echo "After copying the key to all hosts, test with:"
echo "  ssh -o BatchMode=yes root@<HOST_IP> hostname"
