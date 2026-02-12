# streamdeck-homelab

A multi-page monitoring dashboard for the Elgato Stream Deck, designed to run on a Raspberry Pi and monitor homelab infrastructure.

## Features

- **Multi-page navigation** - 3 pages across 15 keys (keys 13/14 for prev/next)
- **Service health checks** - ping, TCP port, HTTP/HTTPS, DNS, SSH command
- **Host stats** - CPU and memory usage via SSH displayed in a 3-line layout
- **Remote actions** - restart services with double-press confirmation
- **Background polling** - parallel checks every 30 seconds with color-coded status (green = OK, red = DOWN, grey = checking)
- **Configurable** - all hosts, checks, and actions defined in a single `config.json`

## Pages

| Page | Purpose | Example Keys |
|------|---------|-------------|
| Services | Network & service status | WAN, DNS, pfSense, HAProxy, Pi-hole, Plex, etc. |
| Infrastructure | Host health & stats | ZFS pool, Proxmox quorum, per-node CPU/MEM |
| Actions | Remote control | Restart services, brightness, manual refresh |

## Requirements

- Raspberry Pi (or any Linux host) with USB
- Elgato Stream Deck (tested with Stream Deck Original, 15 keys)
- Python 3.9+

## Installation

```bash
# Install system dependencies
sudo apt-get install -y libhidapi-libusb0 libhidapi-dev

# Install Python packages
pip3 install streamdeck Pillow

# Set up udev rules for non-root access (optional)
echo 'SUBSYSTEM=="hidraw", MODE="0666"' | sudo tee /etc/udev/rules.d/99-streamdeck.rules
sudo udevadm control --reload-rules

# Clone the repo
git clone https://github.com/nath2125/streamdeck-homelab.git
cd streamdeck-homelab

# Copy and edit the config
cp config.example.json config.json
# Edit config.json with your actual host IPs, ports, and SSH users
```

## Configuration

Copy `config.example.json` to `config.json` and update it with your infrastructure details.

### Hosts

Define your hosts with IPs and optional per-host SSH users:

```json
"hosts": {
  "pfsense": { "ip": "10.0.0.1", "ssh_user": "admin" },
  "proxmox": { "ip": "10.0.0.2" }
}
```

Hosts without `ssh_user` fall back to the global `ssh_user` in settings (default: `root`).

### Check Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `ping` | ICMP ping | `target` (host alias or IP) |
| `tcp` | TCP port connect | `host`, `port` |
| `http` | HTTP GET check | `host` + `port`, or `url` |
| `https` | HTTPS GET (skip TLS verify) | `host`, `port` |
| `dns` | DNS resolution via dig | `target` (domain name) |
| `ssh_cmd` | Run command over SSH | `host`, `command` |
| `ssh_stats` | CPU/MEM stats over SSH | `host` |

#### Check options

- `expect` - for `ssh_cmd`, match this string in stdout to determine OK
- `status_only` - for `ssh_cmd`, show OK/FAIL instead of command output
- `path` - for `http`/`https`, URL path (default: `/`)

### Action Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `ssh_cmd` | Run SSH command on remote host | `host`, `command` |
| `brightness` | Set Stream Deck brightness | `level` (0-100) |
| `refresh` | Force re-run all checks | - |

Add `"confirm": true` to any action to require a double-press within 3 seconds.

## SSH Setup

For SSH-based checks and actions, run the included setup script:

```bash
bash setup_ssh.sh
```

This generates an SSH key and scans host keys. You then need to copy the public key to each host:

```bash
# For Linux hosts
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@<HOST_IP>

# For pfSense, add via web UI:
# System > User Manager > <user> > Authorized Keys
```

## Usage

```bash
python3 deck.py
```

The dashboard starts on Page 1 (Services), runs all checks immediately, then polls every 30 seconds. Press keys 13/14 to navigate pages.

## License

MIT
