#!/usr/bin/env python3
"""Stream Deck monitoring dashboard for homelab infrastructure.

Displays service statuses across multiple pages, runs background health checks,
and provides action buttons with confirmation for remote operations.
"""

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from PIL import Image, ImageDraw, ImageFont
from StreamDeck.DeviceManager import DeviceManager
from StreamDeck.ImageHelpers import PILHelper

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

COLOR_OK = "#004400"
COLOR_DOWN = "#440000"
COLOR_UNKNOWN = "#333333"
COLOR_CONFIRM = "#665500"
COLOR_ACTION = "#1a1a2e"
COLOR_NAV = "#0a0a1a"
COLOR_RUNNING = "#000044"

NAV_PREV_KEY = 13
NAV_NEXT_KEY = 14
WATCHDOG_INTERVAL = 3   # seconds between health checks
MAX_RETRIES = 10
RETRY_DELAY = 2  # seconds between restart attempts


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def recover_usb():
    """Attempt to recover a stale Stream Deck USB connection."""
    print("[recovery] Attempting USB device recovery...")

    # Try usbreset first
    try:
        result = subprocess.run(
            ["usbreset", "0fd9:0080"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print("[recovery] USB reset sent")
    except Exception:
        pass

    time.sleep(2)

    # If hidraw device is missing, force USB re-enumeration
    if not os.path.exists("/dev/hidraw0"):
        print("[recovery] /dev/hidraw0 missing, forcing USB re-enumeration...")
        for devdir in os.listdir("/sys/bus/usb/devices/"):
            vendor_path = f"/sys/bus/usb/devices/{devdir}/idVendor"
            try:
                with open(vendor_path) as f:
                    if f.read().strip() == "0fd9":
                        config_path = f"/sys/bus/usb/devices/{devdir}/bConfigurationValue"
                        with open(config_path, "w") as cf:
                            cf.write("1")
                        print(f"[recovery] Re-enumerated USB device {devdir}")
                        time.sleep(2)
                        break
            except (FileNotFoundError, PermissionError, OSError):
                continue

    if os.path.exists("/dev/hidraw0"):
        print("[recovery] /dev/hidraw0 is back")
        return True
    else:
        print("[recovery] Failed to recover USB device")
        return False


# ---------------------------------------------------------------------------
# Check engine
# ---------------------------------------------------------------------------
def resolve_host(host, hosts_map):
    """Resolve a host alias to an IP using the hosts map, or return as-is."""
    entry = hosts_map.get(host)
    if entry is None:
        return host
    if isinstance(entry, dict):
        return entry.get("ip", host)
    return entry


def get_ssh_user(host, hosts_map, default_user="root"):
    """Get the SSH user for a host, checking per-host override first."""
    entry = hosts_map.get(host)
    if isinstance(entry, dict):
        return entry.get("ssh_user", default_user)
    return default_user


def check_ping(target, hosts_map, timeout=2):
    """ICMP ping check. Returns (ok: bool, detail: str)."""
    ip = resolve_host(target, hosts_map)
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 1
        )
        if result.returncode == 0:
            # Extract RTT from ping output
            for line in result.stdout.splitlines():
                if "time=" in line:
                    ms = line.split("time=")[1].split()[0]
                    return True, f"ONLINE|{ms}ms"
            return True, "ONLINE|"
        return False, "OFFLINE|"
    except Exception:
        return False, "OFFLINE|"


def check_tcp(host, port, hosts_map, timeout=3):
    """TCP port connectivity check."""
    ip = resolve_host(host, hosts_map)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True, "OK"
    except Exception:
        return False, "DOWN"


def check_http(url=None, host=None, port=None, path="/", hosts_map=None, timeout=5, use_https=False):
    """HTTP(S) GET check. Returns (ok, detail)."""
    hosts_map = hosts_map or {}
    if url is None:
        ip = resolve_host(host, hosts_map)
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{ip}:{port}{path}"
    try:
        import urllib.request
        ctx = None
        if url.startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "StreamDeck-Monitor/1.0")
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        code = resp.getcode()
        if 200 <= code < 400:
            return True, "OK"
        return False, f"HTTP {code}"
    except Exception as e:
        err = str(e)
        if "SSL" in err or "certificate" in err.lower():
            # SSL errors on a reachable host still mean service is up
            return True, "OK(ssl)"
        return False, "DOWN"


def check_dns(target, timeout=3):
    """DNS resolution check using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", target],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if output and result.returncode == 0:
            return True, "OK"
        return False, "FAIL"
    except Exception:
        return False, "FAIL"


def check_ssh_cmd(host, command, hosts_map, ssh_user="root", timeout=5, expect=None, status_only=False):
    """Run a command over SSH and check result."""
    ip = resolve_host(host, hosts_map)
    try:
        result = subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={timeout}",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{ssh_user}@{ip}", command
            ],
            capture_output=True, text=True, timeout=timeout + 2
        )
        output = result.stdout.strip()
        if expect is not None:
            if expect.lower() in output.lower():
                return True, "OK"
            else:
                return False, output[:20] or "FAIL"
        if result.returncode == 0:
            if status_only:
                return True, "OK"
            return True, output[:20] or "OK"
        return False, "FAIL"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception:
        return False, "SSH ERR"


def check_ssh_stats(host, hosts_map, ssh_user="root", timeout=5):
    """Get CPU and memory stats from a remote host via SSH. Returns (ok, 'cpu%|used/totalG')."""
    ip = resolve_host(host, hosts_map)
    cmd = (
        "read c1 i1 <<< $(awk '/^cpu /{print $2+$4, $2+$4+$5}' /proc/stat); "
        "sleep 0.3; "
        "read c2 i2 <<< $(awk '/^cpu /{print $2+$4, $2+$4+$5}' /proc/stat); "
        "cpu=$(( (c2-c1) * 100 / (i2-i1) )); "
        "mem=$(free -g | awk '/Mem:/{printf \"%d/%dG\",$3,$2}'); "
        "echo \"${cpu}|${mem}\""
    )
    try:
        result = subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={timeout}",
                "-o", "StrictHostKeyChecking=accept-new",
                f"{ssh_user}@{ip}", "bash", "-c", cmd
            ],
            capture_output=True, text=True, timeout=timeout + 3
        )
        output = result.stdout.strip()
        if result.returncode == 0 and output:
            return True, output
        return False, "N/A"
    except Exception:
        return False, "N/A"


def run_check(key_def, hosts_map, settings):
    """Run the appropriate check for a key definition. Returns (ok, detail)."""
    check_type = key_def.get("check", "")
    timeout = settings.get("check_timeout", 5)
    ssh_user = settings.get("ssh_user", "root")

    if check_type == "ping":
        target = key_def.get("target", key_def.get("host", ""))
        return check_ping(target, hosts_map, timeout=2)

    elif check_type == "tcp":
        return check_tcp(
            key_def["host"], key_def["port"], hosts_map, timeout=3
        )

    elif check_type == "http":
        url = key_def.get("url")
        host = key_def.get("host")
        port = key_def.get("port", 80)
        path = key_def.get("path", "/")
        return check_http(url=url, host=host, port=port, path=path,
                          hosts_map=hosts_map, timeout=timeout)

    elif check_type == "https":
        return check_http(
            host=key_def["host"], port=key_def.get("port", 443),
            path=key_def.get("path", "/"), hosts_map=hosts_map,
            timeout=timeout, use_https=True
        )

    elif check_type == "dns":
        return check_dns(key_def["target"], timeout=timeout)

    elif check_type == "ssh_cmd":
        host = key_def["host"]
        user = get_ssh_user(host, hosts_map, ssh_user)
        return check_ssh_cmd(
            host, key_def["command"], hosts_map,
            ssh_user=user, timeout=settings.get("ssh_timeout", 5),
            expect=key_def.get("expect"),
            status_only=key_def.get("status_only", False)
        )

    elif check_type == "ssh_stats":
        host = key_def["host"]
        user = get_ssh_user(host, hosts_map, ssh_user)
        return check_ssh_stats(
            host, hosts_map,
            ssh_user=user, timeout=settings.get("ssh_timeout", 5)
        )

    return None, ""


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_key(deck, line1, line2="", bg_color="#000000", text_color="#ffffff"):
    """Render a key image with up to two lines of text."""
    image = PILHelper.create_key_image(deck)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, image.width, image.height), fill=bg_color)

    try:
        font_large = ImageFont.truetype(FONT_PATH, 13)
        font_small = ImageFont.truetype(FONT_PATH, 11)
    except OSError:
        font_large = ImageFont.load_default()
        font_small = font_large

    if line2:
        # Two-line layout
        bbox1 = draw.textbbox((0, 0), line1, font=font_large)
        tw1 = bbox1[2] - bbox1[0]
        x1 = (image.width - tw1) // 2
        draw.text((x1, 14), line1, font=font_large, fill=text_color)

        bbox2 = draw.textbbox((0, 0), line2, font=font_small)
        tw2 = bbox2[2] - bbox2[0]
        x2 = (image.width - tw2) // 2
        draw.text((x2, 42), line2, font=font_small, fill=text_color)
    else:
        # Single line centered
        # Handle multi-line labels (e.g. "Reboot\npfSense")
        lines = line1.split("\n")
        total_h = len(lines) * 18
        y_start = (image.height - total_h) // 2
        for i, line in enumerate(lines):
            bbox = draw.textbbox((0, 0), line, font=font_large)
            tw = bbox[2] - bbox[0]
            x = (image.width - tw) // 2
            draw.text((x, y_start + i * 18), line, font=font_large, fill=text_color)

    return PILHelper.to_native_key_format(deck, image)


def render_key_3line(deck, line1, line2, line3, bg_color="#000000",
                     color1="#ffffff", color2="#00ff88", color3="#00ccff"):
    """Render a key with 3 lines: title, cpu, memory."""
    image = PILHelper.create_key_image(deck)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, image.width, image.height), fill=bg_color)

    try:
        font_title = ImageFont.truetype(FONT_PATH, 12)
        font_stat = ImageFont.truetype(FONT_PATH, 11)
    except OSError:
        font_title = ImageFont.load_default()
        font_stat = font_title

    # Line 1 - title at top
    bbox = draw.textbbox((0, 0), line1, font=font_title)
    x = (image.width - (bbox[2] - bbox[0])) // 2
    draw.text((x, 6), line1, font=font_title, fill=color1)

    # Line 2 - cpu in middle
    bbox = draw.textbbox((0, 0), line2, font=font_stat)
    x = (image.width - (bbox[2] - bbox[0])) // 2
    draw.text((x, 28), line2, font=font_stat, fill=color2)

    # Line 3 - memory at bottom
    bbox = draw.textbbox((0, 0), line3, font=font_stat)
    x = (image.width - (bbox[2] - bbox[0])) // 2
    draw.text((x, 48), line3, font=font_stat, fill=color3)

    return PILHelper.to_native_key_format(deck, image)


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------
class StreamDeckApp:
    def __init__(self):
        self.config = load_config()
        self.hosts = self.config.get("hosts", {})
        self.settings = self.config.get("settings", {})
        self.pages = self.config.get("pages", [])
        self.current_page = 0
        self.deck = None
        self.stop_event = threading.Event()

        # Status cache: {(page_idx, key_idx): (ok, detail, timestamp)}
        self.status_cache = {}
        self.cache_lock = threading.Lock()

        # Confirmation state: {key_idx: expiry_time}
        self.pending_confirms = {}
        self.confirm_lock = threading.Lock()

        self.user_shutdown = False

    def start(self):
        decks = DeviceManager().enumerate()
        if not decks:
            print("No Stream Deck found.")
            sys.exit(1)

        self.deck = decks[0]
        self.deck.open()
        self.deck.reset()

        print(f"Connected: {self.deck.deck_type()} ({self.deck.key_count()} keys)")
        self.deck.set_brightness(self.settings.get("brightness", 60))

        self.deck.set_key_callback(self._key_callback)
        self._render_page()

        # Start background poller
        poller = threading.Thread(target=self._poll_loop, daemon=True)
        poller.start()

        # Start confirmation expiry watcher
        confirm_watcher = threading.Thread(target=self._confirm_watcher, daemon=True)
        confirm_watcher.start()

        # Start health watchdog
        watchdog = threading.Thread(target=self._watchdog_loop, daemon=True)
        watchdog.start()

        # Handle signals
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        print(f"Stream Deck ready. Page: {self.pages[0]['name']}. Press Ctrl+C to exit.", flush=True)
        self.stop_event.wait()

    def _shutdown(self, sig=None, frame=None):
        print("\nShutting down...", flush=True)
        self.user_shutdown = True
        self.stop_event.set()
        if self.deck:
            try:
                self.deck.reset()
                self.deck.close()
            except Exception:
                pass

    # -- Page rendering -----------------------------------------------------
    def _render_page(self):
        """Render all keys for the current page."""
        deck = self.deck
        page = self.pages[self.current_page]
        page_keys = page.get("keys", {})

        for key_idx in range(deck.key_count()):
            if key_idx == NAV_PREV_KEY:
                label = "<" if self.current_page > 0 else ""
                img = render_key(deck, label, bg_color=COLOR_NAV, text_color="#888888")
            elif key_idx == NAV_NEXT_KEY:
                label = ">" if self.current_page < len(self.pages) - 1 else ""
                img = render_key(deck, label, bg_color=COLOR_NAV, text_color="#888888")
            else:
                key_def = page_keys.get(str(key_idx))
                if key_def is None:
                    img = render_key(deck, "", bg_color="#000000")
                elif "check" in key_def:
                    img = self._render_status_key(key_idx, key_def)
                elif "action" in key_def:
                    img = self._render_action_key(key_def)
                else:
                    img = render_key(deck, key_def.get("label", ""), bg_color=COLOR_UNKNOWN)

            deck.set_key_image(key_idx, img)

    def _render_status_key(self, key_idx, key_def):
        """Render a status check key with cached results."""
        label = key_def.get("label", "?")
        cache_key = (self.current_page, key_idx)

        with self.cache_lock:
            cached = self.status_cache.get(cache_key)

        if cached is None:
            if key_def.get("check") == "ssh_stats":
                return render_key_3line(self.deck, label, "CPU: ...", "MEM: ...",
                                        COLOR_UNKNOWN, "#aaaaaa", "#aaaaaa", "#aaaaaa")
            return render_key(self.deck, label, "...", COLOR_UNKNOWN, "#aaaaaa")

        ok, detail = cached[0], cached[1]

        # Special rendering for ssh_stats (3-line: name / cpu / mem)
        if key_def.get("check") == "ssh_stats":
            bg = COLOR_OK if ok else COLOR_DOWN
            if ok and "|" in detail:
                parts = detail.split("|")
                cpu_line = f"CPU: {parts[0]}%"
                mem_line = f"MEM: {parts[1]}"
            else:
                cpu_line = "CPU: N/A"
                mem_line = "MEM: N/A"
            return render_key_3line(self.deck, label, cpu_line, mem_line,
                                    bg, "#ffffff", "#00ff88", "#00ccff")

        # Special rendering for ping checks (3-line: name / ONLINE|OFFLINE / latency)
        if key_def.get("check") == "ping" and detail and "|" in detail:
            bg = COLOR_OK if ok else COLOR_DOWN
            parts = detail.split("|", 1)
            status_line = parts[0]
            latency_line = parts[1] if len(parts) > 1 and parts[1] else ""
            return render_key_3line(self.deck, label, status_line, latency_line,
                                    bg, "#ffffff", "#00ff88", "#aaaaaa")

        if ok is None:
            bg = COLOR_UNKNOWN
            status = detail or "..."
        elif ok:
            bg = COLOR_OK
            status = detail or "OK"
        else:
            bg = COLOR_DOWN
            status = detail or "DOWN"

        return render_key(self.deck, label, status, bg, "#ffffff")

    def _render_action_key(self, key_def):
        """Render an action button key."""
        label = key_def.get("label", "?")
        return render_key(self.deck, label, bg_color=COLOR_ACTION, text_color="#ffffff")

    # -- Key press handling -------------------------------------------------
    def _key_callback(self, deck, key, state):
        if not state:  # Only handle press, not release
            return

        # Navigation
        if key == NAV_PREV_KEY:
            if self.current_page > 0:
                self.current_page -= 1
                print(f"Page: {self.pages[self.current_page]['name']}")
                self._render_page()
            return

        if key == NAV_NEXT_KEY:
            if self.current_page < len(self.pages) - 1:
                self.current_page += 1
                print(f"Page: {self.pages[self.current_page]['name']}")
                self._render_page()
            return

        # Get key definition
        page = self.pages[self.current_page]
        key_def = page.get("keys", {}).get(str(key))
        if key_def is None:
            return

        # Status keys - pressing just prints current status
        if "check" in key_def:
            cache_key = (self.current_page, key)
            with self.cache_lock:
                cached = self.status_cache.get(cache_key)
            if cached:
                print(f"  {key_def['label']}: {'OK' if cached[0] else 'DOWN'} - {cached[1]}")
            return

        # Action keys
        if "action" in key_def:
            self._handle_action(key, key_def)

    def _handle_action(self, key, key_def):
        action = key_def["action"]

        if action == "brightness":
            level = key_def.get("level", 50)
            self.deck.set_brightness(level)
            print(f"Brightness: {level}%")
            return

        if action == "refresh":
            print("Forcing refresh...")
            self._run_all_checks()
            return

        # Actions requiring confirmation
        if key_def.get("confirm", False):
            with self.confirm_lock:
                expiry = self.pending_confirms.get(key)
                if expiry and time.time() < expiry:
                    # Second press - execute
                    del self.pending_confirms[key]
                    self._execute_action(key, key_def)
                    return
                else:
                    # First press - set confirmation
                    self.pending_confirms[key] = time.time() + 3
                    print(f"  Press again within 3s to confirm: {key_def['label']}")
                    # Flash the key yellow
                    img = render_key(self.deck, "CONFIRM?", bg_color=COLOR_CONFIRM, text_color="#ffffff")
                    self.deck.set_key_image(key, img)
                    return

        # No confirmation needed
        self._execute_action(key, key_def)

    def _execute_action(self, key, key_def):
        action = key_def["action"]
        label = key_def.get("label", "").replace("\n", " ")

        if action == "ssh_cmd":
            host = key_def["host"]
            command = key_def["command"]
            ip = resolve_host(host, self.hosts)
            ssh_user = get_ssh_user(host, self.hosts, self.settings.get("ssh_user", "root"))
            timeout = self.settings.get("ssh_timeout", 5)

            # Show "running" state
            img = render_key(self.deck, label, "RUNNING", COLOR_RUNNING, "#ffcc00")
            self.deck.set_key_image(key, img)

            print(f"  Executing: ssh {ssh_user}@{ip} {command}")
            try:
                result = subprocess.run(
                    [
                        "ssh", "-o", "BatchMode=yes",
                        "-o", f"ConnectTimeout={timeout}",
                        "-o", "StrictHostKeyChecking=accept-new",
                        f"{ssh_user}@{ip}", command
                    ],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                if result.returncode == 0:
                    print(f"  Success: {result.stdout.strip()[:80]}")
                    img = render_key(self.deck, label, "DONE", COLOR_OK, "#ffffff")
                else:
                    print(f"  Failed: {result.stderr.strip()[:80]}")
                    img = render_key(self.deck, label, "FAILED", COLOR_DOWN, "#ffffff")
            except Exception as e:
                print(f"  Error: {e}")
                img = render_key(self.deck, label, "ERROR", COLOR_DOWN, "#ffffff")

            self.deck.set_key_image(key, img)
            # Restore normal appearance after 3 seconds
            threading.Timer(3.0, self._restore_action_key, args=[key, key_def]).start()

    def _restore_action_key(self, key, key_def):
        """Restore an action key to its normal appearance."""
        try:
            img = self._render_action_key(key_def)
            self.deck.set_key_image(key, img)
        except Exception:
            pass

    # -- Confirmation expiry watcher ----------------------------------------
    def _confirm_watcher(self):
        """Revert keys whose confirmation window has expired."""
        while not self.stop_event.is_set():
            time.sleep(0.5)
            expired = []
            with self.confirm_lock:
                now = time.time()
                for key, expiry in list(self.pending_confirms.items()):
                    if now >= expiry:
                        expired.append(key)
                        del self.pending_confirms[key]

            for key in expired:
                # Restore normal key appearance
                page = self.pages[self.current_page]
                key_def = page.get("keys", {}).get(str(key))
                if key_def and "action" in key_def:
                    try:
                        img = self._render_action_key(key_def)
                        self.deck.set_key_image(key, img)
                    except Exception:
                        pass

    # -- Health watchdog ----------------------------------------------------
    def _watchdog_loop(self):
        """Periodically verify the Stream Deck is still responsive."""
        while not self.stop_event.is_set():
            self.stop_event.wait(WATCHDOG_INTERVAL)
            if self.stop_event.is_set():
                break
            try:
                # Try reading firmware version as a health check
                self.deck.get_firmware_version()
            except Exception as e:
                print(f"[watchdog] Stream Deck unresponsive: {e}", flush=True)
                self._shutdown_for_restart()
                return

    def _shutdown_for_restart(self):
        """Signal the main loop to exit so the wrapper can restart."""
        print("[watchdog] Triggering restart...", flush=True)
        try:
            self.deck.reset()
            self.deck.close()
        except Exception:
            pass
        self.stop_event.set()

    # -- Background polling -------------------------------------------------
    def _poll_loop(self):
        """Periodically run all checks in the background."""
        interval = self.settings.get("poll_interval", 30)
        while not self.stop_event.is_set():
            self._run_all_checks()
            self.stop_event.wait(interval)

    def _run_all_checks(self):
        """Run checks for all pages in parallel."""
        tasks = []
        for page_idx, page in enumerate(self.pages):
            for key_str, key_def in page.get("keys", {}).items():
                if "check" in key_def:
                    tasks.append((page_idx, int(key_str), key_def))

        if not tasks:
            return

        print(f"[{time.strftime('%H:%M:%S')}] Running {len(tasks)} checks...")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            for page_idx, key_idx, key_def in tasks:
                future = executor.submit(run_check, key_def, self.hosts, self.settings)
                futures[future] = (page_idx, key_idx)

            for future in as_completed(futures):
                page_idx, key_idx = futures[future]
                try:
                    ok, detail = future.result()
                except Exception as e:
                    ok, detail = False, str(e)[:15]

                cache_key = (page_idx, key_idx)
                with self.cache_lock:
                    self.status_cache[cache_key] = (ok, detail, time.time())

                # Update key image if this check is on the currently displayed page
                if page_idx == self.current_page:
                    page = self.pages[page_idx]
                    key_def = page.get("keys", {}).get(str(key_idx))
                    if key_def:
                        try:
                            img = self._render_status_key(key_idx, key_def)
                            self.deck.set_key_image(key_idx, img)
                        except Exception:
                            pass

        ok_count = sum(1 for v in self.status_cache.values() if v[0])
        total = len(self.status_cache)
        print(f"[{time.strftime('%H:%M:%S')}] Checks done: {ok_count}/{total} OK")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    retries = 0
    while retries < MAX_RETRIES:
        try:
            app = StreamDeckApp()
            app.start()
            # User pressed Ctrl+C or sent SIGTERM - exit cleanly
            if app.user_shutdown:
                break
            # Watchdog or error triggered restart
            retries += 1
            print(f"[main] Restarting... (attempt {retries}/{MAX_RETRIES})", flush=True)
            time.sleep(RETRY_DELAY)
            recover_usb()
            continue
        except KeyboardInterrupt:
            print("\nExiting.", flush=True)
            break
        except Exception as e:
            retries += 1
            print(f"[main] Error: {e} (attempt {retries}/{MAX_RETRIES})", flush=True)
            time.sleep(RETRY_DELAY)
            recover_usb()
            continue

        # Clean exit
        break

    if retries >= MAX_RETRIES:
        print(f"[main] Failed after {MAX_RETRIES} attempts. Exiting.", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
