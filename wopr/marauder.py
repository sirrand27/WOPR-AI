"""
W.O.P.R. Network Defense Sentry — ESP32 Marauder RF Monitor
Serial interface to ESP32 Marauder via Flipper Zero USB-UART Bridge.

Provides RF-layer awareness: rogue AP detection, deauth attack monitoring,
and probe request capture. Complements UniFi controller-level monitoring
with over-the-air signal intelligence.

Prerequisite: Flipper Zero in USB-UART Bridge mode (GPIO > USB-UART Bridge,
115200 baud, pins 13/14) with ESP32 Marauder GPIO board attached.
"""

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

from config import (
    MARAUDER_DEVICE, MARAUDER_BAUD,
    MARAUDER_SCAN_INTERVAL, MARAUDER_SCAN_DWELL,
    MARAUDER_DEAUTH_BURST_THRESHOLD, MARAUDER_DEAUTH_BURST_WINDOW,
)

logger = logging.getLogger(__name__)

# Serial output parsers
_RE_SCANAP = re.compile(
    r'SSID:\s*(.+?)\s{2,}BSSID:\s*([0-9a-fA-F:]{17})\s+'
    r'Ch:\s*(\d+)\s+RSSI:\s*(-?\d+)\s+Enc:\s*(\S+)'
)
_RE_DEAUTH = re.compile(
    r'Src:\s*([0-9a-fA-F:]{17})\s+Dst:\s*([0-9a-fA-F:]{17})'
)
_RE_PROBE = re.compile(
    r'Src:\s*([0-9a-fA-F:]{17}).*?SSID:\s*(.+)'
)
# Status lines to ignore (not data)
_IGNORE_PREFIXES = (
    "Starting", "Stopping", "ESP32 Marauder", "By:", "---", "> ",
)


class MarauderMonitor:
    """ESP32 Marauder serial interface via Flipper Zero USB-UART bridge.

    Manages serial connection lifecycle, background reading, mode cycling
    between passive sniffdeauth and periodic scanap sweeps, and cross-
    referencing AP scans against UniFi managed infrastructure.
    """

    def __init__(self, blackboard, voice):
        self.blackboard = blackboard
        self.voice = voice
        self._device_path = MARAUDER_DEVICE
        self._baud = MARAUDER_BAUD
        self._scan_interval = MARAUDER_SCAN_INTERVAL
        self._scan_dwell = MARAUDER_SCAN_DWELL
        self._burst_threshold = MARAUDER_DEAUTH_BURST_THRESHOLD
        self._burst_window = MARAUDER_DEAUTH_BURST_WINDOW

        # Serial state
        self._fd = None
        self._reader_thread = None
        self._running = False
        self._current_mode = None
        self._mode_lock = threading.Lock()

        # Availability
        self._available = None  # None = unchecked, True/False after probe
        self._connect_attempted = False

        # AP scan data
        self._known_rf_aps = {}  # bssid -> {ssid, channel, rssi, enc, first_seen, last_seen, count}
        self._ap_scan_buffer = []
        self._last_scan_time = 0

        # Deauth tracking
        self._deauth_events = deque(maxlen=1000)
        self._deauth_rate = defaultdict(list)  # src_mac -> [timestamps]
        self._deauth_total = 0

        # Probe tracking
        self._probe_devices = set()  # unique source MACs seen probing

        logger.info(f"MarauderMonitor initialized (device={self._device_path}, "
                    f"scan_interval={self._scan_interval}s, dwell={self._scan_dwell}s)")

    # ── Serial Connection ──────────────────────────────────

    def connect(self):
        """Open serial connection to Marauder. Returns True on success."""
        try:
            import termios

            self._fd = os.open(self._device_path, os.O_RDWR | os.O_NOCTTY)

            # Configure termios for 115200 8N1 raw mode
            attrs = termios.tcgetattr(self._fd)

            # Input flags: no parity, no strip, no flow control
            attrs[0] = 0  # iflag
            # Output flags: raw
            attrs[1] = 0  # oflag
            # Control flags: 8N1, enable receiver, local mode
            attrs[2] = (termios.CS8 | termios.CREAD | termios.CLOCAL)
            # Local flags: raw (no echo, no canonical, no signals)
            attrs[3] = 0  # lflag

            # Baud rate
            baud_const = getattr(termios, f'B{self._baud}', termios.B115200)
            attrs[4] = baud_const  # ispeed
            attrs[5] = baud_const  # ospeed

            # Control characters
            attrs[6][termios.VMIN] = 1   # read at least 1 byte
            attrs[6][termios.VTIME] = 1  # 100ms timeout

            termios.tcsetattr(self._fd, termios.TCSANOW, attrs)
            termios.tcflush(self._fd, termios.TCIOFLUSH)

            self._available = True
            self._connect_attempted = True

            # Start background reader
            self._running = True
            self._reader_thread = threading.Thread(
                target=self._reader_loop, daemon=True, name="marauder-reader")
            self._reader_thread.start()

            # Start in sniffdeauth mode (primary passive monitoring)
            time.sleep(0.5)  # let serial settle
            self._send_command("stopscan")
            time.sleep(0.5)
            self._send_command("sniffdeauth")
            self._current_mode = "sniffdeauth"

            logger.info(f"Marauder connected on {self._device_path} @ {self._baud} baud — "
                        f"sniffdeauth active")
            return True

        except FileNotFoundError:
            logger.warning(f"Marauder device not found: {self._device_path} "
                           f"(Flipper not in USB-UART Bridge mode?)")
            self._available = False
            self._connect_attempted = True
            return False

        except PermissionError:
            logger.warning(f"Marauder permission denied: {self._device_path} "
                           f"(Docker device passthrough missing?)")
            self._available = False
            self._connect_attempted = True
            return False

        except Exception as e:
            logger.warning(f"Marauder connect failed: {e}")
            self._available = False
            self._connect_attempted = True
            return False

    def disconnect(self):
        """Close serial connection."""
        self._running = False
        if self._fd is not None:
            try:
                self._send_command("stopscan")
                time.sleep(0.3)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=3)
        self._current_mode = None
        self._available = False

    def _send_command(self, cmd):
        """Send a command to Marauder over serial."""
        if self._fd is None:
            return
        try:
            os.write(self._fd, (cmd + '\n').encode('ascii'))
        except OSError as e:
            logger.warning(f"Marauder send failed: {e}")
            self._available = False

    # ── Background Reader ──────────────────────────────────

    def _reader_loop(self):
        """Background thread: reads serial output line-by-line, dispatches to parsers."""
        buf = b''
        while self._running and self._fd is not None:
            try:
                chunk = os.read(self._fd, 256)
                if not chunk:
                    continue
                buf += chunk

                # Process complete lines
                while b'\n' in buf:
                    line_bytes, buf = buf.split(b'\n', 1)
                    line = line_bytes.decode('ascii', errors='replace').strip()
                    if not line:
                        continue

                    # Skip status/banner lines
                    if any(line.startswith(p) for p in _IGNORE_PREFIXES):
                        continue

                    # Dispatch to parser based on current mode
                    mode = self._current_mode
                    if mode == 'scanap':
                        self._parse_scanap_line(line)
                    elif mode == 'sniffdeauth':
                        self._parse_deauth_line(line)
                    elif mode == 'sniffprobe':
                        self._parse_probe_line(line)

            except OSError as e:
                if self._running:
                    logger.warning(f"Marauder serial read error: {e} — marking offline")
                    self._available = False
                break
            except Exception as e:
                if self._running:
                    logger.debug(f"Marauder reader exception: {e}")

        logger.info("Marauder reader thread exited")

    # ── Line Parsers ───────────────────────────────────────

    def _parse_scanap_line(self, line):
        """Parse scanap output: SSID, BSSID, channel, RSSI, encryption."""
        m = _RE_SCANAP.search(line)
        if not m:
            return

        ap = {
            "ssid": m.group(1).strip(),
            "bssid": m.group(2).lower(),
            "channel": int(m.group(3)),
            "rssi": int(m.group(4)),
            "enc": m.group(5),
        }

        self._ap_scan_buffer.append(ap)

        # Update known AP tracking
        bssid = ap["bssid"]
        now = time.time()
        if bssid in self._known_rf_aps:
            existing = self._known_rf_aps[bssid]
            existing["last_seen"] = now
            existing["count"] += 1
            existing["rssi"] = ap["rssi"]
        else:
            self._known_rf_aps[bssid] = {
                "ssid": ap["ssid"],
                "channel": ap["channel"],
                "rssi": ap["rssi"],
                "enc": ap["enc"],
                "first_seen": now,
                "last_seen": now,
                "count": 1,
            }

    def _parse_deauth_line(self, line):
        """Parse sniffdeauth output: source MAC, destination MAC."""
        m = _RE_DEAUTH.search(line)
        if not m:
            return

        now = time.time()
        src = m.group(1).lower()
        dst = m.group(2).lower()

        self._deauth_events.append((now, src, dst))
        self._deauth_rate[src].append(now)
        self._deauth_total += 1

    def _parse_probe_line(self, line):
        """Parse sniffprobe output: source MAC, probed SSID."""
        m = _RE_PROBE.search(line)
        if not m:
            return
        src = m.group(1).lower()
        self._probe_devices.add(src)

    # ── Mode Switching ─────────────────────────────────────

    def _switch_mode(self, new_mode):
        """Switch Marauder to a new scan mode. Thread-safe."""
        with self._mode_lock:
            if self._fd is None or not self._available:
                return

            # Stop current scan
            self._send_command("stopscan")
            time.sleep(1.0)  # wait for "Stopping WiFi tran/recv"

            # Clear scan buffer
            self._ap_scan_buffer.clear()

            # Start new mode
            self._send_command(new_mode)
            self._current_mode = new_mode
            logger.debug(f"Marauder mode switched to: {new_mode}")

    # ── Poll Interface (called from defense loop) ──────────

    def poll(self, poll_count, managed_aps, known_ssids):
        """Run periodic checks. Returns list of anomaly dicts.

        Args:
            poll_count: defense loop cycle number
            managed_aps: set of BSSID MACs managed by UniFi
            known_ssids: list of legitimate SSIDs

        Returns:
            List of anomaly dicts with 'type', 'source'='marauder', etc.
        """
        # Connect on first call
        if not self._connect_attempted:
            if not self.connect():
                return []

        if not self._available:
            # Retry connection every 100 cycles (~50 min)
            if poll_count % 100 == 0 and poll_count > 0:
                logger.info("Marauder reconnect attempt...")
                self.disconnect()
                if not self.connect():
                    return []
            else:
                return []

        anomalies = []
        now = time.time()

        # 1. Process deauth events → detect bursts
        anomalies.extend(self._process_deauth_events())

        # 2. Periodic AP scan
        if (now - self._last_scan_time) >= self._scan_interval:
            self._last_scan_time = now
            anomalies.extend(self._run_ap_scan(managed_aps, known_ssids))

        return anomalies

    def _run_ap_scan(self, managed_aps, known_ssids):
        """Switch to scanap, dwell, cross-reference, switch back."""
        anomalies = []

        try:
            # Switch to AP scan mode
            self._switch_mode("scanap")
            time.sleep(self._scan_dwell)

            # Read results from buffer
            scanned = list(self._ap_scan_buffer)
            new_count = 0

            for ap in scanned:
                bssid = ap["bssid"]
                ssid = ap["ssid"]

                # Check for rogue AP: known SSID but unknown BSSID
                if ssid in known_ssids and bssid not in managed_aps:
                    anomalies.append({
                        "type": "rogue_ap",
                        "source": "marauder",
                        "bssid": bssid,
                        "ssid": ssid,
                        "channel": ap.get("channel", 0),
                        "rssi": ap.get("rssi", 0),
                        "enc": ap.get("enc", "?"),
                    })

                # Track new APs
                info = self._known_rf_aps.get(bssid, {})
                if info.get("count", 0) <= 1:
                    new_count += 1

            # Post scan summary to activity log
            rogue_count = len(anomalies)
            try:
                self.blackboard.post_activity(
                    f"[RF] AP scan complete: {len(scanned)} observed, "
                    f"{new_count} new, {rogue_count} rogue",
                    entry_type="OK" if rogue_count == 0 else "WARN"
                )
            except Exception:
                pass

            logger.info(f"[RF] AP scan: {len(scanned)} APs, {new_count} new, "
                        f"{rogue_count} rogue, {len(self._known_rf_aps)} total tracked")

        except Exception as e:
            logger.error(f"Marauder AP scan error: {e}")

        finally:
            # Switch back to deauth monitoring
            self._switch_mode("sniffdeauth")

        return anomalies

    def _process_deauth_events(self):
        """Check deauth rate tracker for burst attacks."""
        anomalies = []
        now = time.time()
        window = self._burst_window
        threshold = self._burst_threshold

        expired_srcs = []
        for src, timestamps in self._deauth_rate.items():
            # Prune old timestamps
            recent = [t for t in timestamps if (now - t) <= window]
            self._deauth_rate[src] = recent

            if not recent:
                expired_srcs.append(src)
                continue

            # Check burst threshold
            if len(recent) >= threshold:
                # Find the most common target
                targets = defaultdict(int)
                for ts, s, d in self._deauth_events:
                    if s == src and (now - ts) <= window:
                        targets[d] += 1
                top_target = max(targets, key=targets.get) if targets else "ff:ff:ff:ff:ff:ff"

                anomalies.append({
                    "type": "deauth_attack",
                    "source": "marauder",
                    "src": src,
                    "dst": top_target,
                    "count": len(recent),
                    "window": window,
                    "mac": src,  # for posture tracking
                })

                # Clear this source after reporting (prevent re-trigger until new burst)
                self._deauth_rate[src] = []

        # Clean up empty entries
        for src in expired_srcs:
            del self._deauth_rate[src]

        return anomalies

    # ── Status Interface ───────────────────────────────────

    def get_status(self):
        """Return current Marauder status for defense dashboard."""
        return {
            "available": self._available or False,
            "mode": self._current_mode,
            "known_rf_aps": len(self._known_rf_aps),
            "deauth_events_total": self._deauth_total,
            "probe_devices": len(self._probe_devices),
            "last_scan": self._last_scan_time,
        }

    def stop(self):
        """Shutdown Marauder monitor."""
        logger.info("Stopping MarauderMonitor...")
        self.disconnect()
        logger.info("MarauderMonitor stopped")
