"""
W.O.P.R. Mining Fleet Monitor
Dual-source monitoring: AxeOS HTTP API (hardware telemetry for 7 miners)
+ Public Pool stratum API (hashrate/availability for all 26 workers).
Tracks hashrate, temperature, connectivity, and auto-restarts overheating units.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from config import (
    MINER_MONITORING_ENABLED, MINER_POLL_INTERVAL,
    MINER_TEMP_WARNING, MINER_TEMP_CRITICAL,
    MINER_TEMP_THROTTLE, MINER_THROTTLE_REDUCTION,
    MINER_AUTO_THROTTLE, MINER_THROTTLE_COOLDOWN,
    MINER_AUTO_RESTART_ON_OVERHEAT, MINER_KNOWN_MACS,
    MINER_AXEOS_MACS, MINER_NERDMINER_MACS, MINER_CGMINER_MACS,
    MINER_SUBNET, PUBLIC_POOL_URL, PUBLIC_POOL_BTC_ADDRESS,
    PUBLIC_POOL_POLL_INTERVAL, MINER_STALE_SHARE_THRESHOLD,
    MINER_STALE_SHARE_POLLS,
    MINER_OFFLINE_RESTART_THRESHOLD, MINER_OFFLINE_AUTO_RESTART,
    MINER_HASHRATE_DROP_POLLS, FIRMWARE_DIR,
)

logger = logging.getLogger(__name__)

# AxeOS API timeout (ESP32 can be slow to respond)
_AXEOS_TIMEOUT = 8
# Public Pool API timeout
_POOL_TIMEOUT = 15

# Worker name → type classification patterns
_WORKER_TYPE_PATTERNS = {
    "nerdminer": "nerdminer",
    "nerdqaxe": "axeos",
    "nerdaxe": "axeos",
    "bitaxe": "axeos",
    "cgminer": "cgminer",
    "A1Pool": "cgminer",
    "avalon": "cgminer",
    "marslander": "cgminer",
}


def _classify_worker(name):
    """Classify a pool worker name into a miner type."""
    lower = name.lower()
    if lower.startswith("nerdminer") or lower.startswith("nerdminerv"):
        return "nerdminer"
    if lower.startswith("goldnugget"):
        return "nerdminer"  # ESP32 NerdMiner variant
    if any(lower.startswith(p) for p in ("nerdqaxe", "nerdaxe", "bitaxe")):
        return "axeos"
    if lower in ("a1pool", "avalon", "marslander"):
        return "cgminer"
    return "unknown"


def _format_hashrate(hr_ghps):
    """Format hashrate in human-readable units (GH/s input)."""
    if hr_ghps >= 1000:
        return f"{hr_ghps / 1000:.2f} TH/s"
    if hr_ghps >= 1:
        return f"{hr_ghps:.1f} GH/s"
    if hr_ghps >= 0.001:
        return f"{hr_ghps * 1000:.1f} MH/s"
    if hr_ghps > 0:
        return f"{hr_ghps * 1e6:.0f} KH/s"
    return "0 H/s"


class MinerMonitor:
    """Dual-source fleet monitor: AxeOS direct + Public Pool API."""

    def __init__(self, device_db, blackboard, voice):
        self.device_db = device_db
        self.blackboard = blackboard
        self.voice = voice
        self.enabled = MINER_MONITORING_ENABLED
        # MAC → IP mapping (resolved from UniFi client data or DB)
        self._mac_to_ip = {}
        # MAC → hostname
        self._mac_to_name = {}
        # Track consecutive failures per miner (AxeOS)
        self._fail_count = {}
        # Cooldown: don't restart same miner within 5 minutes
        self._restart_cooldown = {}
        # Pool worker name → MAC correlation cache
        self._worker_to_mac = {}
        # Last pool poll timestamp
        self._last_pool_poll = 0
        # Pool poll counter for log throttling
        self._pool_poll_count = 0
        # Throttle state: MAC → {"original_freq": int, "throttled_freq": int, "throttled_at": float}
        self._throttled_miners = {}
        # Cooldown: don't re-throttle same miner within MINER_THROTTLE_COOLDOWN seconds
        self._throttle_cooldown = {}
        # Consecutive below-warning polls per miner (for restore hysteresis)
        self._below_warning_count = {}
        # Share quality: track consecutive high-reject polls per miner
        self._high_reject_count = {}
        # Previous share totals per miner (to compute delta between polls)
        self._prev_shares = {}
        # Pool API failover tracking
        self._pool_fail_count = 0
        self._pool_down = False
        # Pool failover recovery verification
        self._pre_outage_workers = {}
        self._post_recovery_check_pending = False
        self._recovery_check_time = 0
        # Sustained hashrate drop tracking
        self._low_hashrate_count = {}

        if self.enabled:
            self._load_known_miners()
            logger.info(
                f"MinerMonitor initialized: {len(MINER_AXEOS_MACS)} AxeOS, "
                f"{len(MINER_NERDMINER_MACS)} NerdMiners, "
                f"{len(MINER_CGMINER_MACS)} cgminers, "
                f"Public Pool at {PUBLIC_POOL_URL}")

    def _load_known_miners(self):
        """Load IP/hostname mappings from device DB for known miner MACs."""
        for mac in MINER_KNOWN_MACS:
            mac = mac.lower()
            device = self.device_db.get_device(mac)
            if device:
                try:
                    ips = json.loads(device.get("ip_history", "[]"))
                    if ips:
                        self._mac_to_ip[mac] = ips[-1]
                except (json.JSONDecodeError, IndexError):
                    pass
                self._mac_to_name[mac] = device.get("hostname", "")

            # Also check miner_stats table
            miner = self.device_db.get_miner(mac)
            if miner and miner.get("ip"):
                self._mac_to_ip[mac] = miner["ip"]
                if miner.get("hostname"):
                    self._mac_to_name[mac] = miner["hostname"]

        # Load existing pool worker → MAC correlations from DB
        pool_workers = self.device_db.get_all_pool_workers()
        for pw in pool_workers:
            if pw.get("mac"):
                self._worker_to_mac[pw["worker_name"]] = pw["mac"]

        # Mark all known miner MACs as trusted
        for mac in MINER_KNOWN_MACS:
            mac = mac.lower()
            device = self.device_db.get_device(mac)
            if device and device.get("trust_level") != "trusted":
                self.device_db.set_trust_level(mac, "trusted", reason="known miner MAC", actor="miner_monitor")

        logger.info(f"Loaded {len(self._mac_to_ip)} miner IP mappings, "
                    f"{len(self._worker_to_mac)} pool worker correlations from DB")

    def update_ip_map(self, clients):
        """Update MAC→IP mapping from UniFi client list.
        Called from the defense loop after each client poll."""
        if not self.enabled:
            return
        known_set = set(m.lower() for m in MINER_KNOWN_MACS)
        for client in clients:
            if not isinstance(client, dict):
                continue
            mac = client.get("mac", "").lower()
            if mac in known_set:
                ip = client.get("ip", "")
                if ip:
                    self._mac_to_ip[mac] = ip
                hostname = client.get("hostname", client.get("name", ""))
                if hostname:
                    self._mac_to_name[mac] = hostname

    # ── AxeOS Polling (7 hardware-monitored miners) ───────────────

    def poll_axeos(self):
        """Poll AxeOS-capable miners for hardware telemetry.
        Called every MINER_POLL_INTERVAL from defense loop."""
        if not self.enabled:
            return []

        anomalies = []
        online = 0
        offline = 0
        total_hashrate = 0.0

        for mac in MINER_AXEOS_MACS:
            mac = mac.lower()
            ip = self._mac_to_ip.get(mac)

            if not ip:
                continue

            result = self._poll_miner(ip, mac)

            if result is None:
                self._fail_count[mac] = self._fail_count.get(mac, 0) + 1
                if self._fail_count[mac] == 3:
                    self.device_db.record_miner_offline(mac)
                    name = self._mac_to_name.get(mac, mac)
                    logger.warning(f"[MINER] OFFLINE: {name} ({mac}) at {ip}")
                    anomalies.append({
                        "type": "miner_offline",
                        "mac": mac,
                        "hostname": name,
                        "ip": ip,
                        "consecutive_failures": self._fail_count[mac],
                    })
                # Auto-restart after sustained offline
                if (MINER_OFFLINE_AUTO_RESTART
                        and self._fail_count[mac] >= MINER_OFFLINE_RESTART_THRESHOLD):
                    if self._auto_restart_offline(ip, mac):
                        self._fail_count[mac] = 0
                offline += 1
                continue

            # Success — reset fail counter
            self._fail_count[mac] = 0
            online += 1

            hashrate = result.get("hashRate", result.get("hashrate", 0.0))
            temp = result.get("temp", result.get("temperature", 0.0))
            total_hashrate += hashrate

            # Check temperature thresholds
            temp_anomaly = self._check_temperature(mac, temp, ip)
            if temp_anomaly:
                anomalies.append(temp_anomaly)

            # Check hashrate degradation
            hr_anomaly = self._check_hashrate(mac, hashrate)
            if hr_anomaly:
                anomalies.append(hr_anomaly)

            # Check share quality (reject ratio)
            shares_acc = int(result.get("sharesAccepted", result.get("shares_accepted", 0)))
            shares_rej = int(result.get("sharesRejected", result.get("shares_rejected", 0)))
            wifi_rssi = int(result.get("wifiRSSI", result.get("wifi_rssi", result.get("rssi", 0))))
            share_anomaly = self._check_share_quality(mac, shares_acc, shares_rej, wifi_rssi)
            if share_anomaly:
                anomalies.append(share_anomaly)

            # Auto-correlate with pool worker via stratum user
            pool_user = result.get("stratumUser", result.get("pool_user", ""))
            if pool_user:
                # Extract worker name from "btc_address.worker_name" format
                parts = pool_user.split(".")
                if len(parts) >= 2:
                    worker_name = parts[-1]
                    if worker_name not in self._worker_to_mac or self._worker_to_mac[worker_name] != mac:
                        self._worker_to_mac[worker_name] = mac
                        self.device_db.link_pool_worker_mac(worker_name, mac)
                        logger.info(f"[MINER] Correlated pool worker '{worker_name}' → {mac}")

        logger.info(f"[MINER] AxeOS poll: {online}/{len(MINER_AXEOS_MACS)} online, "
                    f"{total_hashrate:.1f} GH/s")

        return anomalies

    def poll_all(self):
        """Legacy entry point — now delegates to poll_axeos().
        Public Pool polling is separate via poll_public_pool()."""
        return self.poll_axeos()

    def _poll_miner(self, ip, mac):
        """Query AxeOS /api/system/info and update stats in DB."""
        url = f"http://{ip}/api/system/info"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            logger.debug(f"[MINER] Poll failed for {ip} ({mac}): {e}")
            return None

        # Parse AxeOS response fields
        hashrate = float(data.get("hashRate", data.get("hashrate", 0)))
        temp = float(data.get("temp", data.get("temperature", 0)))
        best_diff = str(data.get("bestDiff", data.get("best_diff", "0")))
        voltage = float(data.get("voltage", data.get("coreVoltage", 0)))
        frequency = float(data.get("frequency", 0))
        fan_speed = int(data.get("fanspeed", data.get("fanSpeed", data.get("fan_speed", 0))))
        wifi_rssi = int(data.get("wifiRSSI", data.get("wifi_rssi", data.get("rssi", 0))))
        shares_accepted = int(data.get("sharesAccepted", data.get("shares_accepted", 0)))
        shares_rejected = int(data.get("sharesRejected", data.get("shares_rejected", 0)))
        uptime = int(data.get("uptimeSeconds", data.get("uptime", 0)))
        pool_url = data.get("stratumURL", data.get("pool_url", ""))
        pool_user = data.get("stratumUser", data.get("pool_user", ""))
        hostname = data.get("hostname", data.get("deviceModel", ""))

        status = "online"
        if temp >= MINER_TEMP_CRITICAL:
            status = "overheating"

        self.device_db.upsert_miner(
            mac=mac, ip=ip,
            hostname=hostname or self._mac_to_name.get(mac, ""),
            hashrate=hashrate, temp=temp,
            best_diff=best_diff, pool_url=pool_url, pool_user=pool_user,
            voltage=voltage, frequency=frequency, fan_speed=fan_speed,
            wifi_rssi=wifi_rssi, shares_accepted=shares_accepted,
            shares_rejected=shares_rejected, uptime_seconds=uptime,
            status=status,
        )

        if hostname:
            self._mac_to_name[mac] = hostname

        device = self.device_db.get_device(mac)
        if device and device.get("trust_level") != "trusted":
            self.device_db.set_trust_level(mac, "trusted", reason="AxeOS telemetry confirmed", actor="miner_monitor")

        return data

    # ── Public Pool API Polling (all 26 workers) ──────────────────

    def poll_public_pool(self):
        """Query Public Pool API for all workers. Returns anomalies list."""
        if not self.enabled:
            return []

        import time
        now = time.time()
        if now - self._last_pool_poll < PUBLIC_POOL_POLL_INTERVAL:
            return []
        self._last_pool_poll = now
        self._pool_poll_count += 1

        url = f"{PUBLIC_POOL_URL}/api/client/{PUBLIC_POOL_BTC_ADDRESS}"
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=_POOL_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            self._pool_fail_count += 1
            if self._pool_fail_count >= 3 and not self._pool_down:
                self._pool_down = True
                # Snapshot worker states for recovery verification
                self._pre_outage_workers = {}
                try:
                    all_pw = self.device_db.get_all_pool_workers()
                    for pw in all_pw:
                        self._pre_outage_workers[pw["worker_name"]] = pw.get("status", "unknown")
                except Exception:
                    pass
                logger.warning(f"[POOL] Public Pool API DOWN after {self._pool_fail_count} failures: {e}")
                self.voice.speak(
                    "Mining fleet. Public pool API is unreachable. "
                    "Switching to direct miner telemetry only."
                )
                cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
                self.blackboard.post_activity(
                    f"[{cst_stamp}] [POOL] API UNREACHABLE after {self._pool_fail_count} consecutive failures — "
                    f"AxeOS-only mode active",
                    entry_type="WARN",
                )
            else:
                logger.warning(f"[POOL] Public Pool API query failed ({self._pool_fail_count}x): {e}")
            return []

        # Pool API recovered
        if self._pool_down:
            self._pool_down = False
            self._post_recovery_check_pending = True
            self._recovery_check_time = time.time()
            logger.info("[POOL] Public Pool API recovered — scheduling recovery verification")
            self.voice.speak("Mining fleet. Public pool API connection restored.")
            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(
                f"[{cst_stamp}] [POOL] API connection restored after {self._pool_fail_count} failures",
                entry_type="OK",
            )
        self._pool_fail_count = 0

        # Post-recovery: verify workers reconnected after grace period
        if self._post_recovery_check_pending and not self._pool_down:
            import time as _t
            if _t.time() - self._recovery_check_time > 120:
                self._post_recovery_check_pending = False
                missing = []
                for wname, pre_status in self._pre_outage_workers.items():
                    if pre_status == "online":
                        pw = self.device_db.get_pool_worker(wname)
                        if pw and pw.get("status") != "online":
                            missing.append(wname)
                if missing:
                    logger.warning(
                        f"[POOL] Post-recovery: {len(missing)} workers did not reconnect: "
                        f"{', '.join(missing[:5])}"
                    )
                    self.blackboard.post_finding(
                        title="Pool Recovery: Workers Missing",
                        severity="MEDIUM",
                        description=(
                            f"After pool recovery, {len(missing)} workers have not reconnected: "
                            f"{', '.join(missing)}. Manual check recommended."
                        ),
                    )
                else:
                    logger.info("[POOL] Post-recovery: all workers reconnected successfully")
                self._pre_outage_workers = {}

        workers = data.get("workers", [])
        if not workers:
            logger.warning("[POOL] No workers returned from Public Pool API")
            return []

        anomalies = []
        online_count = 0
        total_hr_ghps = 0.0
        best_diff = 0.0

        for w in workers:
            worker_name = w.get("name", "unknown")
            if not worker_name or worker_name == "unknown":
                continue

            # Public Pool API: single "hashRate" field in H/s
            hashrate_hps = float(w.get("hashRate", 0))
            hashrate_ghps = hashrate_hps / 1e9  # Convert to GH/s for storage

            # bestDifficulty is a string like "8742523.12"
            try:
                w_best = float(w.get("bestDifficulty", "0"))
            except (ValueError, TypeError):
                w_best = 0.0

            last_seen = w.get("lastSeen", "")
            start_time = w.get("startTime", "")

            worker_type = _classify_worker(worker_name)

            # Status: any positive hashrate = online
            status = "online" if hashrate_hps > 0 else "offline"

            if status == "online":
                online_count += 1
                total_hr_ghps += hashrate_ghps

            if w_best > best_diff:
                best_diff = w_best

            # Look up MAC correlation
            mac = self._worker_to_mac.get(worker_name, "")

            # Store hashrate in GH/s as hashrate_1h (pool provides a rolling average)
            self.device_db.upsert_pool_worker(
                worker_name=worker_name,
                hashrate_5m=hashrate_ghps,  # Pool gives one rate, store in all slots
                hashrate_1h=hashrate_ghps,
                hashrate_12h=hashrate_ghps,
                hashrate_1d=hashrate_ghps,
                best_difficulty=w_best,
                last_seen=last_seen, start_time=start_time,
                worker_type=worker_type,
                mac=mac, status=status,
            )

            # Anomaly: worker went offline
            if status == "offline" and self._pool_poll_count > 1:
                existing = self.device_db.get_pool_worker(worker_name)
                if existing and existing.get("status") == "online":
                    anomalies.append({
                        "type": "pool_worker_offline",
                        "worker": worker_name,
                        "worker_type": worker_type,
                        "mac": mac,
                    })

        # Log summary (throttle to every 5th poll)
        if self._pool_poll_count % 5 == 1:
            logger.info(
                f"[POOL] Fleet: {online_count}/{len(workers)} workers online, "
                f"total hashrate: {_format_hashrate(total_hr_ghps)}, "
                f"best difficulty: {best_diff:,.0f}")

        return anomalies

    # ── Temperature / Hashrate Checks ─────────────────────────────

    def _check_temperature(self, mac, temp, ip):
        """Check temperature thresholds with graduated response:
        <65C  = nominal (restore if throttled)
        65-70 = WARNING: log only
        70-75 = THROTTLE: reduce frequency by 25%
        75+   = CRITICAL: full restart
        """
        name = self._mac_to_name.get(mac, mac)

        # --- CRITICAL (75+): Full restart ---
        if temp >= MINER_TEMP_CRITICAL:
            logger.warning(f"[MINER] CRITICAL TEMP: {name} at {temp}C (threshold {MINER_TEMP_CRITICAL}C)")
            if MINER_AUTO_RESTART_ON_OVERHEAT:
                self._restart_miner(ip, mac, f"Temperature critical: {temp}C")
            return {
                "type": "miner_overheat",
                "mac": mac,
                "hostname": name,
                "temp": temp,
                "threshold": MINER_TEMP_CRITICAL,
                "action": "auto-restart" if MINER_AUTO_RESTART_ON_OVERHEAT else "alert-only",
            }

        # --- THROTTLE (70-75): Reduce clock speed ---
        if temp >= MINER_TEMP_THROTTLE and MINER_AUTO_THROTTLE:
            miner = self.device_db.get_miner(mac)
            current_freq = miner.get("frequency", 0) if miner else 0
            if current_freq > 0:
                self._throttle_miner(ip, mac, current_freq, temp)
            else:
                logger.warning(f"[MINER] Cannot throttle {name}: no frequency data")
            return {
                "type": "miner_throttle",
                "mac": mac,
                "hostname": name,
                "temp": temp,
                "threshold": MINER_TEMP_THROTTLE,
                "action": "auto-throttle" if MINER_AUTO_THROTTLE else "alert-only",
            }

        # --- WARNING (65-70): Log only ---
        if temp >= MINER_TEMP_WARNING:
            logger.info(f"[MINER] WARM: {name} at {temp}C (warning threshold {MINER_TEMP_WARNING}C)")
            self._below_warning_count.pop(mac, None)
            return {
                "type": "miner_warm",
                "mac": mac,
                "hostname": name,
                "temp": temp,
                "threshold": MINER_TEMP_WARNING,
            }

        # --- NOMINAL (<65): Restore if throttled ---
        if mac in self._throttled_miners:
            count = self._below_warning_count.get(mac, 0) + 1
            self._below_warning_count[mac] = count
            if count >= 2:
                self._restore_miner(ip, mac, temp)

        return None

    def _check_hashrate(self, mac, hashrate):
        """Check for hashrate anomalies: near-zero or sustained 50%+ drop."""
        miner = self.device_db.get_miner(mac)
        if not miner:
            return None
        avg = miner.get("avg_hashrate", 0)
        name = self._mac_to_name.get(mac, mac)

        # Near-zero on a miner that normally hashes (possible firmware compromise)
        if avg > 0.1 and hashrate < 0.01:
            self._low_hashrate_count[mac] = 0
            return {
                "type": "miner_hashrate_drop",
                "mac": mac,
                "hostname": name,
                "current": hashrate,
                "average": avg,
                "ratio": 0.0,
                "alert": "NEAR_ZERO_HASHRATE",
            }

        # Sustained significant drop (>50% below average for N consecutive polls)
        if avg > 0 and hashrate > 0 and hashrate < avg * 0.5:
            self._low_hashrate_count[mac] = self._low_hashrate_count.get(mac, 0) + 1
            if self._low_hashrate_count[mac] >= MINER_HASHRATE_DROP_POLLS:
                self._low_hashrate_count[mac] = 0
                return {
                    "type": "miner_hashrate_drop",
                    "mac": mac,
                    "hostname": name,
                    "current": hashrate,
                    "average": avg,
                    "ratio": round(hashrate / avg, 2),
                    "alert": "SUSTAINED_DROP",
                }
        else:
            self._low_hashrate_count.pop(mac, None)

        return None

    def _check_share_quality(self, mac, shares_accepted, shares_rejected, wifi_rssi):
        """Check if reject ratio exceeds threshold over consecutive polls."""
        name = self._mac_to_name.get(mac, mac)
        total = shares_accepted + shares_rejected
        if total < 10:
            # Not enough shares to judge quality
            return None

        # Compute delta since last poll (reject ratio on new shares only)
        prev = self._prev_shares.get(mac, {"accepted": 0, "rejected": 0})
        delta_accepted = shares_accepted - prev["accepted"]
        delta_rejected = shares_rejected - prev["rejected"]
        self._prev_shares[mac] = {"accepted": shares_accepted, "rejected": shares_rejected}

        delta_total = delta_accepted + delta_rejected
        if delta_total < 5:
            # Too few new shares this poll to evaluate
            return None

        reject_pct = (delta_rejected / delta_total) * 100

        if reject_pct >= MINER_STALE_SHARE_THRESHOLD:
            self._high_reject_count[mac] = self._high_reject_count.get(mac, 0) + 1
        else:
            self._high_reject_count[mac] = 0
            return None

        if self._high_reject_count[mac] >= MINER_STALE_SHARE_POLLS:
            # Sustained high reject ratio — flag anomaly
            self._high_reject_count[mac] = 0  # reset after flagging
            return {
                "type": "miner_stale_shares",
                "mac": mac,
                "hostname": name,
                "reject_pct": round(reject_pct, 1),
                "delta_accepted": delta_accepted,
                "delta_rejected": delta_rejected,
                "wifi_rssi": wifi_rssi,
                "total_accepted": shares_accepted,
                "total_rejected": shares_rejected,
            }
        return None

    def _restart_miner(self, ip, mac, reason):
        """POST to AxeOS /api/system/restart with cooldown check."""
        import time
        name = self._mac_to_name.get(mac, mac)
        now = time.time()

        last_restart = self._restart_cooldown.get(mac, 0)
        if now - last_restart < 300:
            logger.info(f"[MINER] Restart cooldown active for {name}, skipping")
            return False

        url = f"http://{ip}/api/system/restart"
        try:
            req = urllib.request.Request(url, data=b"", method="POST")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                resp.read()
            logger.warning(f"[MINER] RESTART: {name} ({mac}) at {ip} — {reason}")
            self._restart_cooldown[mac] = now
            self.device_db.record_miner_restart(mac)
            # Restart resets AxeOS frequency — clear throttle state
            if mac in self._throttled_miners:
                del self._throttled_miners[mac]
                self._below_warning_count.pop(mac, None)

            self.voice.speak(f"Miner {name} restarted. Reason: {reason}")

            self.blackboard.post_finding(
                title=f"Miner Restart: {name}",
                severity="MEDIUM",
                description=f"Auto-restarted {name} ({mac}) at {ip}. Reason: {reason}",
                host=ip,
            )

            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(
                f"[{cst_stamp}] [MINER] RESTART: {name} ({mac}) at {ip} — {reason}",
                entry_type="WARN",
            )
            return True

        except (urllib.error.URLError, OSError) as e:
            logger.error(f"[MINER] Restart failed for {name} at {ip}: {e}")
            return False

    def _auto_restart_offline(self, ip, mac):
        """Attempt to restart an unresponsive miner via AxeOS API.
        Different from thermal restart — the info endpoint failed but
        the restart endpoint may still respond."""
        import time
        name = self._mac_to_name.get(mac, mac)
        now = time.time()

        last_restart = self._restart_cooldown.get(mac, 0)
        if now - last_restart < 300:
            logger.info(f"[MINER] Offline restart cooldown active for {name}, skipping")
            return False

        url = f"http://{ip}/api/system/restart"
        try:
            req = urllib.request.Request(url, data=b"", method="POST")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                resp.read()
            logger.warning(
                f"[MINER] OFFLINE RESTART: {name} ({mac}) at {ip} — "
                f"unresponsive for {self._fail_count.get(mac, 0)} consecutive polls"
            )
            self._restart_cooldown[mac] = now
            self.device_db.record_miner_restart(mac)

            if mac in self._throttled_miners:
                del self._throttled_miners[mac]
                self._below_warning_count.pop(mac, None)

            self.voice.speak(
                f"Mining fleet. Restarting offline miner {name}. "
                f"Unit was unresponsive for {self._fail_count.get(mac, 0)} consecutive polls."
            )

            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(
                f"[{cst_stamp}] [MINER] OFFLINE RESTART: {name} ({mac}) at {ip} — "
                f"unresponsive for {self._fail_count.get(mac, 0)} polls",
                entry_type="WARN",
            )
            return True
        except (urllib.error.URLError, OSError) as e:
            logger.error(f"[MINER] Offline restart failed for {name} at {ip}: {e}")
            return False

    # ── Firmware OTA ────────────────────────────────────────────────

    def firmware_update(self, ip, mac, firmware_path=None):
        """Flash AxeOS firmware via OTA. Auto-detects board version if no
        firmware_path is given and selects from FIRMWARE_DIR.

        Returns (success: bool, message: str)."""
        import os
        name = self._mac_to_name.get(mac, mac)

        # 1. Query the miner for board version and current firmware
        try:
            url = f"http://{ip}/api/system/info"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                info = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return (False, f"Cannot reach {name} at {ip}: {e}")

        board_version = str(info.get("boardVersion", "unknown"))
        current_version = info.get("version", "unknown")
        asic_model = info.get("ASICModel", "unknown")

        logger.info(
            f"[OTA] {name}: board={board_version}, ASIC={asic_model}, "
            f"firmware={current_version}"
        )

        # 2. Resolve firmware binary
        if not firmware_path:
            firmware_path = self._resolve_firmware(board_version)
            if not firmware_path:
                return (False,
                    f"No firmware binary for board version {board_version}. "
                    f"Place esp-miner-{board_version}.bin in {FIRMWARE_DIR}")

        if not os.path.isfile(firmware_path):
            return (False, f"Firmware file not found: {firmware_path}")

        file_size = os.path.getsize(firmware_path)
        if file_size < 10000 or file_size > 10_000_000:
            return (False, f"Firmware file size suspect: {file_size} bytes")

        # 3. Read binary
        with open(firmware_path, "rb") as f:
            firmware_data = f.read()

        # 4. Flash via OTA endpoint
        logger.warning(
            f"[OTA] FLASHING {name} ({mac}) at {ip} — "
            f"board={board_version}, file={os.path.basename(firmware_path)} "
            f"({len(firmware_data)} bytes)"
        )

        try:
            req = urllib.request.Request(
                f"http://{ip}/api/system/OTA",
                data=firmware_data,
                method="POST",
            )
            req.add_header("Content-Type", "application/octet-stream")
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = resp.read().decode("utf-8", errors="replace")
                status_code = resp.status
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:200]
            return (False, f"OTA flash failed — HTTP {e.code}: {body}")
        except Exception as e:
            return (False, f"OTA flash failed: {e}")

        if status_code != 200:
            return (False, f"OTA flash returned HTTP {status_code}: {result[:200]}")

        # 5. Log success
        msg = (
            f"FIRMWARE UPDATE: {name} ({mac}) at {ip} — "
            f"board {board_version}, {os.path.basename(firmware_path)}, "
            f"was {current_version}. Miner will reboot."
        )
        logger.warning(f"[OTA] {msg}")

        self.voice.speak(
            f"Firmware update complete for {name}. "
            f"Board version {board_version}. Miner is rebooting."
        )

        cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime(
            "%Y-%m-%d %H:%M:%S CST"
        )
        self.blackboard.post_activity(
            f"[{cst_stamp}] [OTA] {msg}", entry_type="OK"
        )
        self.blackboard.post_finding(
            title=f"Firmware Update: {name}",
            severity="INFO",
            description=msg,
            host=ip,
        )

        return (True, msg)

    def _resolve_firmware(self, board_version):
        """Find the firmware binary for a given board version."""
        import os
        if not os.path.isdir(FIRMWARE_DIR):
            return None

        # Try exact match first: esp-miner-401.bin
        exact = os.path.join(FIRMWARE_DIR, f"esp-miner-{board_version}.bin")
        if os.path.isfile(exact):
            return exact

        # Try with version suffix: esp-miner-401-v2.12.2.bin (pick latest)
        candidates = []
        for f in os.listdir(FIRMWARE_DIR):
            if f.startswith(f"esp-miner-{board_version}") and f.endswith(".bin"):
                candidates.append(os.path.join(FIRMWARE_DIR, f))

        if candidates:
            # Sort by modification time, newest first
            candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return candidates[0]

        return None

    def list_firmware(self):
        """List available firmware binaries and their board versions."""
        import os
        if not os.path.isdir(FIRMWARE_DIR):
            return {}

        result = {}
        for f in sorted(os.listdir(FIRMWARE_DIR)):
            if f.endswith(".bin"):
                path = os.path.join(FIRMWARE_DIR, f)
                size = os.path.getsize(path)
                result[f] = {
                    "path": path,
                    "size_bytes": size,
                    "size_mb": round(size / 1_048_576, 2),
                }
        return result

    def get_fleet_firmware(self):
        """Get current firmware versions for all AxeOS miners."""
        versions = {}
        for mac in MINER_AXEOS_MACS:
            mac = mac.lower()
            ip = self._mac_to_ip.get(mac)
            if not ip:
                continue
            try:
                url = f"http://{ip}/api/system/info"
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                    info = json.loads(resp.read().decode("utf-8"))
                versions[mac] = {
                    "hostname": info.get("hostname", mac),
                    "ip": ip,
                    "version": info.get("version", "unknown"),
                    "boardVersion": str(info.get("boardVersion", "unknown")),
                    "ASICModel": info.get("ASICModel", "unknown"),
                    "idfVersion": info.get("idfVersion", "unknown"),
                    "runningPartition": info.get("runningPartition", "unknown"),
                }
            except Exception:
                versions[mac] = {
                    "hostname": self._mac_to_name.get(mac, mac),
                    "ip": ip,
                    "version": "unreachable",
                }
        return versions

    # ── Clock Setting Safeguards ─────────────────────────────────

    # Safe operating limits per ASIC model.
    # frequency: (min_mhz, max_mhz), coreVoltage: (min_mv, max_mv)
    _ASIC_LIMITS = {
        "BM1366": {"freq": (50, 600),  "voltage": (1000, 1250)},
        "BM1368": {"freq": (50, 600),  "voltage": (1000, 1250)},
        "BM1370": {"freq": (50, 625),  "voltage": (1000, 1300)},
        "BM1397": {"freq": (50, 500),  "voltage": (1000, 1200)},
    }
    _DEFAULT_LIMITS = {"freq": (50, 575), "voltage": (1000, 1250)}

    def validate_clock_settings(self, ip, mac, frequency=None, core_voltage=None):
        """Validate frequency/voltage against safe ASIC limits.
        Returns (valid: bool, message: str). Queries the miner for its
        ASIC model to select the correct limits."""
        name = self._mac_to_name.get(mac, mac)

        # Get current info to determine ASIC model
        try:
            url = f"http://{ip}/api/system/info"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                info = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return (False, f"Cannot reach {name} at {ip} to verify ASIC: {e}")

        asic = info.get("ASICModel", "unknown")
        limits = self._ASIC_LIMITS.get(asic, self._DEFAULT_LIMITS)
        min_freq, max_freq = limits["freq"]
        min_volt, max_volt = limits["voltage"]

        errors = []
        if frequency is not None:
            if not isinstance(frequency, (int, float)) or frequency <= 0:
                errors.append(f"Invalid frequency value: {frequency}")
            elif frequency < min_freq:
                errors.append(
                    f"Frequency {frequency} MHz below minimum {min_freq} MHz "
                    f"for {asic}")
            elif frequency > max_freq:
                errors.append(
                    f"Frequency {frequency} MHz exceeds safe maximum {max_freq} MHz "
                    f"for {asic}")

        if core_voltage is not None:
            if not isinstance(core_voltage, (int, float)) or core_voltage <= 0:
                errors.append(f"Invalid voltage value: {core_voltage}")
            elif core_voltage < min_volt:
                errors.append(
                    f"Core voltage {core_voltage} mV below minimum {min_volt} mV "
                    f"for {asic}")
            elif core_voltage > max_volt:
                errors.append(
                    f"Core voltage {core_voltage} mV exceeds safe maximum {max_volt} mV "
                    f"for {asic}")

        if errors:
            msg = f"SAFETY CHECK FAILED for {name} ({asic}): {'; '.join(errors)}"
            logger.warning(f"[MINER] {msg}")
            return (False, msg)

        return (True, f"Settings valid for {asic}: "
                f"freq={frequency} MHz, voltage={core_voltage} mV")

    def safe_set_clock(self, ip, mac, frequency=None, core_voltage=None):
        """Set miner clock frequency and/or core voltage with safety validation.
        Returns (success: bool, message: str)."""
        name = self._mac_to_name.get(mac, mac)

        # Validate first
        valid, msg = self.validate_clock_settings(ip, mac, frequency, core_voltage)
        if not valid:
            self.blackboard.post_finding(
                title=f"Clock Setting Rejected: {name}",
                severity="HIGH",
                description=msg,
                host=ip,
            )
            return (False, msg)

        # Build PATCH payload with only the fields being changed
        payload = {}
        if frequency is not None:
            payload["frequency"] = int(frequency)
        if core_voltage is not None:
            payload["coreVoltage"] = int(core_voltage)

        if not payload:
            return (False, "No settings to change.")

        url = f"http://{ip}/api/system"
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), method="PATCH")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                resp.read()
        except Exception as e:
            return (False, f"Failed to set clock on {name} at {ip}: {e}")

        msg = f"Clock updated on {name} ({mac}): {payload}"
        logger.info(f"[MINER] {msg}")

        cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime(
            "%Y-%m-%d %H:%M:%S CST")
        self.blackboard.post_activity(
            f"[{cst_stamp}] [MINER] CLOCK SET: {name} ({mac}) — {payload}",
            entry_type="OK",
        )

        return (True, msg)

    # ── Clock Throttle / Restore ──────────────────────────────────

    def _throttle_miner(self, ip, mac, current_freq, temp):
        """Reduce miner clock frequency via PATCH /api/system."""
        import time
        name = self._mac_to_name.get(mac, mac)
        now = time.time()

        if mac in self._throttled_miners:
            logger.debug(f"[MINER] {name} already throttled, skipping")
            return False

        last_throttle = self._throttle_cooldown.get(mac, 0)
        if now - last_throttle < MINER_THROTTLE_COOLDOWN:
            logger.info(f"[MINER] Throttle cooldown active for {name}, skipping")
            return False

        if current_freq <= 0:
            logger.warning(f"[MINER] Cannot throttle {name}: frequency unknown ({current_freq})")
            return False

        reduced_freq = int(current_freq * (1 - MINER_THROTTLE_REDUCTION))

        # Safety check — ensure reduced frequency is within ASIC limits
        valid, vmsg = self.validate_clock_settings(ip, mac, frequency=reduced_freq)
        if not valid:
            logger.warning(f"[MINER] Throttle blocked by safety check: {vmsg}")
            return False

        url = f"http://{ip}/api/system"
        payload = json.dumps({"frequency": reduced_freq}).encode("utf-8")

        try:
            req = urllib.request.Request(url, data=payload, method="PATCH")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                resp.read()

            logger.warning(
                f"[MINER] THROTTLE: {name} ({mac}) at {ip} — "
                f"temp {temp}C, freq {int(current_freq)} -> {reduced_freq} MHz"
            )

            self._throttled_miners[mac] = {
                "original_freq": int(current_freq),
                "throttled_freq": reduced_freq,
                "throttled_at": now,
            }
            self._throttle_cooldown[mac] = now
            self._below_warning_count.pop(mac, None)

            self.device_db.log_response_action(
                mac, "throttle",
                reason=f"Temperature {temp}C > {MINER_TEMP_THROTTLE}C, "
                       f"freq {int(current_freq)} -> {reduced_freq} MHz",
                posture="throttle"
            )

            self.voice.speak(
                f"Mining fleet. Throttling {name}. "
                f"Temperature {temp:.0f} degrees. "
                f"Frequency reduced from {int(current_freq)} to {reduced_freq} megahertz."
            )

            self.blackboard.post_finding(
                title=f"Miner Throttle: {name}",
                severity="MEDIUM",
                description=(
                    f"Clock throttled {name} ({mac}) at {ip}. "
                    f"Temp: {temp}C (threshold: {MINER_TEMP_THROTTLE}C). "
                    f"Frequency: {int(current_freq)} -> {reduced_freq} MHz "
                    f"({int(MINER_THROTTLE_REDUCTION * 100)}% reduction)."
                ),
                host=ip,
            )

            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(
                f"[{cst_stamp}] [MINER] THROTTLE: {name} ({mac}) at {ip} — "
                f"temp {temp}C, freq {int(current_freq)} -> {reduced_freq} MHz",
                entry_type="WARN",
            )
            return True

        except (urllib.error.URLError, OSError) as e:
            logger.error(f"[MINER] Throttle failed for {name} at {ip}: {e}")
            return False

    def _restore_miner(self, ip, mac, temp):
        """Restore original clock frequency when temperature drops below WARNING."""
        import time
        name = self._mac_to_name.get(mac, mac)

        if mac not in self._throttled_miners:
            return False

        state = self._throttled_miners[mac]
        original_freq = state["original_freq"]
        url = f"http://{ip}/api/system"
        payload = json.dumps({"frequency": original_freq}).encode("utf-8")

        try:
            req = urllib.request.Request(url, data=payload, method="PATCH")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=_AXEOS_TIMEOUT) as resp:
                resp.read()

            throttled_freq = state["throttled_freq"]
            throttled_duration = int(time.time() - state["throttled_at"])

            logger.info(
                f"[MINER] RESTORE: {name} ({mac}) at {ip} — "
                f"temp {temp}C, freq {throttled_freq} -> {original_freq} MHz "
                f"(throttled for {throttled_duration}s)"
            )

            del self._throttled_miners[mac]
            self._below_warning_count.pop(mac, None)

            self.device_db.log_response_action(
                mac, "restore",
                reason=f"Temperature {temp}C < {MINER_TEMP_WARNING}C, "
                       f"freq restored to {original_freq} MHz "
                       f"(was throttled for {throttled_duration}s)",
                posture="restore"
            )

            self.voice.speak(
                f"Mining fleet. Restoring {name}. "
                f"Temperature {temp:.0f} degrees nominal. "
                f"Frequency restored to {original_freq} megahertz."
            )

            self.blackboard.post_finding(
                title=f"Miner Restored: {name}",
                severity="LOW",
                description=(
                    f"Clock restored {name} ({mac}) at {ip}. "
                    f"Temp: {temp}C (below warning {MINER_TEMP_WARNING}C). "
                    f"Frequency: {throttled_freq} -> {original_freq} MHz. "
                    f"Throttled for {throttled_duration}s."
                ),
                host=ip,
            )

            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(
                f"[{cst_stamp}] [MINER] RESTORE: {name} ({mac}) at {ip} — "
                f"temp {temp}C, freq {throttled_freq} -> {original_freq} MHz "
                f"(throttled for {throttled_duration}s)",
                entry_type="OK",
            )
            return True

        except (urllib.error.URLError, OSError) as e:
            logger.error(f"[MINER] Restore failed for {name} at {ip}: {e}")
            return False

    def is_throttled(self, mac):
        """Check if a miner is currently throttled."""
        return mac.lower() in self._throttled_miners

    def get_throttle_state(self):
        """Get all currently throttled miners and their state."""
        return dict(self._throttled_miners)

    # ── Unified Fleet Interface ───────────────────────────────────

    def get_fleet_summary(self):
        """Get combined fleet summary from both AxeOS and Public Pool data."""
        # Pool data is the authoritative source for worker count + hashrate
        pool_summary = self.device_db.get_pool_fleet_summary()
        # AxeOS data provides hardware telemetry for the 7 direct-polled miners
        axeos_summary = self.device_db.get_fleet_summary()

        if pool_summary["total_workers"] == 0:
            # Fall back to AxeOS-only if no pool data yet
            return axeos_summary

        return {
            # Pool-sourced (authoritative)
            "total_workers": pool_summary["total_workers"],
            "pool_online": pool_summary["online"],
            "pool_offline": pool_summary["offline"],
            "total_hashrate_1h": pool_summary["total_hashrate_1h"],
            "best_difficulty": pool_summary["best_difficulty"],
            "by_type": pool_summary["by_type"],
            # AxeOS hardware telemetry
            "axeos_monitored": axeos_summary.get("total", 0),
            "axeos_online": axeos_summary.get("online", 0),
            "avg_temp": axeos_summary.get("avg_temp", 0),
            "overheating": axeos_summary.get("overheating", 0),
            "total_restarts": axeos_summary.get("total_restarts", 0),
            "throttled": len(self._throttled_miners),
            "pool_api_down": self._pool_down,
        }

    def get_fleet_health(self):
        """Compute per-miner composite health score (0-100).

        AxeOS miners (full telemetry):
            temperature (25%), hashrate stability (25%),
            uptime (20%), share quality (15%), WiFi RSSI (15%)

        Pool-only miners (NerdMiners, cgminers):
            hashrate stability (35%), online status (35%),
            best difficulty (30%)
        """
        all_miners = self.device_db.get_all_miners()
        results = {}

        # --- Phase 1: AxeOS miners (full hardware telemetry) ---
        for miner in all_miners:
            mac = miner.get("mac", "")
            if not mac:
                continue

            # Temperature score (25%)
            temp = miner.get("temp", miner.get("last_temp", 0)) or 0
            if temp <= 0:
                temp_score = 50.0
            elif temp <= 55:
                temp_score = 100.0
            elif temp <= 65:
                temp_score = 100.0 - ((temp - 55) / 10) * 30
            elif temp <= 70:
                temp_score = 70.0 - ((temp - 65) / 5) * 40
            else:
                temp_score = max(0, 30.0 - ((temp - 70) / 5) * 30)

            # Hashrate stability (25%)
            current_hr = miner.get("hashrate", miner.get("last_hashrate", 0)) or 0
            avg_hr = miner.get("avg_hashrate", 0) or 0
            if avg_hr > 0 and current_hr > 0:
                ratio = min(current_hr / avg_hr, 1.2)
                hr_score = min(100.0, ratio * 83.3)  # 1.0 ratio = 83, 1.2+ = 100
            elif miner.get("status") == "offline":
                hr_score = 0.0
            else:
                hr_score = 50.0

            # Uptime (20%)
            restarts = miner.get("restart_count", miner.get("total_restarts", 0)) or 0
            offline_count = miner.get("offline_count", 0) or 0
            uptime_penalty = min(100, (restarts * 5) + (offline_count * 10))
            uptime_score = max(0.0, 100.0 - uptime_penalty)

            # Share quality (15%)
            accepted = miner.get("shares_accepted", 0) or 0
            rejected = miner.get("shares_rejected", 0) or 0
            total_shares = accepted + rejected
            if total_shares > 10:
                reject_pct = (rejected / total_shares) * 100
                share_score = max(0.0, 100.0 - (reject_pct * 10))
            else:
                share_score = 50.0

            # WiFi RSSI (15%)
            rssi = miner.get("wifi_rssi", 0) or 0
            if rssi == 0:
                rssi_score = 50.0
            elif rssi >= -50:
                rssi_score = 100.0
            elif rssi >= -65:
                rssi_score = 80.0
            elif rssi >= -75:
                rssi_score = 50.0
            elif rssi >= -85:
                rssi_score = 20.0
            else:
                rssi_score = 0.0

            composite = (
                temp_score * 0.25
                + hr_score * 0.25
                + uptime_score * 0.20
                + share_score * 0.15
                + rssi_score * 0.15
            )

            if composite >= 90:
                grade = "A"
            elif composite >= 75:
                grade = "B"
            elif composite >= 60:
                grade = "C"
            elif composite >= 40:
                grade = "D"
            else:
                grade = "F"

            results[mac] = {
                "score": round(composite, 1),
                "grade": grade,
                "hostname": miner.get("hostname", mac),
                "status": miner.get("status", "unknown"),
                "scoring": "full",
                "components": {
                    "temperature": round(temp_score, 1),
                    "hashrate_stability": round(hr_score, 1),
                    "uptime": round(uptime_score, 1),
                    "share_quality": round(share_score, 1),
                    "wifi_signal": round(rssi_score, 1),
                },
            }

        # --- Phase 2: Pool-only miners (NerdMiners, cgminers) ---
        # These lack hardware telemetry — score on pool data only:
        #   hashrate stability (35%), online status (35%), best difficulty (30%)
        pool_workers = self.device_db.get_all_pool_workers()
        scored_macs = set(results.keys())

        # Compute fleet-wide best difficulty for relative scoring
        fleet_best_diff = 0.0
        for pw in pool_workers:
            try:
                d = float(pw.get("best_difficulty", 0) or 0)
                if d > fleet_best_diff:
                    fleet_best_diff = d
            except (ValueError, TypeError):
                pass

        for pw in pool_workers:
            mac = (pw.get("mac") or "").lower()
            worker_type = pw.get("worker_type", "unknown")

            # Skip AxeOS miners already scored with full telemetry
            if mac and mac in scored_macs:
                continue
            # Skip workers with no type classification
            if worker_type not in ("nerdminer", "cgminer"):
                continue

            worker_name = pw.get("worker_name", "unknown")
            status = pw.get("status", "unknown")

            # Hashrate stability (35%): 1h vs 1d ratio
            hr_1h = float(pw.get("hashrate_1h", 0) or 0)
            hr_1d = float(pw.get("hashrate_1d", 0) or 0)
            if hr_1d > 0 and hr_1h > 0:
                ratio = min(hr_1h / hr_1d, 1.2)
                hr_score = min(100.0, ratio * 83.3)
            elif status == "offline":
                hr_score = 0.0
            else:
                hr_score = 50.0

            # Online status (35%)
            online_score = 100.0 if status == "online" else 0.0

            # Best difficulty (30%): relative to fleet best
            try:
                worker_diff = float(pw.get("best_difficulty", 0) or 0)
            except (ValueError, TypeError):
                worker_diff = 0.0

            if fleet_best_diff > 0 and worker_diff > 0:
                # Log scale — even small diffs relative to fleet best
                # should score decently since difficulty is largely luck
                import math
                diff_ratio = math.log10(max(worker_diff, 1)) / math.log10(max(fleet_best_diff, 10))
                diff_score = min(100.0, diff_ratio * 100.0)
            else:
                diff_score = 50.0

            composite = (
                hr_score * 0.35
                + online_score * 0.35
                + diff_score * 0.30
            )

            if composite >= 90:
                grade = "A"
            elif composite >= 75:
                grade = "B"
            elif composite >= 60:
                grade = "C"
            elif composite >= 40:
                grade = "D"
            else:
                grade = "F"

            # Use MAC if available, otherwise key by worker name
            key = mac if mac else f"pool:{worker_name}"

            results[key] = {
                "score": round(composite, 1),
                "grade": grade,
                "hostname": worker_name,
                "status": status,
                "worker_type": worker_type,
                "scoring": "pool",
                "components": {
                    "hashrate_stability": round(hr_score, 1),
                    "online_status": round(online_score, 1),
                    "best_difficulty": round(diff_score, 1),
                },
            }

        return results

    def get_miner_detail(self, identifier):
        """Get detail for a specific miner by MAC, hostname, or pool worker name."""
        identifier = identifier.lower().strip()

        # Try as pool worker name first
        pool_worker = self.device_db.get_pool_worker(identifier)

        # Try as MAC in AxeOS stats
        miner = self.device_db.get_miner(identifier)
        if miner:
            # Merge with pool data if correlated
            if pool_worker:
                miner["pool"] = pool_worker
            else:
                # Try to find pool worker by checking correlation
                for wname, wmac in self._worker_to_mac.items():
                    if wmac == identifier:
                        pw = self.device_db.get_pool_worker(wname)
                        if pw:
                            miner["pool"] = pw
                        break
            return miner

        # If found as pool worker only
        if pool_worker:
            return pool_worker

        # Try hostname match across both tables
        all_miners = self.device_db.get_all_miners()
        for m in all_miners:
            if identifier in (m.get("hostname", "").lower()):
                return m

        all_pool = self.device_db.get_all_pool_workers()
        for pw in all_pool:
            if identifier in pw.get("worker_name", "").lower():
                return pw

        return None

    def get_connectivity_suggestions(self):
        """Analyze WiFi RSSI, reconnect patterns, and suggest improvements."""
        stats = self.device_db.get_miner_connectivity_stats()
        if not stats:
            return "No miner connectivity data available yet."

        suggestions = []
        weak_rssi = []
        high_reconnects = []
        high_offline = []

        for m in stats:
            rssi = m.get("wifi_rssi", 0)
            reconnects = m.get("reconnects_24h", 0)
            offline_count = m.get("offline_count", 0)
            name = m.get("hostname") or m.get("mac")

            if rssi and rssi < -75:
                weak_rssi.append(f"{name} (RSSI {rssi}dBm)")
            if reconnects > 10:
                high_reconnects.append(f"{name} ({reconnects} reconnects/24h)")
            if offline_count > 5:
                high_offline.append(f"{name} ({offline_count} offline events)")

        if weak_rssi:
            suggestions.append(
                f"WEAK SIGNAL: {len(weak_rssi)} miners with poor WiFi — "
                f"consider dedicated AP placement or 2.4GHz-only SSID. "
                f"Affected: {', '.join(weak_rssi[:5])}"
            )

        if high_reconnects:
            suggestions.append(
                f"UNSTABLE CONNECTIONS: {len(high_reconnects)} miners with frequent reconnects — "
                f"check for channel congestion, consider static DHCP reservations and "
                f"dedicated IoT VLAN. ESP32 WiFi benefits from disabling power save mode. "
                f"Affected: {', '.join(high_reconnects[:5])}"
            )

        if high_offline:
            suggestions.append(
                f"FREQUENT DROPOUTS: {len(high_offline)} miners with repeated offline events — "
                f"may need firmware updates, power supply check, or reduced TX power setting. "
                f"Affected: {', '.join(high_offline[:5])}"
            )

        if not suggestions:
            suggestions.append("Fleet connectivity nominal. No issues detected.")

        return "\n".join(suggestions)

    def format_fleet_report(self):
        """Format unified fleet summary as natural language for W.O.P.R. voice."""
        summary = self.get_fleet_summary()

        # Use pool data if available, fall back to AxeOS-only
        if "total_workers" in summary:
            total = summary["total_workers"]
            online = summary["pool_online"]
            hashrate = summary["total_hashrate_1h"]
            best = summary["best_difficulty"]
            temp = summary.get("avg_temp", 0)
            by_type = summary.get("by_type", {})

            type_breakdown = []
            for wtype, stats in sorted(by_type.items()):
                type_breakdown.append(
                    f"{stats['count']} {wtype} ({stats['online']} online, "
                    f"{_format_hashrate(stats['hashrate_1h'])})"
                )
            breakdown_str = ". ".join(type_breakdown) if type_breakdown else "No type data"

            parts = [
                f"MINING FLEET STATUS. {online} of {total} workers online.",
                f"Total hashrate: {_format_hashrate(hashrate)}.",
                f"Fleet composition: {breakdown_str}.",
                f"Best difficulty: {best:,.0f}." if best else "",
            ]
            if temp > 0:
                parts.append(f"AxeOS average temperature: {temp:.1f}C.")
            if summary.get("overheating", 0) > 0:
                parts.append(f"ALERT: {summary['overheating']} miners overheating.")
            if summary.get("throttled", 0) > 0:
                parts.append(f"THROTTLED: {summary['throttled']} miners at reduced clock speed.")
            if summary.get("pool_api_down"):
                parts.append("WARNING: Pool API unreachable. Fleet data from AxeOS direct telemetry only.")
            parts.append("W.O.P.R. out.")
            return " ".join(p for p in parts if p)

        # AxeOS-only fallback
        if summary.get("total", 0) == 0:
            return "MINING FLEET. No miners registered. W.O.P.R. out."

        return (
            f"MINING FLEET STATUS. {summary['online']} of {summary['total']} miners online. "
            f"Total hashrate: {summary['total_hashrate']:.1f} GH/s. "
            f"Average temperature: {summary['avg_temp']:.1f}C. "
            f"Best difficulty: {summary['best_diff']}. "
            f"Overheating: {summary.get('overheating', 0)}. "
            f"Total restarts: {summary.get('total_restarts', 0)}. "
            f"W.O.P.R. out."
        )
