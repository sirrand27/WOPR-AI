"""
W.O.P.R. Persistent Device Knowledge Base
SQLite-backed device tracking, connection history, response audit trail,
and mining fleet statistics. Foundation for behavioral analysis,
graduated response, and fleet management.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Default DB path — overridden by config.DEVICE_DB_PATH
_DEFAULT_DB = "/home/sirrand/pentest/local_joshua/wopr_devices.db"


class DeviceKnowledgeBase:
    """SQLite-backed persistent device and miner knowledge base."""

    def __init__(self, db_path=None):
        from config import DEVICE_DB_PATH
        self.db_path = db_path or DEVICE_DB_PATH or _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()
        logger.info(f"Device KB initialized: {self.db_path}")

    def _conn(self):
        """Get a thread-local SQLite connection."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS devices (
                        mac TEXT PRIMARY KEY,
                        hostname TEXT DEFAULT 'unknown',
                        oui TEXT DEFAULT '',
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        trust_level TEXT DEFAULT 'unknown'
                            CHECK(trust_level IN ('trusted','known','unknown','suspicious','blocked')),
                        connection_count INTEGER DEFAULT 1,
                        networks TEXT DEFAULT '[]',
                        ip_history TEXT DEFAULT '[]',
                        avg_tx_bytes REAL DEFAULT 0.0,
                        avg_rx_bytes REAL DEFAULT 0.0,
                        typical_hours TEXT DEFAULT '[]',
                        dpi_baseline TEXT DEFAULT '{}',
                        alert_count INTEGER DEFAULT 0,
                        last_alert TEXT,
                        notes TEXT DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS connection_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        event_type TEXT NOT NULL
                            CHECK(event_type IN ('connect','disconnect','reconnect')),
                        timestamp TEXT NOT NULL,
                        network TEXT DEFAULT '',
                        ip TEXT DEFAULT '',
                        FOREIGN KEY (mac) REFERENCES devices(mac)
                    );

                    CREATE INDEX IF NOT EXISTS idx_connlog_mac_ts
                        ON connection_log(mac, timestamp);

                    CREATE TABLE IF NOT EXISTS response_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        action TEXT NOT NULL,
                        reason TEXT DEFAULT '',
                        posture TEXT DEFAULT '',
                        timestamp TEXT NOT NULL,
                        approved_by TEXT DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS pool_workers (
                        worker_name TEXT PRIMARY KEY,
                        hashrate_5m REAL DEFAULT 0.0,
                        hashrate_1h REAL DEFAULT 0.0,
                        hashrate_12h REAL DEFAULT 0.0,
                        hashrate_1d REAL DEFAULT 0.0,
                        best_difficulty REAL DEFAULT 0.0,
                        last_seen TEXT DEFAULT '',
                        start_time TEXT DEFAULT '',
                        worker_type TEXT DEFAULT 'unknown'
                            CHECK(worker_type IN ('axeos','nerdminer','cgminer','unknown')),
                        mac TEXT DEFAULT '',
                        ip TEXT DEFAULT '',
                        last_poll TEXT,
                        status TEXT DEFAULT 'unknown'
                            CHECK(status IN ('online','offline','stale','unknown'))
                    );

                    CREATE TABLE IF NOT EXISTS trust_level_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT NOT NULL,
                        old_level TEXT NOT NULL,
                        new_level TEXT NOT NULL,
                        reason TEXT DEFAULT '',
                        actor TEXT DEFAULT 'wopr',
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (mac) REFERENCES devices(mac)
                    );

                    CREATE INDEX IF NOT EXISTS idx_trust_history_mac
                        ON trust_level_history(mac, timestamp);

                    CREATE TABLE IF NOT EXISTS miner_stats (
                        mac TEXT PRIMARY KEY,
                        ip TEXT DEFAULT '',
                        hostname TEXT DEFAULT '',
                        last_hashrate REAL DEFAULT 0.0,
                        avg_hashrate REAL DEFAULT 0.0,
                        last_temp REAL DEFAULT 0.0,
                        max_temp REAL DEFAULT 0.0,
                        best_diff TEXT DEFAULT '0',
                        pool_url TEXT DEFAULT '',
                        pool_user TEXT DEFAULT '',
                        voltage REAL DEFAULT 0.0,
                        frequency REAL DEFAULT 0.0,
                        fan_speed INTEGER DEFAULT 0,
                        wifi_rssi INTEGER DEFAULT 0,
                        shares_accepted INTEGER DEFAULT 0,
                        shares_rejected INTEGER DEFAULT 0,
                        uptime_seconds INTEGER DEFAULT 0,
                        last_restart TEXT,
                        restart_count INTEGER DEFAULT 0,
                        offline_count INTEGER DEFAULT 0,
                        last_poll TEXT,
                        status TEXT DEFAULT 'unknown'
                            CHECK(status IN ('online','offline','overheating','restarting','unknown'))
                    );
                """)
                conn.commit()
                logger.info("Device KB tables verified")
            finally:
                conn.close()

    # ── Device CRUD ──────────────────────────────────────────────

    def upsert_device(self, mac, hostname="unknown", oui="", network="",
                      ip="", tx_bytes=0, rx_bytes=0):
        """Insert or update device on each poll cycle."""
        now = datetime.now(timezone.utc).isoformat()
        mac = mac.lower()
        oui = oui or mac[:8]

        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM devices WHERE mac = ?", (mac,)
                ).fetchone()

                if row is None:
                    # New device
                    networks = json.dumps([network] if network else [])
                    ip_hist = json.dumps([ip] if ip else [])
                    conn.execute("""
                        INSERT INTO devices
                            (mac, hostname, oui, first_seen, last_seen,
                             connection_count, networks, ip_history,
                             avg_tx_bytes, avg_rx_bytes)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """, (mac, hostname, oui, now, now,
                          networks, ip_hist, float(tx_bytes), float(rx_bytes)))
                else:
                    # Update existing
                    count = (row["connection_count"] or 0) + 1

                    # Update networks list
                    try:
                        nets = json.loads(row["networks"] or "[]")
                    except json.JSONDecodeError:
                        nets = []
                    if network and network not in nets:
                        nets.append(network)

                    # Update IP history (keep last 20)
                    try:
                        ips = json.loads(row["ip_history"] or "[]")
                    except json.JSONDecodeError:
                        ips = []
                    if ip and (not ips or ips[-1] != ip):
                        ips.append(ip)
                        ips = ips[-20:]

                    # Rolling average for bandwidth (EMA: 0.9 old + 0.1 new)
                    avg_tx = row["avg_tx_bytes"] or 0.0
                    avg_rx = row["avg_rx_bytes"] or 0.0
                    if tx_bytes > 0:
                        avg_tx = 0.9 * avg_tx + 0.1 * float(tx_bytes)
                    if rx_bytes > 0:
                        avg_rx = 0.9 * avg_rx + 0.1 * float(rx_bytes)

                    conn.execute("""
                        UPDATE devices SET
                            hostname = ?, last_seen = ?, connection_count = ?,
                            networks = ?, ip_history = ?,
                            avg_tx_bytes = ?, avg_rx_bytes = ?
                        WHERE mac = ?
                    """, (hostname or row["hostname"], now, count,
                          json.dumps(nets), json.dumps(ips),
                          avg_tx, avg_rx, mac))

                conn.commit()
            finally:
                conn.close()

    def get_device(self, mac):
        """Get device record by MAC."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (mac.lower(),)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_all_devices(self):
        """Get all tracked devices."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_device_count(self):
        """Get total number of tracked devices."""
        conn = self._conn()
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM devices").fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def set_trust_level(self, mac, level, reason="", actor="wopr"):
        """Set trust level for a device, logging the transition."""
        valid = ('trusted', 'known', 'unknown', 'suspicious', 'blocked')
        if level not in valid:
            logger.warning(f"Invalid trust level: {level}")
            return False
        mac = mac.lower()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                # Get current level for audit trail
                row = conn.execute(
                    "SELECT trust_level FROM devices WHERE mac = ?", (mac,)
                ).fetchone()
                old_level = row["trust_level"] if row else "unknown"

                if old_level != level:
                    # Log the transition
                    conn.execute(
                        "INSERT INTO trust_level_history "
                        "(mac, old_level, new_level, reason, actor, timestamp) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (mac, old_level, level, reason, actor, now)
                    )
                    logger.info(
                        f"Trust level change: {mac} {old_level} -> {level} "
                        f"(reason: {reason}, actor: {actor})"
                    )

                conn.execute(
                    "UPDATE devices SET trust_level = ? WHERE mac = ?",
                    (level, mac)
                )
                conn.commit()
                return True
            finally:
                conn.close()

    def get_trust_history(self, mac, days=30):
        """Get trust level transition history for a device."""
        mac = mac.lower()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT old_level, new_level, reason, actor, timestamp "
                    "FROM trust_level_history WHERE mac = ? AND timestamp > ? "
                    "ORDER BY timestamp DESC",
                    (mac, cutoff)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def increment_alert_count(self, mac):
        """Increment alert count for a device."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    UPDATE devices SET
                        alert_count = alert_count + 1,
                        last_alert = ?
                    WHERE mac = ?
                """, (now, mac.lower()))
                conn.commit()
            finally:
                conn.close()

    # ── Connection Log ───────────────────────────────────────────

    def log_connection(self, mac, event_type, network="", ip=""):
        """Log a connection event (connect/disconnect/reconnect)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    INSERT INTO connection_log (mac, event_type, timestamp, network, ip)
                    VALUES (?, ?, ?, ?, ?)
                """, (mac.lower(), event_type, now, network, ip))
                conn.commit()
            finally:
                conn.close()

    def get_reconnect_count(self, mac, window_minutes=10):
        """Count reconnections within a time window (deauth detection)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        conn = self._conn()
        try:
            row = conn.execute("""
                SELECT COUNT(*) as cnt FROM connection_log
                WHERE mac = ? AND event_type IN ('connect', 'reconnect')
                AND timestamp > ?
            """, (mac.lower(), cutoff)).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def get_recent_connections(self, mac, limit=20):
        """Get recent connection events for a device."""
        conn = self._conn()
        try:
            rows = conn.execute("""
                SELECT * FROM connection_log
                WHERE mac = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (mac.lower(), limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Temporal Analysis ────────────────────────────────────────

    def update_typical_hours(self, mac, hour):
        """Track which hours a device is typically seen (0-23)."""
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT typical_hours FROM devices WHERE mac = ?",
                    (mac.lower(),)
                ).fetchone()
                if not row:
                    return
                try:
                    hours = json.loads(row["typical_hours"] or "[]")
                except json.JSONDecodeError:
                    hours = []
                hours.append(hour)
                # Keep last 168 entries (7 days of hourly samples)
                hours = hours[-168:]
                conn.execute(
                    "UPDATE devices SET typical_hours = ? WHERE mac = ?",
                    (json.dumps(hours), mac.lower())
                )
                conn.commit()
            finally:
                conn.close()

    def is_unusual_hour(self, mac, current_hour):
        """Check if current hour is unusual for this device.
        Requires 72+ hours of history to be meaningful."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT typical_hours FROM devices WHERE mac = ?",
                (mac.lower(),)
            ).fetchone()
            if not row:
                return False
            try:
                hours = json.loads(row["typical_hours"] or "[]")
            except json.JSONDecodeError:
                return False
            if len(hours) < 72:
                return False  # Not enough history
            hour_set = set(hours)
            return current_hour not in hour_set
        finally:
            conn.close()

    # ── DPI Baseline ─────────────────────────────────────────────

    def update_dpi_baseline(self, mac, dpi_data):
        """Update DPI traffic baseline for a device."""
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT dpi_baseline FROM devices WHERE mac = ?",
                    (mac.lower(),)
                ).fetchone()
                if not row:
                    return
                try:
                    baseline = json.loads(row["dpi_baseline"] or "{}")
                except json.JSONDecodeError:
                    baseline = {}
                # EMA update for each DPI category
                for cat, val in dpi_data.items():
                    old = baseline.get(cat, 0)
                    baseline[cat] = 0.9 * old + 0.1 * float(val)
                conn.execute(
                    "UPDATE devices SET dpi_baseline = ? WHERE mac = ?",
                    (json.dumps(baseline), mac.lower())
                )
                conn.commit()
            finally:
                conn.close()

    def get_dpi_deviation(self, mac, current_dpi):
        """Check if current DPI deviates significantly from baseline.
        Returns list of (category, current, baseline, ratio) for deviations > 3x."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT dpi_baseline FROM devices WHERE mac = ?",
                (mac.lower(),)
            ).fetchone()
            if not row:
                return []
            try:
                baseline = json.loads(row["dpi_baseline"] or "{}")
            except json.JSONDecodeError:
                return []
            deviations = []
            for cat, val in current_dpi.items():
                base = baseline.get(cat, 0)
                if base > 0 and float(val) > base * 3:
                    deviations.append({
                        "category": cat,
                        "current": float(val),
                        "baseline": base,
                        "ratio": round(float(val) / base, 1),
                    })
            return deviations
        finally:
            conn.close()

    # ── Baseline Recovery ────────────────────────────────────────

    def load_baseline_state(self):
        """Load known clients and OUIs from DB for instant baseline recovery.
        Returns (known_clients_dict, known_ouis_set, device_count)."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT mac, hostname, oui, first_seen, networks, connection_count "
                "FROM devices ORDER BY last_seen DESC"
            ).fetchall()
            known_clients = {}
            known_ouis = set()
            for r in rows:
                mac = r["mac"]
                try:
                    nets = set(json.loads(r["networks"] or "[]"))
                except json.JSONDecodeError:
                    nets = set()
                known_clients[mac] = {
                    "hostname": r["hostname"],
                    "oui": r["oui"],
                    "first_seen": r["first_seen"],
                    "networks": nets,
                    "connection_count": r["connection_count"] or 0,
                }
                if r["oui"]:
                    known_ouis.add(r["oui"])
            return known_clients, known_ouis, len(rows)
        finally:
            conn.close()

    # ── Reporting ────────────────────────────────────────────────

    def get_hourly_delta(self, hours=1):
        """Get devices that connected/disconnected in the last N hours."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conn = self._conn()
        try:
            connects = conn.execute("""
                SELECT DISTINCT mac FROM connection_log
                WHERE event_type = 'connect' AND timestamp > ?
            """, (cutoff,)).fetchall()
            disconnects = conn.execute("""
                SELECT DISTINCT mac FROM connection_log
                WHERE event_type = 'disconnect' AND timestamp > ?
            """, (cutoff,)).fetchall()
            return {
                "new_connections": [r["mac"] for r in connects],
                "disconnections": [r["mac"] for r in disconnects],
            }
        finally:
            conn.close()

    def get_daily_digest(self):
        """Get 24-hour summary for daily report."""
        conn = self._conn()
        try:
            total = conn.execute("SELECT COUNT(*) as cnt FROM devices").fetchone()["cnt"]
            cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            active = conn.execute(
                "SELECT COUNT(*) as cnt FROM devices WHERE last_seen > ?",
                (cutoff_24h,)
            ).fetchone()["cnt"]

            trust_rows = conn.execute(
                "SELECT trust_level, COUNT(*) as cnt FROM devices GROUP BY trust_level"
            ).fetchall()
            trust = {r["trust_level"]: r["cnt"] for r in trust_rows}

            alerts = conn.execute(
                "SELECT SUM(alert_count) as total FROM devices"
            ).fetchone()["total"] or 0

            return {
                "total_tracked": total,
                "active_24h": active,
                "trust_breakdown": trust,
                "total_alerts": alerts,
            }
        finally:
            conn.close()

    # ── Response Actions ─────────────────────────────────────────

    def log_response_action(self, mac, action, reason="", posture="",
                            approved_by=""):
        """Log a graduated response action."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    INSERT INTO response_actions
                        (mac, action, reason, posture, timestamp, approved_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (mac.lower(), action, reason, posture, now, approved_by))
                conn.commit()
            finally:
                conn.close()

    def get_response_history(self, mac, limit=10):
        """Get response action history for a device."""
        conn = self._conn()
        try:
            rows = conn.execute("""
                SELECT * FROM response_actions
                WHERE mac = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (mac.lower(), limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Miner Stats ──────────────────────────────────────────────

    def upsert_miner(self, mac, ip="", hostname="", hashrate=0.0,
                     temp=0.0, best_diff="0", pool_url="", pool_user="",
                     voltage=0.0, frequency=0.0, fan_speed=0,
                     wifi_rssi=0, shares_accepted=0, shares_rejected=0,
                     uptime_seconds=0, status="online"):
        """Insert or update miner stats from AxeOS poll."""
        now = datetime.now(timezone.utc).isoformat()
        mac = mac.lower()

        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM miner_stats WHERE mac = ?", (mac,)
                ).fetchone()

                if row is None:
                    conn.execute("""
                        INSERT INTO miner_stats
                            (mac, ip, hostname, last_hashrate, avg_hashrate,
                             last_temp, max_temp, best_diff, pool_url, pool_user,
                             voltage, frequency, fan_speed, wifi_rssi,
                             shares_accepted, shares_rejected, uptime_seconds,
                             last_poll, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (mac, ip, hostname, hashrate, hashrate,
                          temp, temp, best_diff, pool_url, pool_user,
                          voltage, frequency, fan_speed, wifi_rssi,
                          shares_accepted, shares_rejected, uptime_seconds,
                          now, status))
                else:
                    # EMA for hashrate
                    avg_hr = row["avg_hashrate"] or 0.0
                    if hashrate > 0:
                        avg_hr = 0.9 * avg_hr + 0.1 * hashrate
                    max_t = max(row["max_temp"] or 0.0, temp)

                    conn.execute("""
                        UPDATE miner_stats SET
                            ip = ?, hostname = ?,
                            last_hashrate = ?, avg_hashrate = ?,
                            last_temp = ?, max_temp = ?,
                            best_diff = ?, pool_url = ?, pool_user = ?,
                            voltage = ?, frequency = ?, fan_speed = ?,
                            wifi_rssi = ?, shares_accepted = ?,
                            shares_rejected = ?, uptime_seconds = ?,
                            last_poll = ?, status = ?
                        WHERE mac = ?
                    """, (ip, hostname or row["hostname"],
                          hashrate, avg_hr,
                          temp, max_t,
                          best_diff or row["best_diff"],
                          pool_url or row["pool_url"],
                          pool_user or row["pool_user"],
                          voltage, frequency, fan_speed, wifi_rssi,
                          shares_accepted, shares_rejected, uptime_seconds,
                          now, status, mac))

                conn.commit()
            finally:
                conn.close()

    def get_miner(self, mac):
        """Get miner stats by MAC."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM miner_stats WHERE mac = ?", (mac.lower(),)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_all_miners(self):
        """Get all miner stats."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM miner_stats ORDER BY hostname, mac"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_fleet_summary(self):
        """Get aggregated fleet statistics."""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM miner_stats").fetchall()
            if not rows:
                return {
                    "total": 0, "online": 0, "offline": 0,
                    "total_hashrate": 0.0, "avg_temp": 0.0,
                    "best_diff": "0",
                }

            miners = [dict(r) for r in rows]
            online = [m for m in miners if m["status"] == "online"]
            total_hr = sum(m["last_hashrate"] for m in online)
            temps = [m["last_temp"] for m in online if m["last_temp"] > 0]
            avg_temp = sum(temps) / len(temps) if temps else 0.0

            # Best difficulty across fleet
            best = "0"
            for m in miners:
                try:
                    if float(m["best_diff"] or "0") > float(best):
                        best = m["best_diff"]
                except (ValueError, TypeError):
                    pass

            return {
                "total": len(miners),
                "online": len(online),
                "offline": len(miners) - len(online),
                "total_hashrate": round(total_hr, 2),
                "avg_temp": round(avg_temp, 1),
                "best_diff": best,
                "overheating": len([m for m in online if m["status"] == "overheating"]),
                "total_restarts": sum(m["restart_count"] or 0 for m in miners),
                "total_offline_events": sum(m["offline_count"] or 0 for m in miners),
            }
        finally:
            conn.close()

    def record_miner_restart(self, mac):
        """Increment restart count and update last restart time."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    UPDATE miner_stats SET
                        restart_count = restart_count + 1,
                        last_restart = ?,
                        status = 'restarting'
                    WHERE mac = ?
                """, (now, mac.lower()))
                conn.commit()
            finally:
                conn.close()

    def record_miner_offline(self, mac):
        """Increment offline count and set status to offline."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    UPDATE miner_stats SET
                        offline_count = offline_count + 1,
                        status = 'offline'
                    WHERE mac = ?
                """, (mac.lower(),))
                conn.commit()
            finally:
                conn.close()

    def get_miner_connectivity_stats(self):
        """Get connectivity statistics for all miners — for suggestions."""
        conn = self._conn()
        try:
            miners = conn.execute(
                "SELECT mac, hostname, ip, wifi_rssi, offline_count, restart_count "
                "FROM miner_stats ORDER BY offline_count DESC"
            ).fetchall()
            result = []
            for m in miners:
                mac = m["mac"]
                # Get reconnect frequency from connection_log
                cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                reconnects = conn.execute("""
                    SELECT COUNT(*) as cnt FROM connection_log
                    WHERE mac = ? AND event_type IN ('connect', 'reconnect')
                    AND timestamp > ?
                """, (mac, cutoff_24h)).fetchone()["cnt"]
                result.append({
                    "mac": mac,
                    "hostname": m["hostname"],
                    "ip": m["ip"],
                    "wifi_rssi": m["wifi_rssi"],
                    "offline_count": m["offline_count"],
                    "restart_count": m["restart_count"],
                    "reconnects_24h": reconnects,
                })
            return result
        finally:
            conn.close()

    # ── Pool Workers ──────────────────────────────────────────────

    def upsert_pool_worker(self, worker_name, hashrate_5m=0.0, hashrate_1h=0.0,
                           hashrate_12h=0.0, hashrate_1d=0.0, best_difficulty=0.0,
                           last_seen="", start_time="", worker_type="unknown",
                           mac="", ip="", status="online"):
        """Insert or update a pool worker from Public Pool API."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM pool_workers WHERE worker_name = ?",
                    (worker_name,)
                ).fetchone()

                if row is None:
                    conn.execute("""
                        INSERT INTO pool_workers
                            (worker_name, hashrate_5m, hashrate_1h, hashrate_12h,
                             hashrate_1d, best_difficulty, last_seen, start_time,
                             worker_type, mac, ip, last_poll, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (worker_name, hashrate_5m, hashrate_1h, hashrate_12h,
                          hashrate_1d, best_difficulty, last_seen, start_time,
                          worker_type, mac, ip, now, status))
                else:
                    conn.execute("""
                        UPDATE pool_workers SET
                            hashrate_5m = ?, hashrate_1h = ?, hashrate_12h = ?,
                            hashrate_1d = ?, best_difficulty = ?,
                            last_seen = ?, start_time = ?,
                            worker_type = ?, mac = COALESCE(NULLIF(?, ''), mac),
                            ip = COALESCE(NULLIF(?, ''), ip),
                            last_poll = ?, status = ?
                        WHERE worker_name = ?
                    """, (hashrate_5m, hashrate_1h, hashrate_12h,
                          hashrate_1d, best_difficulty,
                          last_seen or row["last_seen"],
                          start_time or row["start_time"],
                          worker_type if worker_type != "unknown" else row["worker_type"],
                          mac, ip, now, status, worker_name))

                conn.commit()
            finally:
                conn.close()

    def get_pool_worker(self, worker_name):
        """Get a pool worker by name."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM pool_workers WHERE worker_name = ?",
                (worker_name,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_all_pool_workers(self):
        """Get all pool workers."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM pool_workers ORDER BY hashrate_1h DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_pool_fleet_summary(self):
        """Get aggregated pool fleet statistics (all 26 workers)."""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM pool_workers").fetchall()
            if not rows:
                return {
                    "total_workers": 0, "online": 0, "offline": 0,
                    "total_hashrate_1h": 0.0, "best_difficulty": 0.0,
                    "by_type": {},
                }

            workers = [dict(r) for r in rows]
            online = [w for w in workers if w["status"] == "online"]
            total_hr = sum(w["hashrate_1h"] for w in online)

            best = 0.0
            for w in workers:
                try:
                    d = float(w["best_difficulty"] or 0)
                    if d > best:
                        best = d
                except (ValueError, TypeError):
                    pass

            # Breakdown by type
            by_type = {}
            for w in workers:
                wt = w["worker_type"]
                if wt not in by_type:
                    by_type[wt] = {"count": 0, "online": 0, "hashrate_1h": 0.0}
                by_type[wt]["count"] += 1
                if w["status"] == "online":
                    by_type[wt]["online"] += 1
                    by_type[wt]["hashrate_1h"] += w["hashrate_1h"]

            return {
                "total_workers": len(workers),
                "online": len(online),
                "offline": len(workers) - len(online),
                "total_hashrate_1h": round(total_hr, 2),
                "best_difficulty": best,
                "by_type": by_type,
            }
        finally:
            conn.close()

    def link_pool_worker_mac(self, worker_name, mac):
        """Link a pool worker to a network MAC address."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "UPDATE pool_workers SET mac = ? WHERE worker_name = ?",
                    (mac.lower(), worker_name)
                )
                conn.commit()
            finally:
                conn.close()

    # ── Forensic Query Methods (tool bridge) ─────────────────────

    def get_device_by_name(self, name):
        """Search devices by hostname, MAC, or IP (case-insensitive partial match)."""
        conn = self._conn()
        try:
            # Check if it looks like a MAC address (must have MAC-like hex:hex pattern)
            import re
            if re.search(r'^([0-9a-f]{2}[:-]){2,5}[0-9a-f]{2}$', name.lower()):
                rows = conn.execute(
                    "SELECT * FROM devices WHERE mac LIKE ? ORDER BY last_seen DESC",
                    (f"%{name.lower()}%",)
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]

            # Check if it looks like an IP address
            if name.count(".") >= 2 and any(c.isdigit() for c in name):
                rows = conn.execute(
                    "SELECT * FROM devices WHERE ip_history LIKE ? ORDER BY last_seen DESC",
                    (f"%{name}%",)
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]

            # Default: hostname search
            rows = conn.execute(
                "SELECT * FROM devices WHERE hostname LIKE ? ORDER BY last_seen DESC",
                (f"%{name}%",)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_device_timeline(self, mac, hours=24):
        """Get connection timeline for a device within the last N hours."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conn = self._conn()
        try:
            device = conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (mac.lower(),)
            ).fetchone()
            events = conn.execute("""
                SELECT * FROM connection_log
                WHERE mac = ? AND timestamp > ?
                ORDER BY timestamp ASC
            """, (mac.lower(), cutoff)).fetchall()
            return {
                "device": dict(device) if device else None,
                "events": [dict(r) for r in events],
                "window_hours": hours,
            }
        finally:
            conn.close()

    def get_cross_device_correlation(self, mac, window_minutes=30):
        """Find devices with connection events near the same times as the target MAC.
        Identifies devices that consistently appear/disappear together."""
        mac = mac.lower()
        conn = self._conn()
        try:
            # Get target device's recent connection events
            target_events = conn.execute(
                "SELECT timestamp FROM connection_log "
                "WHERE mac = ? ORDER BY timestamp DESC LIMIT 50",
                (mac,)
            ).fetchall()
            if not target_events:
                return {
                    "mac": mac,
                    "correlated_devices": [],
                    "note": "No connection events found for this MAC",
                }

            # For each event, find other MACs with events within the window
            correlated = {}
            for evt in target_events:
                ts = evt["timestamp"]
                try:
                    dt = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    continue
                window_start = (dt - timedelta(minutes=window_minutes)).isoformat()
                window_end = (dt + timedelta(minutes=window_minutes)).isoformat()

                nearby = conn.execute("""
                    SELECT DISTINCT mac FROM connection_log
                    WHERE mac != ? AND timestamp BETWEEN ? AND ?
                """, (mac, window_start, window_end)).fetchall()

                for row in nearby:
                    other_mac = row["mac"]
                    if other_mac not in correlated:
                        correlated[other_mac] = {"mac": other_mac, "overlap_count": 0}
                    correlated[other_mac]["overlap_count"] += 1

            # Enrich with device info and sort by overlap count
            result = []
            for other_mac, info in sorted(
                correlated.items(),
                key=lambda x: x[1]["overlap_count"],
                reverse=True,
            ):
                device = conn.execute(
                    "SELECT hostname, trust_level, first_seen, last_seen "
                    "FROM devices WHERE mac = ?",
                    (other_mac,)
                ).fetchone()
                if device:
                    info.update(dict(device))
                result.append(info)

            return {
                "mac": mac,
                "window_minutes": window_minutes,
                "target_events_checked": len(target_events),
                "correlated_devices": result[:20],
            }
        finally:
            conn.close()

    def get_anomaly_history(self, mac, days=7):
        """Get response action / anomaly history for a device within the last N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        mac = mac.lower()
        conn = self._conn()
        try:
            device = conn.execute(
                "SELECT hostname, trust_level, alert_count, last_alert "
                "FROM devices WHERE mac = ?",
                (mac,)
            ).fetchone()
            actions = conn.execute("""
                SELECT * FROM response_actions
                WHERE mac = ? AND timestamp > ?
                ORDER BY timestamp DESC
            """, (mac, cutoff)).fetchall()
            return {
                "device_summary": dict(device) if device else None,
                "response_actions": [dict(r) for r in actions],
                "window_days": days,
            }
        finally:
            conn.close()
