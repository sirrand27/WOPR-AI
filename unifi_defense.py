"""
Local Joshua AI Agent — UniFi Network Defense Module
AI-augmented IDS layer using UniFi MCP on port 9600.

Polls UniFi MCP every 30s, maintains behavioral baselines,
classifies threats, auto-responds to CRITICAL, and reports
all detections to Blackboard + voice alerts.
"""

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from config import UNIFI_MCP_URL, AGENT_NAME

logger = logging.getLogger(__name__)

# Threat severity thresholds
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Polling interval (seconds)
DEFENSE_POLL_INTERVAL = 30


class UniFiMCPClient:
    """HTTP client for UniFi MCP on localhost:9600."""

    def __init__(self, base_url=None):
        import urllib.request
        import urllib.error
        self.base_url = (base_url or UNIFI_MCP_URL).rstrip("/")
        self._urllib = urllib.request
        self._urllib_error = urllib.error

    def _call_tool(self, tool_name, arguments=None, timeout=15):
        """Call an MCP tool on the UniFi MCP server."""
        url = f"{self.base_url}/mcp"
        data = {
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            }
        }
        body = json.dumps(data).encode()
        req = self._urllib.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"}
        )
        try:
            with self._urllib.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.error(f"UniFi MCP call failed: {tool_name} — {e}")
            return None

    # === Monitoring Tools (poll every 30s) ===

    def get_threat_summary(self):
        return self._call_tool("get_threat_summary")

    def get_alerts(self, limit=50):
        return self._call_tool("get_alerts", {"limit": limit})

    def get_events(self, limit=50):
        return self._call_tool("get_events", {"limit": limit})

    def get_syslog_events(self, limit=50):
        return self._call_tool("get_syslog_events", {"limit": limit})

    # === Investigation Tools (on-demand) ===

    def get_clients(self):
        return self._call_tool("get_clients", timeout=30)

    def get_client_detail(self, mac):
        return self._call_tool("get_client_detail", {"mac": mac})

    def search_clients(self, query):
        return self._call_tool("search_clients", {"query": query})

    def get_dpi_stats(self):
        return self._call_tool("get_dpi_stats", timeout=30)

    def get_devices(self):
        return self._call_tool("get_devices")

    def get_network_health(self):
        return self._call_tool("get_network_health")

    def get_firewall_rules(self):
        return self._call_tool("get_firewall_rules")

    # === Response Actions ===

    def block_client(self, mac, reason=""):
        return self._call_tool("block_client", {"mac": mac, "reason": reason})

    def unblock_client(self, mac):
        return self._call_tool("unblock_client", {"mac": mac})

    def kick_client(self, mac):
        return self._call_tool("kick_client", {"mac": mac})


class BehavioralBaseline:
    """Tracks normal network behavior and detects deviations."""

    def __init__(self):
        self.known_clients = {}       # mac -> {hostname, oui, first_seen, networks, ...}
        self.known_ouis = set()       # set of seen OUI prefixes
        self.client_count_history = []  # list of (timestamp, count)
        self.baseline_ready = False
        self._learning_cycles = 0
        self._min_learning_cycles = 10  # ~5 minutes of data before flagging

    def update_client_list(self, clients):
        """Update baseline with current client list. Returns list of anomalies."""
        anomalies = []
        if not clients:
            return anomalies

        current_macs = set()
        now = datetime.now(timezone.utc).isoformat()

        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue

            current_macs.add(mac)
            hostname = client.get("hostname", client.get("name", "unknown"))
            oui = mac[:8]  # First 3 octets
            network = client.get("network", client.get("essid", "unknown"))

            if mac not in self.known_clients:
                # New device detected
                self.known_clients[mac] = {
                    "hostname": hostname,
                    "oui": oui,
                    "first_seen": now,
                    "networks": {network},
                    "connection_count": 1,
                }

                if self.baseline_ready:
                    anomaly = {
                        "type": "new_device",
                        "mac": mac,
                        "hostname": hostname,
                        "oui": oui,
                        "network": network,
                    }
                    # Unknown OUI is more suspicious
                    if oui not in self.known_ouis:
                        anomaly["unknown_oui"] = True
                    anomalies.append(anomaly)
            else:
                # Known device — check for network changes
                known = self.known_clients[mac]
                known["connection_count"] = known.get("connection_count", 0) + 1

                if network and network not in known.get("networks", set()):
                    known.setdefault("networks", set()).add(network)
                    if self.baseline_ready:
                        anomalies.append({
                            "type": "network_change",
                            "mac": mac,
                            "hostname": known["hostname"],
                            "old_networks": list(known["networks"] - {network}),
                            "new_network": network,
                        })

            self.known_ouis.add(oui)

        # Track client count over time
        self.client_count_history.append((now, len(current_macs)))
        if len(self.client_count_history) > 1000:
            self.client_count_history = self.client_count_history[-500:]

        # Check for population spikes
        if self.baseline_ready and len(self.client_count_history) > 5:
            avg_count = sum(c for _, c in self.client_count_history[-20:]) / min(20, len(self.client_count_history))
            current_count = len(current_macs)
            if current_count > avg_count * 1.5 and current_count - avg_count > 3:
                anomalies.append({
                    "type": "population_spike",
                    "current_count": current_count,
                    "average_count": round(avg_count, 1),
                })

        # Advance learning
        self._learning_cycles += 1
        if self._learning_cycles >= self._min_learning_cycles and not self.baseline_ready:
            self.baseline_ready = True
            logger.info(f"Behavioral baseline established: {len(self.known_clients)} clients, "
                        f"{len(self.known_ouis)} OUIs tracked")

        return anomalies

    def get_summary(self):
        """Get baseline summary."""
        return {
            "total_known_clients": len(self.known_clients),
            "known_ouis": len(self.known_ouis),
            "baseline_ready": self.baseline_ready,
            "learning_cycles": self._learning_cycles,
        }


class ThreatClassifier:
    """Classifies detected anomalies and determines response."""

    # Anomaly type -> base severity
    SEVERITY_MAP = {
        "new_device": SEVERITY_MEDIUM,
        "network_change": SEVERITY_LOW,
        "population_spike": SEVERITY_HIGH,
        "auth_failure_spike": SEVERITY_HIGH,
        "rogue_ap": SEVERITY_CRITICAL,
        "unusual_dpi": SEVERITY_MEDIUM,
        "ips_alert": SEVERITY_HIGH,
        "threat_detected": SEVERITY_HIGH,
    }

    @classmethod
    def classify(cls, anomaly):
        """Classify an anomaly and return (severity, description, auto_respond)."""
        anomaly_type = anomaly.get("type", "unknown")
        base_severity = cls.SEVERITY_MAP.get(anomaly_type, SEVERITY_INFO)

        # Escalate new device with unknown OUI to HIGH
        if anomaly_type == "new_device" and anomaly.get("unknown_oui"):
            base_severity = SEVERITY_HIGH

        # Build description
        description = cls._describe(anomaly)

        # Auto-respond only on CRITICAL
        auto_respond = base_severity == SEVERITY_CRITICAL

        return base_severity, description, auto_respond

    @classmethod
    def _describe(cls, anomaly):
        """Generate human-readable description of anomaly."""
        atype = anomaly.get("type", "unknown")

        if atype == "new_device":
            oui_note = " (UNKNOWN MANUFACTURER)" if anomaly.get("unknown_oui") else ""
            return (f"New device joined network: {anomaly.get('hostname', 'unknown')} "
                    f"({anomaly.get('mac', '??:??:??')}) on {anomaly.get('network', 'unknown')}"
                    f"{oui_note}")

        elif atype == "network_change":
            return (f"Device {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"moved to network {anomaly.get('new_network', '?')}")

        elif atype == "population_spike":
            return (f"Client population spike: {anomaly.get('current_count', 0)} "
                    f"(average: {anomaly.get('average_count', 0)})")

        elif atype == "auth_failure_spike":
            return f"Authentication failure spike detected: {anomaly.get('count', 0)} failures"

        elif atype == "rogue_ap":
            return f"Rogue access point detected: {anomaly.get('ssid', 'unknown')} ({anomaly.get('bssid', '')})"

        return f"Anomaly detected: {json.dumps(anomaly)}"


class UniFiDefenseLoop:
    """Main defense loop — polls UniFi MCP, detects threats, responds."""

    def __init__(self, blackboard, voice, learning=None):
        self.unifi = UniFiMCPClient()
        self.blackboard = blackboard
        self.voice = voice
        self.learning = learning
        self.baseline = BehavioralBaseline()
        self.classifier = ThreatClassifier()
        self._thread = None
        self._running = False
        self._poll_count = 0

    def start(self):
        """Start the defense loop in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="unifi-defense")
        self._thread.start()
        logger.info("UniFi Network Defense loop started (30s interval)")

    def stop(self):
        """Stop the defense loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("UniFi Network Defense loop stopped")

    def _loop(self):
        """Main polling loop."""
        # Initial announcement
        self.voice.speak("WOPR defense grid online. Monitoring network perimeter.")

        while self._running:
            try:
                self._poll_cycle()
                self._poll_count += 1
            except Exception as e:
                logger.error(f"Defense loop error: {e}", exc_info=True)

            time.sleep(DEFENSE_POLL_INTERVAL)

    def _poll_cycle(self):
        """Single polling cycle."""
        # 1. Get threat summary
        threat_summary = self.unifi.get_threat_summary()
        if threat_summary and not threat_summary.get("error"):
            self._process_threat_summary(threat_summary)

        # 2. Get current client list and update baseline
        clients_result = self.unifi.get_clients()
        if clients_result and not clients_result.get("error"):
            clients = clients_result if isinstance(clients_result, list) else clients_result.get("result", [])
            anomalies = self.baseline.update_client_list(clients)
            for anomaly in anomalies:
                self._handle_anomaly(anomaly)

        # 3. Check alerts (every 5th cycle = ~2.5 min)
        if self._poll_count % 5 == 0:
            alerts = self.unifi.get_alerts(limit=10)
            if alerts and not alerts.get("error"):
                self._process_alerts(alerts)

        # 4. Log baseline summary periodically (every 20th cycle = ~10 min)
        if self._poll_count % 20 == 0 and self._poll_count > 0:
            summary = self.baseline.get_summary()
            logger.info(f"Baseline: {summary['total_known_clients']} clients, "
                        f"{summary['known_ouis']} OUIs, "
                        f"ready={summary['baseline_ready']}")

    def _process_threat_summary(self, summary):
        """Process threat summary from UniFi MCP."""
        # Extract threat indicators
        threats = summary if isinstance(summary, list) else summary.get("result", [])
        if isinstance(threats, dict):
            threats = [threats]

        for threat in threats:
            if not isinstance(threat, dict):
                continue
            # Check for active IPS threats, anomaly scores, etc.
            threat_score = threat.get("threat_score", threat.get("score", 0))
            if threat_score and int(threat_score) > 0:
                self._handle_anomaly({
                    "type": "threat_detected",
                    "details": threat,
                    "score": threat_score,
                })

    def _process_alerts(self, alerts_result):
        """Process recent UniFi alerts."""
        alerts = alerts_result if isinstance(alerts_result, list) else alerts_result.get("result", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            # Only process unhandled alerts
            if alert.get("handled") or alert.get("archived"):
                continue

            alert_type = alert.get("key", alert.get("type", "unknown"))
            if "auth" in alert_type.lower() and "fail" in alert_type.lower():
                self._handle_anomaly({
                    "type": "auth_failure_spike",
                    "count": alert.get("count", 1),
                    "details": alert,
                })

    def _handle_anomaly(self, anomaly):
        """Classify anomaly, take action, report."""
        severity, description, auto_respond = self.classifier.classify(anomaly)

        logger.warning(f"[{severity}] {description}")

        # CRITICAL: auto-respond (block + voice + Blackboard)
        if auto_respond and severity == SEVERITY_CRITICAL:
            mac = anomaly.get("mac", "")
            if mac:
                logger.warning(f"AUTO-BLOCK: {mac} — {description}")
                self.unifi.block_client(mac, reason=f"Auto-blocked by Joshua: {description}")
                description = f"[AUTO-BLOCKED] {description}"

        # CRITICAL/HIGH: voice alert
        if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            voice_msg = f"ALERT. {description}"
            self.voice.speak(voice_msg)

        # All severities: post to Blackboard
        self.blackboard.post_finding(
            title=f"Network Defense: {anomaly.get('type', 'anomaly')}",
            severity=severity,
            description=description,
            host=anomaly.get("mac", ""),
            evidence=json.dumps(anomaly, default=str),
        )

        # Capture training example for tactical category
        if self.learning and severity in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
            self.learning.capture_tool_interaction(
                tool_name="unifi_defense",
                tool_args={"poll_cycle": self._poll_count},
                tool_output=description,
                user_query=f"Network defense monitoring cycle {self._poll_count}",
                agent_analysis=f"[{severity}] {description}",
            )

    def is_running(self):
        """Check if the defense loop is active."""
        return self._running and self._thread and self._thread.is_alive()
