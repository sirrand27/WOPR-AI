"""UniFi Controller API client for UDM Pro.

Handles authentication, session management, CSRF tokens, and all API calls.
WOPR-exclusive — not shared with TARS Dev.
"""

import json
import logging
import os
import threading
import time
from typing import Optional

import requests
import urllib3

# Suppress self-signed cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("unifi_mcp.client")

# Configuration via environment variables
UNIFI_HOST = os.environ.get("UNIFI_HOST", "192.168.1.1")
UNIFI_PORT = int(os.environ.get("UNIFI_PORT", "443"))
UNIFI_USER = os.environ.get("UNIFI_USER", "")
UNIFI_PASS = os.environ.get("UNIFI_PASS", "")
UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")
UNIFI_VERIFY_SSL = os.environ.get("UNIFI_VERIFY_SSL", "0") == "1"


class UniFiClient:
    """Thread-safe UniFi Controller API client."""

    def __init__(self, host: str = UNIFI_HOST, port: int = UNIFI_PORT,
                 username: str = UNIFI_USER, password: str = UNIFI_PASS,
                 site: str = UNIFI_SITE, verify_ssl: bool = UNIFI_VERIFY_SSL):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._site = site
        self._verify = verify_ssl
        self._base = f"https://{host}:{port}"
        self._api_base = f"{self._base}/proxy/network/api/s/{site}"
        self._session: Optional[requests.Session] = None
        self._csrf_token: Optional[str] = None
        self._lock = threading.Lock()
        self._authenticated = False
        self._last_auth: float = 0
        self._auth_ttl: float = 3500  # re-auth before 1h expiry

    @property
    def is_configured(self) -> bool:
        return bool(self._username and self._password)

    @property
    def is_authenticated(self) -> bool:
        if not self._authenticated:
            return False
        if time.time() - self._last_auth > self._auth_ttl:
            return False
        return True

    def login(self) -> bool:
        """Authenticate to UniFi Controller."""
        with self._lock:
            return self._login_unlocked()

    def _login_unlocked(self) -> bool:
        if not self.is_configured:
            log.error("UniFi credentials not configured (set UNIFI_USER / UNIFI_PASS)")
            return False

        self._session = requests.Session()
        self._session.verify = self._verify

        try:
            resp = self._session.post(
                f"{self._base}/api/auth/login",
                json={"username": self._username, "password": self._password},
                timeout=10,
            )

            if resp.status_code == 200:
                # Extract CSRF token from response headers or cookies
                self._csrf_token = resp.headers.get("X-CSRF-Token", "")
                if not self._csrf_token:
                    for cookie in self._session.cookies:
                        if cookie.name.lower() in ("csrf_token", "x-csrf-token", "TOKEN"):
                            self._csrf_token = cookie.value
                            break

                if self._csrf_token:
                    self._session.headers.update({"X-CSRF-Token": self._csrf_token})

                self._authenticated = True
                self._last_auth = time.time()
                log.info("Authenticated to UniFi Controller at %s", self._host)
                return True
            else:
                log.error("Login failed: %d %s", resp.status_code, resp.text[:200])
                return False

        except requests.RequestException as e:
            log.error("Login connection error: %s", e)
            return False

    def _ensure_auth(self) -> bool:
        """Ensure we have a valid session, re-authenticating if needed."""
        if self.is_authenticated:
            return True
        return self._login_unlocked()

    def _get(self, endpoint: str, params: dict = None) -> dict:
        """GET request to API endpoint. Returns parsed JSON."""
        with self._lock:
            if not self._ensure_auth():
                return {"error": "Not authenticated"}

            url = f"{self._api_base}/{endpoint}"
            try:
                resp = self._session.get(url, params=params, timeout=15)

                if resp.status_code == 401:
                    # Session expired, retry
                    log.warning("Session expired, re-authenticating...")
                    if self._login_unlocked():
                        resp = self._session.get(url, params=params, timeout=15)
                    else:
                        return {"error": "Re-authentication failed"}

                if resp.status_code == 200:
                    return resp.json()
                else:
                    return {"error": f"HTTP {resp.status_code}", "body": resp.text[:500]}

            except requests.RequestException as e:
                log.error("GET %s failed: %s", endpoint, e)
                return {"error": str(e)}

    def _post(self, endpoint: str, data: dict = None) -> dict:
        """POST request to API endpoint."""
        with self._lock:
            if not self._ensure_auth():
                return {"error": "Not authenticated"}

            url = f"{self._api_base}/{endpoint}"
            try:
                resp = self._session.post(url, json=data or {}, timeout=15)

                if resp.status_code == 401:
                    log.warning("Session expired, re-authenticating...")
                    if self._login_unlocked():
                        resp = self._session.post(url, json=data or {}, timeout=15)
                    else:
                        return {"error": "Re-authentication failed"}

                if resp.status_code in (200, 201):
                    return resp.json()
                else:
                    return {"error": f"HTTP {resp.status_code}", "body": resp.text[:500]}

            except requests.RequestException as e:
                log.error("POST %s failed: %s", endpoint, e)
                return {"error": str(e)}

    def logout(self):
        """Logout and clear session."""
        with self._lock:
            if self._session:
                try:
                    self._session.post(f"{self._base}/api/auth/logout", timeout=5)
                except Exception:
                    pass
                self._session.close()
            self._authenticated = False
            self._csrf_token = None

    # ── Client Operations ──────────────────────────────────────────

    def get_clients(self) -> list[dict]:
        """Get all active (connected) clients."""
        result = self._get("stat/sta")
        return result.get("data", []) if "data" in result else []

    def get_all_clients(self) -> list[dict]:
        """Get all known clients (including offline)."""
        result = self._get("rest/user")
        return result.get("data", []) if "data" in result else []

    def get_client(self, mac: str) -> dict:
        """Get specific client by MAC."""
        mac = mac.lower().replace("-", ":")
        result = self._get(f"stat/sta/{mac}")
        data = result.get("data", [])
        return data[0] if data else result

    # ── IDS/IPS Alerts ─────────────────────────────────────────────

    def get_alerts(self, limit: int = 50) -> list[dict]:
        """Get IDS/IPS alerts."""
        result = self._get("stat/alarm")
        data = result.get("data", [])
        return data[:limit]

    def get_ips_events(self) -> list[dict]:
        """Get IPS events (threats blocked)."""
        result = self._get("stat/ips/event")
        return result.get("data", []) if "data" in result else []

    # ── Events ─────────────────────────────────────────────────────

    def get_events(self, limit: int = 50) -> list[dict]:
        """Get system events."""
        result = self._get("stat/event")
        data = result.get("data", [])
        return data[:limit]

    # ── DPI ────────────────────────────────────────────────────────

    def get_dpi_site(self) -> list[dict]:
        """Get site-wide DPI stats."""
        result = self._post("stat/sitedpi", {"type": "by_app"})
        return result.get("data", []) if "data" in result else []

    def get_dpi_client(self, mac: str) -> list[dict]:
        """Get DPI stats for a specific client."""
        mac = mac.lower().replace("-", ":")
        result = self._post("stat/stadpi", {"type": "by_app", "macs": [mac]})
        return result.get("data", []) if "data" in result else []

    # ── Devices ────────────────────────────────────────────────────

    def get_devices(self) -> list[dict]:
        """Get all UniFi network devices (APs, switches, gateway)."""
        result = self._get("stat/device")
        return result.get("data", []) if "data" in result else []

    # ── Client Actions ─────────────────────────────────────────────

    def block_client(self, mac: str) -> dict:
        """Block a client by MAC address."""
        mac = mac.lower().replace("-", ":")
        return self._post("cmd/stamgr", {"cmd": "block-sta", "mac": mac})

    def unblock_client(self, mac: str) -> dict:
        """Unblock a client by MAC address."""
        mac = mac.lower().replace("-", ":")
        return self._post("cmd/stamgr", {"cmd": "unblock-sta", "mac": mac})

    def reconnect_client(self, mac: str) -> dict:
        """Force a client to reconnect."""
        mac = mac.lower().replace("-", ":")
        return self._post("cmd/stamgr", {"cmd": "kick-sta", "mac": mac})

    # ── Firewall ───────────────────────────────────────────────────

    def get_firewall_rules(self) -> list[dict]:
        """Get all firewall rules."""
        result = self._get("rest/firewallrule")
        return result.get("data", []) if "data" in result else []

    def create_firewall_rule(self, rule: dict) -> dict:
        """Create a new firewall rule."""
        return self._post("rest/firewallrule", rule)

    # ── Network Health ─────────────────────────────────────────────

    def get_health(self) -> list[dict]:
        """Get network health metrics."""
        result = self._get("stat/health")
        return result.get("data", []) if "data" in result else []

    def get_sysinfo(self) -> dict:
        """Get controller system info."""
        result = self._get("stat/sysinfo")
        return result.get("data", [{}])[0] if "data" in result else result


# Singleton
_client: Optional[UniFiClient] = None
_client_lock = threading.Lock()


def get_unifi_client() -> UniFiClient:
    global _client
    with _client_lock:
        if _client is None:
            _client = UniFiClient()
        return _client
