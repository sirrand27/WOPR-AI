"""
Local Joshua AI Agent — Voice Client
TCP socket client for Joshua voice server (F5-TTS) on port 9876.
"""

import socket
import logging

from config import VOICE_HOST, VOICE_PORT, VOICE_ENABLED, SPEAK_THRESHOLD

logger = logging.getLogger(__name__)

# Pronunciation substitutions for F5-TTS (case-insensitive replacements)
_PRONUNCIATION_MAP = {
    "WOPR": "Whopper",
    "W.O.P.R.": "Whopper",
    "W.O.P.R": "Whopper",
    "wopr": "Whopper",
    "OSINT": "oh-sint",
    "MCP": "M C P",
    "DEFCON": "def-con",
}


def _fix_pronunciation(text):
    """Apply pronunciation substitutions for TTS clarity."""
    for token, replacement in _PRONUNCIATION_MAP.items():
        text = text.replace(token, replacement)
    return text


class VoiceClient:
    """TCP client for Joshua F5-TTS voice server."""

    def __init__(self, host=None, port=None):
        self.host = host or VOICE_HOST
        self.port = port or VOICE_PORT
        self.enabled = VOICE_ENABLED

    def speak(self, text):
        """Send text to voice server for TTS synthesis and playback."""
        if not self.enabled:
            return False

        if len(text) < SPEAK_THRESHOLD:
            logger.debug(f"Text too short for voice ({len(text)} chars), skipping")
            return False

        # Trim to first 500 chars for voice — long responses get truncated
        voice_text = text[:500].strip()
        if len(text) > 500:
            voice_text += "..."

        # Apply pronunciation fixes
        voice_text = _fix_pronunciation(voice_text)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.host, self.port))
            sock.sendall((voice_text + "\n").encode("utf-8"))

            # Wait for OK response
            response = sock.recv(1024).decode("utf-8").strip()
            sock.close()

            if response.startswith("OK"):
                logger.info(f"Voice spoke {len(voice_text)} chars")
                return True
            else:
                logger.warning(f"Voice server responded: {response}")
                return False

        except ConnectionRefusedError:
            logger.warning("Voice server not available (connection refused)")
            self.enabled = False  # Disable until next check
            return False
        except socket.timeout:
            logger.warning("Voice server timed out")
            return False
        except Exception as e:
            logger.error(f"Voice error: {e}")
            return False

    def check_available(self):
        """Check if voice server is reachable (respects VOICE_ENABLED config)."""
        if not VOICE_ENABLED:
            self.enabled = False
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))
            sock.close()
            self.enabled = True
            return True
        except Exception:
            self.enabled = False
            return False
