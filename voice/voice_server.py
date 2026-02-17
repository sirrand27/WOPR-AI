"""Piper TTS Voice Server — TCP socket interface.

Drop-in replacement for F5-TTS Joshua voice server.
Matches the TCP socket protocol expected by wopr/voice.py:
  - Client connects to LISTEN_HOST:LISTEN_PORT
  - Sends UTF-8 text terminated by newline
  - Server synthesizes speech and sends back WAV audio bytes
  - Server sends 4-byte big-endian length prefix, then WAV data

Lightweight: ~200MB RAM, CPU-only (no GPU required).
"""

import io
import os
import socket
import struct
import subprocess
import tempfile
import threading

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9876"))
PIPER_VOICE = os.environ.get("PIPER_VOICE", "en_US-lessac-medium")
PIPER_DATA_DIR = os.environ.get("PIPER_DATA_DIR", "/data/voice")


def download_voice():
    """Ensure piper voice model is available."""
    model_path = os.path.join(PIPER_DATA_DIR, f"{PIPER_VOICE}.onnx")
    if os.path.exists(model_path):
        print(f"[VOICE] Model already downloaded: {PIPER_VOICE}")
        return model_path

    print(f"[VOICE] Downloading voice model: {PIPER_VOICE}...")
    os.makedirs(PIPER_DATA_DIR, exist_ok=True)

    try:
        result = subprocess.run(
            ["piper", "--download-dir", PIPER_DATA_DIR,
             "--model", PIPER_VOICE, "--update-voices",
             "--output_file", "/dev/null"],
            input="test",
            capture_output=True,
            text=True,
            timeout=120,
        )
        if os.path.exists(model_path):
            print(f"[VOICE] Model downloaded: {model_path}")
            return model_path
        else:
            print(f"[VOICE] Download may have succeeded, checking...")
    except Exception as e:
        print(f"[VOICE] Download error: {e}")

    return model_path


def synthesize(text, model_path):
    """Synthesize text to WAV bytes using piper CLI."""
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["piper", "--model", model_path, "--output_file", tmp_path],
            input=text,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            print(f"[VOICE] Piper error: {result.stderr}")
            return None

        with open(tmp_path, "rb") as f:
            wav_data = f.read()

        return wav_data
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def handle_client(conn, addr, model_path):
    """Handle a single TTS client connection."""
    try:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        text = data.split(b"\n")[0].decode("utf-8", errors="replace").strip()
        if not text:
            return

        print(f"[VOICE] Synthesizing for {addr}: {text[:80]}...")

        wav_data = synthesize(text, model_path)
        if wav_data:
            # Send length-prefixed WAV data
            conn.sendall(struct.pack(">I", len(wav_data)))
            conn.sendall(wav_data)
            print(f"[VOICE] Sent {len(wav_data)} bytes to {addr}")
        else:
            # Send zero-length to indicate error
            conn.sendall(struct.pack(">I", 0))
            print(f"[VOICE] Synthesis failed for {addr}")

    except Exception as e:
        print(f"[VOICE] Client error {addr}: {e}")
    finally:
        conn.close()


def main():
    model_path = download_voice()
    print(f"[VOICE] Piper TTS server starting on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[VOICE] Model: {PIPER_VOICE}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)

    print(f"[VOICE] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, model_path))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    main()
