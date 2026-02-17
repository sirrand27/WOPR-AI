# Piper TTS Voice Server — Jetson ARM64
# Lightweight CPU-based TTS (~200MB) replacing F5-TTS (~8.8GB GPU)
# Exposes same TCP socket interface on port 9876
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install piper-tts and audio deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir \
    piper-tts \
    numpy \
    soundfile

# Create data directory for voice models
RUN mkdir -p /data/voice

# Voice server wrapper — TCP socket compatible with existing voice.py client
COPY voice_server.py /app/voice_server.py

EXPOSE 9876

CMD ["python", "voice_server.py"]
