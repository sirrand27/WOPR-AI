# WOPR Sentry Agent — Jetson ARM64
# Note: Core agent uses stdlib only (no pip deps)
FROM python:3.11-slim-bookworm

WORKDIR /app

# Create data directories
RUN mkdir -p /data/wopr/training_data /data/logs

# Agent source — will be populated from Kali SCP
COPY agent.py /app/agent.py
COPY config.py /app/config.py
COPY device_db.py /app/device_db.py
COPY miner_monitor.py /app/miner_monitor.py
COPY unifi_defense.py /app/unifi_defense.py
COPY tools.py /app/tools.py
COPY voice.py /app/voice.py
COPY learning.py /app/learning.py
COPY memory.py /app/memory.py
COPY blackboard.py /app/blackboard.py
COPY blackboard_monitor.py /app/blackboard_monitor.py
COPY __init__.py /app/__init__.py

CMD ["python", "agent.py"]
