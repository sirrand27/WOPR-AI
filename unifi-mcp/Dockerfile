# UniFi MCP Server — Jetson ARM64
FROM python:3.11-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir \
    httpx \
    requests \
    aiohttp \
    fastapi \
    uvicorn[standard]

# Install MCP SDK (required by server.py)
RUN pip install --no-cache-dir mcp

# Server source + dependencies
COPY server.py /app/server.py
COPY unifi_client.py /app/unifi_client.py
COPY syslog_listener.py /app/syslog_listener.py
COPY models.py /app/models.py

EXPOSE 9600

CMD ["python", "server.py"]
