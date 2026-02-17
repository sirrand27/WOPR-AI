# Blackboard MCP Server — Jetson ARM64
FROM python:3.11-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    aiosqlite \
    httpx \
    pydantic

# Install MCP SDK (required by server.py)
RUN pip install --no-cache-dir mcp

# Server source + dependencies
COPY server.py /app/server.py
COPY database.py /app/database.py
COPY training.py /app/training.py
COPY pwa/ /app/pwa/

EXPOSE 9700

CMD ["python", "server.py"]
