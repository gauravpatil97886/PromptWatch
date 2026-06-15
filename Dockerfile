# Central Promptward server (collector + dashboard). SQLite by default; mount a volume
# at /data to persist. For Postgres, set PW_DB_URL (see docs/operations.md).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir ".[server]"

# Persist DB + keys here (Promptward writes under $HOME/.promptward).
ENV HOME=/data
VOLUME ["/data"]

# Collector (agents) + dashboard (team).
EXPOSE 9090 9100

# Bind both to all interfaces inside the container; the dashboard still refuses
# to start without PW_DASHBOARD_TOKEN when exposed.
ENV PW_COLLECTOR_HOST=0.0.0.0 \
    PW_DASHBOARD_HOST=0.0.0.0

CMD ["pw", "server"]
