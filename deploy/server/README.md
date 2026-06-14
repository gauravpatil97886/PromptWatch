# PromptWatch Server — Admin / Security-Team Install

This is the **central** side: the collector (agents ship logs here) + the dashboard and
admin/compliance panel where the security team **sees monitoring of every machine**. Install
this on ONE server/VM/container. Employees never install this.

## Easy setup (Docker — recommended)

```bash
cd deploy/server
cp .env.example .env

# 1) generate a strong dashboard token and put it in .env
python3 -c "import secrets; print('PW_DASHBOARD_TOKEN=' + secrets.token_urlsafe(32))" >> .env

# 2) start it
docker compose up -d

# 3) grab the org enroll token to hand to employees (printed once on first boot)
docker compose logs pw | grep -i "enroll token"
```

Open the panel:

| URL | What |
|-----|------|
| `http://<server>:9100` | Dashboard (sign in with `PW_DASHBOARD_TOKEN`) — live activity, endpoints, threats, sessions, hunt |
| `http://<server>:9100/admin` | Admin & Compliance — agents, key rotate/revoke, settings, audit, violation register, erasure, CSV/SIEM export |
| `http://<server>:9090` | Collector (agents connect here; per-agent-key auth) |

> Put TLS (a reverse proxy: Caddy/Nginx/Traefik) in front of 9090 and 9100 for production.
> Keep agents on `https://` — the agent refuses to send credentials over plain HTTP by default.

## No-Docker setup

```bash
pipx install "promptwatch[server]"
export PW_DASHBOARD_TOKEN=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")
pw server          # prints the enroll token on first run
```

## Day-2 admin

| Task | How |
|------|-----|
| Show / rotate enroll token | `pw org-token` · `pw org-token --rotate`, or Admin → (rotate) |
| Revoke / rotate an agent key | Admin → Agents → Rotate / Revoke |
| Toggle security (redaction, HTTPS, retention, model allow/deny) | Admin → Settings (applied live, no restart) |
| Verify audit integrity | Admin → Audit (chain status) |
| Erase a person's data (GDPR Art. 17) | Admin → Settings → Right to erasure |
| Export for SIEM/audit | Admin → Compliance → CSV, or `/api/admin/export.csv` |

See [../../docs/operations.md](../../docs/operations.md) and [../../docs/security.md](../../docs/security.md).
