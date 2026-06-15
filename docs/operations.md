# Operations Runbook

## Org server

```bash
cd deploy/server
cp .env.example .env          # set PW_DASHBOARD_TOKEN (required)
docker compose up -d
docker compose logs pw | grep -i "enroll token"   # hand to employees
```

No Docker:
```bash
pipx install "promptward[server]"
PW_DASHBOARD_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))") pw server
```

- Dashboard → `http://<host>:9100` (sign in with the token)
- Admin/Compliance → `http://<host>:9100/admin`
- Collector (agents) → `http://<host>:9090`

## Employee agent

```bash
curl -fsSL https://<server>/install-agent.sh | \
  PW_SERVER=https://pw.corp PW_ENROLL_TOKEN=xxxxx bash
# or manually:
pipx install promptward
pw enroll --server https://pw.corp --token xxxxx
systemctl --user enable --now pw.service   # Linux
```

Use `claude-tracked` in place of `claude` (the wrapper fails open if the agent is down).

## Admin tasks

| Task | Command / UI |
|------|--------------|
| Show/rotate enroll token | `pw org-token` / `pw org-token --rotate` |
| List agents | `pw agents` or Admin → Agents |
| Revoke an agent | Admin → Agents → Revoke |
| Change detection/retention | Admin → Settings |
| Verify audit integrity | Admin → Audit (chain status shown) |
| Export for SIEM/audit | `GET /api/admin/export.csv` or Admin → Compliance |
| Prune old data | `pw prune` (auto every 6h on the server) |
| Usage stats | `pw stats` |

## Postgres (org scale)

SQLite (default) suits a single collector process. For horizontal scale, set `PW_DB_URL`
to a Postgres DSN once the asyncpg backend lands (tracked as a follow-up); both collector and
dashboard then point at the same database.

## Backups

Back up the server's data volume (`/data` in the container, `~/.promptward` otherwise):
`interactions.db*`, `.secret.key` (without it, encrypted rows are unrecoverable), and the
audit log live there.
