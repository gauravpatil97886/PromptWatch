# PromptWatch (PromptWatch)
## AI Agent Security Monitor — Architecture & Operations Guide

> Share this file with your security team. It covers system design, deployment, threat detection logic, and operational runbooks.

---

## What This System Does

PromptWatch is a **transparent HTTPS proxy** that sits between any Claude-powered tool (Claude Code CLI, VS Code Extension, SDK applications) and Anthropic's API. Every request passes through it unmodified — but PromptWatch logs the interaction, analyzes it for security threats, and surfaces findings in a real-time dashboard.

```
Employee machine                    PromptWatch Proxy               Anthropic API
─────────────────      ─────────────────────────────      ──────────────
Claude Code CLI   ──►  Intercepts request            ──►  api.anthropic.com
VS Code Extension ──►  Logs: device, user, OS        ◄──  Streams response back
SDK / curl        ──►  Runs security analysis        ──►  (unmodified)
                       Writes to DB
                       Dashboard updates live
```

**Zero latency impact** — the proxy streams responses through immediately. Logging happens asynchronously after the response is delivered.

---

## System Architecture

```
promptwatch/
├── src/promptwatch/
│   ├── proxy.py        — FastAPI transparent HTTPS proxy (port 9099)
│   ├── dashboard.py    — Web dashboard FastAPI app (port 9100)
│   ├── storage.py      — SQLite persistence layer with migrations
│   ├── security.py     — Rule-based threat detection engine
│   ├── config.py       — Pydantic settings + machine identity capture
│   ├── crypto.py       — Fernet AES-128 encryption for stored data
│   ├── cli_wrapper.py  — Thin wrapper for `claude --print` CLI calls
│   └── main.py         — CLI entry point (pw command)
├── scripts/
│   └── install.sh      — One-shot install script
└── CLAUDE.md           — This file
```

### Data Flow

```
1. Employee runs: export ANTHROPIC_BASE_URL=http://<proxy>:9099
2. Claude tool makes API call → hits PromptWatch proxy
3. Proxy captures: device_name, hostname, sys_user, os_info, client_ip, user_agent
4. Proxy forwards request to api.anthropic.com (streaming preserved)
5. Response streamed back to client immediately
6. After stream ends: SSE events parsed → text extracted → security.analyze() called
7. Result stored in SQLite with alert_level + alert_reason
8. Dashboard polls /api/logs every 5s → shows new entries with toast notifications
```

---

## Deployment Modes

### Mode 1 — Per-machine (current, development)
Each developer runs their own proxy locally.
```bash
# On each machine:
pw proxy &
export ANTHROPIC_BASE_URL=http://127.0.0.1:9099
```
- Dashboard shows only that machine's data
- Good for: individual monitoring, testing

### Mode 2 — Central proxy (recommended for 300+ employees)
One proxy on a central server. All employees point to it.
```bash
# On central server (e.g. 192.168.1.50):
PW_PROXY_HOST=0.0.0.0 pw proxy &
pw dashboard --no-browser &

# On each employee machine:
export ANTHROPIC_BASE_URL=http://192.168.1.50:9099
export PW_DEVICE_NAME=john-macbook-pro   # optional: friendly name
```
- All 300 employees appear in one dashboard
- Security team watches a single screen
- Requires: firewall rule to allow port 9099 inbound on central server

### Mode 3 — VS Code Extension tracking ✅
The VS Code Claude extension **is automatically tracked** when the proxy is running.
```bash
# Start proxy first
pw proxy &
export ANTHROPIC_BASE_URL=http://127.0.0.1:9099

# Then open VS Code from the same terminal
code .
```
All Claude sidebar requests appear in the dashboard with `source: proxy`.

---

## Security Detection Rules

File: `src/promptwatch/security.py`

| Alert Level | Trigger | MITRE ATLAS |
|-------------|---------|-------------|
| **HIGH (3)** | Credential patterns in prompt (password=, api_key=, private key) | AML.T0056 |
| **HIGH (3)** | Request from non-local IP (indicates lateral movement) | AML.T0002 |
| **MEDIUM (2)** | Prompt injection patterns (ignore instructions, jailbreak, DAN) | AML.T0051 |
| **MEDIUM (2)** | Data exfiltration keywords (send password, dump database) | AML.T0048 |
| **LOW (1)** | Very large prompt > 60,000 tokens | AML.T0043 |

### Adding Custom Rules
Edit `security.py` — add patterns to `_INJECTION`, `_CREDENTIALS`, or `_EXFILTRATION` lists:
```python
_INJECTION = [
    r"your new custom pattern here",
    ...
]
```

### Risk Score Formula (per endpoint)
```
risk_score = min(100, alerts_high × 35 + alerts_medium × 15 + alerts_low × 5)
```
- 0–19: Clean (green)
- 20–49: Low risk (yellow)
- 50–79: High risk (orange)
- 80–100: Critical (red)

---

## Dashboard Features

**URL:** `http://<server>:9100`

| Tab | What you see |
|-----|-------------|
| Overview | Live stats, 24h activity chart, threat severity donut, model usage, 7-day heatmap, live session feed. Toast notifications on new alerts. |
| Endpoints | All machines — device name, OS, user, risk score, session count, last seen. Click to drill into that machine's sessions. |
| Threats | All flagged interactions with MITRE ATLAS tags, filterable by severity. |
| Sessions | Full activity log — what each user actually typed (system context stripped), response, tokens. |
| Threat Hunt | Free-text search across all prompts and responses. Highlights match in context. |

---

## Data Storage

### SQLite Schema (`~/.promptwatch/interactions.db`)
```sql
CREATE TABLE interactions (
    id           INTEGER PRIMARY KEY,
    ts           TEXT,          -- UTC ISO timestamp
    source       TEXT,          -- 'proxy' | 'cli'
    model        TEXT,          -- e.g. claude-sonnet-4-6
    prompt       TEXT,          -- full message array (encrypted if PW_ENCRYPT_LOGS=true)
    response     TEXT,          -- full response text (encrypted)
    tokens_in    INTEGER,
    tokens_out   INTEGER,
    encrypted    INTEGER,
    device_name  TEXT,          -- PW_DEVICE_NAME or hostname
    hostname     TEXT,          -- socket.gethostname()
    sys_user     TEXT,          -- getpass.getuser()
    os_info      TEXT,          -- platform.system() + release
    client_ip    TEXT,          -- connecting IP
    user_agent   TEXT,          -- Claude Code / SDK user-agent
    alert_level  INTEGER,       -- 0=clean 1=low 2=med 3=high
    alert_reason TEXT           -- human-readable finding
);
```

### Encryption
When `PW_ENCRYPT_LOGS=true` (default), prompt and response are encrypted with **Fernet (AES-128-CBC + HMAC-SHA256)**.
Key stored at: `~/.promptwatch/.secret.key` (mode 0600, owner-read only).

**To migrate to PostgreSQL** (recommended for org-wide deployment):
1. Change `storage.py` to use `asyncpg` instead of `sqlite3`
2. Set `PW_DB_URL=postgresql://user:pass@host/db`
3. All 300 endpoints write to one central DB

---

## Configuration

All settings use `PW_` prefix in environment or `~/.promptwatch/.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `PW_PROXY_HOST` | `127.0.0.1` | Proxy listen address. Use `0.0.0.0` for org-wide |
| `PW_PROXY_PORT` | `9099` | Proxy port |
| `PW_UPSTREAM_BASE_URL` | `https://api.anthropic.com` | Anthropic API endpoint |
| `PW_ENCRYPT_LOGS` | `true` | Encrypt stored prompts/responses |
| `PW_DEVICE_NAME` | (auto from hostname) | Override device identifier |
| `PW_ORG_NAME` | `Organization` | Shown in dashboard header |
| `PW_CLAUDE_CLI_CMD` | `claude` | Path to Claude CLI binary |

---

## Operations Runbook

### Start everything
```bash
pw proxy &           # starts proxy on :9099
pw dashboard &       # starts dashboard on :9100
```

### Check status
```bash
pw stats             # session counts + token totals
pw logs -n 20        # last 20 interactions
ss -tlnp | grep 909   # verify ports are listening
```

### View recent interactions
```bash
pw logs --json | python3 -m json.tool | head -100
```

### Stop everything
```bash
pkill -f "pw proxy"
pkill -f "pw dashboard"
```

### Run as systemd service (auto-start on boot)
The agent installs its own user service during enrollment:
```bash
pw enroll --server https://pw.example.com --token <ORG_ENROLL_TOKEN>
# then:
systemctl --user enable --now pw.service
systemctl --user status pw.service
```
(Note: the legacy `scripts/install.sh` does not create units; service install is
handled by `pw enroll` / `pw service install`.)

---

## Important: ANTHROPIC_BASE_URL Warning

**DO NOT** add `ANTHROPIC_BASE_URL` to `.bashrc` or any permanent shell config.

If the proxy stops and the env var is set, all Claude tools will fail silently.

**Correct usage:**
```bash
# In a terminal session only:
pw proxy &
export ANTHROPIC_BASE_URL=http://127.0.0.1:9099
# Now use Claude in this terminal
```

**For org deployment:** Use a wrapper script or shell function that sets and unsets it:
```bash
# ~/.local/bin/claude-tracked
#!/bin/bash
export ANTHROPIC_BASE_URL=http://192.168.1.50:9099
exec claude "$@"
```

---

## VS Code Extension Tracking

When the proxy is running and `ANTHROPIC_BASE_URL` is set:
- **Claude Code terminal** (`claude` CLI) — tracked ✅
- **VS Code Claude extension** (sidebar chat) — tracked ✅ (open VS Code from same terminal)
- **Claude SDK apps** — tracked ✅ (any app using `ANTHROPIC_BASE_URL`)
- **Browser claude.ai** — NOT tracked (direct to Anthropic, not via SDK)

The `user_agent` column identifies the source:
- `claude-code/2.x.x (linux; x64)` → Claude Code CLI or VS Code extension

---

## Roadmap

- [ ] PostgreSQL backend for central org deployment
- [ ] Webhook / Slack alerts on HIGH severity
- [ ] Rate limiting detection (>10 req/min from one device)
- [ ] RBAC on dashboard (admin vs read-only)
- [ ] Export to CSV / SIEM integration
- [ ] Auto-block HIGH alerts (proxy returns 403)
- [ ] React/Next.js separate frontend codebase
