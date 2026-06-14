# Architecture

PromptWatch has two deployables that share one Python package (`promptwatch`):

| Component | Module(s) | Role |
|-----------|-----------|------|
| **Agent** (`pw`) | `agent/` | Thin per-machine forwarder. Sends traffic to Anthropic, ships log events to the collector, fails open. |
| **Server** (`pw server`) | `server/` | Central collector (ingest) + dashboard + admin/compliance UI. |
| **Common** | `common/` | Config, crypto, storage, security rules, redaction, compliance. |

## Request path (agent)

```
claude / VS Code / SDK
   │  ANTHROPIC_BASE_URL=http://127.0.0.1:9099
   ▼
agent/forwarder.py ──────────────►  api.anthropic.com     (streamed, unmodified)
   │ (after response, best-effort)
   ├─ security.analyze + compliance + redact
   ├─ common/storage.py  (local SQLite cache)
   └─ agent/shipper.py ─► collector /api/v1/sessions
          └─ on failure ─► agent/spool.py (disk) ─► drain_loop retries
```

The forward to Anthropic never depends on the collector. Logging is fire-and-forget.

## Server

```
agent ──HTTPS, X-Agent-Key──►  server/collector.py  (/api/v1/sessions, /enroll, /notifications)
                                     │ re-runs security + compliance centrally
                                     ▼
                               common/storage.py  (interactions)   + server/server_store.py (agents, settings, notifications)
team browser ──token──────────►  server/dashboard.py  +  server/admin.py  (/admin, /api/admin/*, /api/compliance)
                                     │ mutations ─► server/audit.py (hash-chained)
                                     └ exports ─► server/reports.py (CSV / SIEM / frameworks)
```

## Auth model

- **Agent → collector:** per-agent key (hashed at rest), issued at enrollment from the org enroll token.
- **Team → dashboard/admin:** shared dashboard token (Phase 0). Per-user RBAC is the next step.
- **Audit:** every admin mutation is appended to a SHA-256 hash-chained log; `verify()` detects tampering.

## Data model

`interactions` (prompts/responses, encrypted + redacted, alert level/reason, agent_id), `agents`,
`org` (enroll token hash), `notifications`, `settings` (runtime config), `audit_log`.
