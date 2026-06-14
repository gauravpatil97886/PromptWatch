# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **PII/PHI/PCI redaction** (`common/compliance.redact`) wired into the agent forwarder, the
  CLI wrapper, and the collector (defense-in-depth) — SSNs, emails, phones, IBANs, and
  Luhn-validated cards (last-4 preserved) are masked before storage/transmission.
- **Agent↔server channel hardening**: `PW_REQUIRE_HTTPS` refuses to send the enroll token or
  agent key over plain HTTP (loopback exempt).
- **Key rotation**: agents can self-rotate (`POST /api/v1/rotate`); admins rotate/revoke from
  the panel (`/api/admin/agents/{id}/rotate|revoke`) and rotate the org enroll token.
- **Right to erasure** (GDPR Art. 17): `Store.delete_by_subject` + `/api/admin/erase` + admin UI.
- **Runtime security toggles**: redaction, HTTPS enforcement, retention, large-prompt threshold,
  model allow/deny, and consent banner are editable live in Admin → Settings (no restart).
- Collector ingest now offloads DB writes via `asyncio.to_thread` and binds stored identity to
  the authenticated agent record rather than the (spoofable) payload.
- Separate install surfaces: `deploy/agent/` (laptop) and `deploy/server/` (admin), each with a
  step-by-step README; shareable animated `docs/overview.html`; professional top-level README.

### Added (earlier)
- Package restructured into `common/`, `agent/`, `server/`, `cli/` with a `[server]` extra
  so the thin agent installs without server dependencies.
- `common/redact.py` — secret masking before storage/transmission (monitor-only posture).
- `agent/identity.py` — agent identity + per-agent collector credentials (env or `agent.json`).
- Dashboard access control (`server/auth.py`): shared token gate, `/login` cookie flow, and a
  refusal to bind beyond loopback without a token. Configurable bind host/port.
- SQLite WAL mode, indexes on `ts`/`device_name`/`alert_level`, `agent_id`/`received_at`
  columns, and retention pruning (`Store.prune`, `server/prune.py`, `pw prune`).
- `pw stats` now reports devices and alert counts.

### Changed
- Security rules tuned to cut false positives: removed the "non-local IP → MEDIUM" rule
  (flagged every request in agent/central mode) and the broad base64 credential rule; added
  specific provider key patterns. Exfiltration rules tightened to secret-adjacent verbs.
- Renamed entry point: `pw` (thin agent); `pw` remains the umbrella CLI.

### Security
- Removed the hardcoded shared agent key (`choicetrack-agent-key-2026`). The agent now refuses
  to ship events without an explicit per-agent key.

## [0.1.0]
- Initial proxy + CLI wrapper + encrypted SQLite + single-file dashboard.
