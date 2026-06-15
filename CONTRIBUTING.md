# Contributing to Promptward

Thanks for helping improve Promptward. This is a security tool, so correctness and privacy come first.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,server]"
pytest
ruff check . && mypy src
```

## Project layout

```
src/promptward/
├── common/   shared: config, crypto, security rules, redaction, compliance, storage
├── agent/    thin per-machine forwarder: forwarder, shipper, spool, enroll, service, notifier
├── server/   central: collector, dashboard, auth, prune, audit, reports
└── cli/       `pw` entry point
```

## Ground rules

- **Fail-open.** Nothing in the agent's request path may raise into a user's Claude call.
  Logging, shipping, and analysis are best-effort.
- **No secrets in logs.** Detection runs on raw text; storage/transmission must use redacted
  text. Never add a code path that persists an unredacted secret when `redact_secrets` is on.
- **Low false positives.** New detection rules should be specific and covered by tests in
  `tests/`. Prefer prefix/assignment-anchored patterns over broad ones.
- **Auth by default.** Any new network surface (dashboard route, collector endpoint) must be
  behind the existing auth (`server/auth.py`) unless explicitly public (health/login).

## Pull requests

1. Add/adjust tests; keep `pytest`, `ruff`, and `mypy` green.
2. Update `CHANGELOG.md` under "Unreleased".
3. Describe the security/privacy impact of the change in the PR.

## Reporting vulnerabilities

Please do **not** open a public issue for security vulnerabilities. Email the maintainers
(see `pyproject.toml`) with details and a reproduction.
