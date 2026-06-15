# Security & Privacy

## Posture

Promptward is **monitor-only and fail-open**. It never blocks a Claude request and never breaks
Claude if the collector is down. It is a visibility/audit layer, not an enforcement gateway —
a determined user with their own API key can bypass it. Be honest about this with stakeholders.

## Threat model (what Promptward defends)

| Goal | Mechanism |
|------|-----------|
| No admin visibility for individual-account orgs | Network-path agent + central collector + dashboard |
| Secrets leaking into prompts | `security.py` detection + `redact.py` masking before store/ship |
| Sensitive data (PII/PHI/PCI) in prompts | `compliance.py` detectors (Luhn-validated cards, SSN, etc.) |
| Off-policy usage | AUP policy packs + model governance |
| Tampered audit history | `audit.py` SHA-256 hash chain + `verify()` |
| Unauthorized dashboard access | Token gate; refuses non-loopback bind without a token |
| Unauthorized ingest | Per-agent keys, hashed at rest; revocation enforced |

## Data handling

- **At rest:** prompts/responses encrypted with Fernet (AES-128-CBC + HMAC) when `PW_ENCRYPT_LOGS=true`.
- **Redaction:** detected secrets are masked **before** local storage and before transmission, so the
  collector and DB never receive raw secrets (when `PW_REDACT_SECRETS=true`).
- **In transit:** put the collector and dashboard behind TLS (reverse proxy) for org deployments.
- **Retention:** `PW_RETENTION_DAYS` + `pw prune` (or the server's 6-hourly auto-prune) delete old rows.

## Consent & compliance

Monitoring AI usage may carry legal/works-council obligations. The agent installer prints an
AI-monitoring notice; configure the dashboard consent banner under Admin → Settings. Promptward maps its
controls to EU AI Act, NIST AI RMF, ISO/IEC 42001, SOC 2, and GDPR (see Admin → Compliance).

## Hardening checklist for org deployment

- [ ] Set a strong `PW_DASHBOARD_TOKEN`; never expose the dashboard without it.
- [ ] Terminate TLS in front of ports 9090 (collector) and 9100 (dashboard).
- [ ] Keep `PW_ENCRYPT_LOGS=true` and `PW_REDACT_SECRETS=true`.
- [ ] Set `PW_RETENTION_DAYS` to your policy.
- [ ] Rotate the org enroll token (`pw org-token --rotate`) after onboarding.
- [ ] Restrict who holds the dashboard token; plan for RBAC (roadmap).

## Reporting vulnerabilities

Email the maintainers (see `pyproject.toml`). Please do not open public issues for vulnerabilities.
