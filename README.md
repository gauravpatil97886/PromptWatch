<div align="center">

# 🛡️ PromptWatch

### Self-hosted monitoring, audit & AI-governance for teams on individual Claude accounts

*Know who is using Claude, on what, with what data — and prove it to your auditors.*

[Quick start](#-quick-start) · [What it solves](#-the-problem) · [How it works](#-how-it-works) ·
[Security levels](#-security-by-layer) · [AI compliance](#-ai-compliance--governance) · [Install](#-installation)

</div>

---

## ❓ The problem

Anthropic's admin console, usage logs, and member management exist **only for Claude Team /
Enterprise** plans. A huge number of organizations run on **individual Claude / Claude Code
accounts** — every employee signs in with their own personal account and API key. Those orgs have:

- ❌ **No admin visibility** — who is using Claude, and for what?
- ❌ **No usage monitoring** — tokens, models, volume, by person/team.
- ❌ **No AI audit trail** — nothing to show a security review or regulator.
- ❌ **No DLP** — secrets, source code, customer PII pasted into prompts, unnoticed.

**PromptWatch is that missing layer.** It sits on the network path between any Claude tool and
Anthropic's API — so it works no matter which individual account an employee uses — and gives
the IT/security/compliance team one dashboard + admin panel to run it. No Anthropic Enterprise
plan required.

## ✅ What we built (and how it solves it)

| You need | PromptWatch gives you | How |
|----------|---------------|-----|
| See all AI usage | Live dashboard: activity, endpoints, models, tokens, sessions | Thin agent → central collector → dashboard |
| Catch risky prompts | Threat detection: injection, secrets, exfiltration | `common/security.py` rule engine, server-enforced |
| Stop data leaks | Secret + PII/PHI/PCI **redaction before storage** | `redact.py` + `compliance.py`, masked at the agent *and* the collector |
| Prove compliance | Tamper-evident audit log + violation register + framework mapping | `audit.py` hash chain, `reports.py` |
| Run it safely | Per-agent keys, dashboard token, HTTPS-only credentials, retention | `auth.py`, `identity.require_secure`, `prune.py` |
| Never break Claude | **Fail-open** — agent forwards to Anthropic regardless of PromptWatch | independent forward path + disk spool |

## 🧭 How it works

```
 EMPLOYEE LAPTOP                                   CENTRAL SERVER (one box)
 ───────────────                                   ────────────────────────
 claude / VS Code / SDK
   │ ANTHROPIC_BASE_URL → 127.0.0.1:9099
   ▼
 ┌─────────────────────┐   forwards directly    ┌──────────────────┐
 │  pw (thin)   │ ─────────────────────► │  api.anthropic   │
 │  • redact secrets+PII│                        │     .com         │
 │  • detect threats    │   event (HTTPS,        └──────────────────┘
 │  • fail-open + spool │   per-agent key)
 └─────────┬───────────┘ ───────────────►  ┌───────────────────────────────┐
           └ Claude keeps working even      │  pw server                    │
             if the server is down          │  • collector (ingest, auth)    │
                                            │  • re-analyze (security+compl.)│
                                            │  • encrypted store + retention │
                                            │  • dashboard + /admin panel    │
                                            │  • hash-chained audit log      │
                                            └───────────────────────────────┘
                                                team browser ─token─► dashboard
```

**Key property:** the forward to Anthropic never depends on the server. If the collector or
network is down, the user's Claude call still succeeds and the log event spools to disk and
replays later. PromptWatch can never break Claude.

## 🔐 Security by layer

| Layer | Control |
|-------|---------|
| **Employee → Anthropic** | Agent forwards unmodified, streams with zero added latency; never logs the user's API key |
| **On the machine** | Secrets + PII masked **before** anything is stored or sent; local DB encrypted (Fernet) |
| **Agent → Server** | Per-agent API keys (hashed at rest, constant-time compare); **HTTPS enforced** for credentials; keys **rotatable**/revocable |
| **Server ingest** | Re-runs detection server-side (can't be downgraded by a forged agent); identity bound to the authenticated agent, not the payload |
| **Team → Dashboard** | Token gate; refuses non-loopback bind without a token; HttpOnly cookie |
| **Governance** | Tamper-evident hash-chained audit log; every admin mutation recorded; `verify()` detects edits |
| **Data lifecycle** | Configurable retention + auto-prune; GDPR Art. 17 right-to-erasure by user/device |

Toggle most of these live in **Admin → Settings** (no restart): redaction, HTTPS enforcement,
retention, large-prompt threshold, allowed/denied models, consent banner.

## ⚖️ AI compliance & governance

Built for security **and** audit **and** compliance teams:

- **Sensitive-data / DLP detection** — emails, phones, **SSNs**, **payment cards (Luhn-validated)**,
  IBANs, PHI terms → flagged and **redacted**.
- **AUP policy packs** — configurable org rules ("no prod DB content", "no secrets in prompts", …)
  → a **violation register**.
- **Model governance** — allow/deny which Claude models may be used; off-policy use is flagged.
- **Tamper-evident audit trail** — hash-chained log of AI interactions and admin actions.
- **Right to erasure (GDPR Art. 17)** — delete a subject's data by user or device, audited.
- **Retention & minimization** — keep-N-days + redaction (GDPR Art. 5).
- **Consent & disclosure** — monitoring notice at install + configurable dashboard banner.
- **Framework mapping** — EU AI Act · NIST AI RMF · ISO/IEC 42001 · SOC 2 · GDPR.
- **Export** — CSV / SIEM webhook for your audit pipeline.

## 🚀 Quick start

**Try it on one machine:**
```bash
./scripts/install.sh
pw proxy &
export ANTHROPIC_BASE_URL=http://127.0.0.1:9099   # this terminal only
pw dashboard                                      # http://127.0.0.1:9100
```

## 📦 Installation

Two sides, each with its own guide:

- 🖥️ **Server (security team), one box:** [`deploy/server/README.md`](deploy/server/README.md)
  → `docker compose up -d`
- 💻 **Agent (employee laptops), one line:** [`deploy/agent/README.md`](deploy/agent/README.md)
  → `curl -fsSL https://<server>/install-agent.sh | PW_SERVER=… PW_ENROLL_TOKEN=… bash`

📊 **Shareable system overview** (open in a browser, send to stakeholders):
[`docs/overview.html`](docs/overview.html)

## 🗂️ Project layout

```
src/promptwatch/
├── common/   config · crypto · security · redact · compliance · storage
├── agent/    forwarder · shipper · spool · enroll · service · identity · notifier
├── server/   collector · dashboard · admin · auth · server_store · audit · reports · prune · app
└── cli/      pw entry point
deploy/agent/   employee laptop install
deploy/server/  central server install (compose, env)
docs/           architecture · security · operations · overview.html
```

## 🛠️ Development

```bash
pip install -e ".[dev,server]"
pytest          # 21 tests
ruff check src tests
mypy src
```

## 📚 Docs

[Architecture](docs/architecture.md) · [Security & threat model](docs/security.md) ·
[Operations runbook](docs/operations.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

## 📄 License

[Apache-2.0](LICENSE) — open source
