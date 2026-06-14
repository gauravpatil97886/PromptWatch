# PromptWatch Agent — Employee Laptop Install

This is the **thin agent** that runs on each employee machine. It forwards Claude traffic
straight to Anthropic (zero added latency, **fails open** — Claude never breaks) and ships
log events to your org's central PromptWatch server. It does **not** include the dashboard.

You need two things from your security team: the **server URL** and the **org enroll token**.

## Easy setup (one line)

```bash
curl -fsSL https://<server>/install-agent.sh | \
  PW_SERVER=https://pw.corp PW_ENROLL_TOKEN=xxxxx bash
```

That installs the agent, enrolls it (gets a unique per-agent key), installs a background
service, and drops a `claude-tracked` wrapper. Done.

## Manual setup

```bash
pipx install promptwatch           # or: pip install --user promptwatch
pw enroll --server https://pw.corp --token xxxxx
# Linux: make it start on boot
systemctl --user enable --now pw.service
loginctl enable-linger "$USER"            # survive logout/reboot on headless machines
```

## Using it

- Run **`claude-tracked`** instead of `claude`. The wrapper checks the local agent's health
  and only routes through it if it's up; otherwise it runs Claude directly (fail-open).
- Or, for a terminal session only (never add to `.bashrc`):
  ```bash
  export ANTHROPIC_BASE_URL=http://127.0.0.1:9099
  ```

## Privacy

Monitor-only. Secrets and PII (SSNs, cards, emails…) are **masked before anything leaves your
machine**. Your organization monitors AI tool usage for security and compliance.

## Uninstall

```bash
systemctl --user disable --now pw.service   # Linux
pipx uninstall promptwatch
rm -rf ~/.promptwatch ~/.local/bin/claude-tracked
```
