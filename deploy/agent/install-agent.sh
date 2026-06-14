#!/usr/bin/env bash
#
# One-line PromptWatch agent install for employee machines (Linux/macOS).
#
#   curl -fsSL https://<server>/install-agent.sh | \
#     PW_SERVER=https://pw.corp PW_ENROLL_TOKEN=xxxxx bash
#
# Installs the thin agent (no server deps), enrolls it (per-agent key), installs
# the OS service + fail-open `claude-tracked` wrapper. Idempotent.
set -euo pipefail

: "${PW_SERVER:?Set PW_SERVER to your collector URL, e.g. https://pw.corp}"
: "${PW_ENROLL_TOKEN:?Set PW_ENROLL_TOKEN (from your security team)}"
PW_PACKAGE="${PW_PACKAGE:-promptwatch}"   # or a git URL / local path

echo "==> Installing PromptWatch agent..."

# Prefer pipx (isolated), fall back to pip --user.
if command -v pipx >/dev/null 2>&1; then
    pipx install --force "$PW_PACKAGE"
    BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
else
    python3 -m pip install --user --upgrade "$PW_PACKAGE"
    BIN="$HOME/.local/bin"
fi
export PATH="$BIN:$PATH"

echo "==> Enrolling with $PW_SERVER ..."
pw enroll --server "$PW_SERVER" --token "$PW_ENROLL_TOKEN"

cat <<EOF

==> Done. AI monitoring is active for this machine (monitor-only, fail-open).

   Use 'claude-tracked' in place of 'claude' (or rely on the background service).
   The agent forwards directly to Anthropic and ships logs to your org collector;
   if the collector is unreachable, Claude keeps working and logs are spooled.

   Notice: your organization monitors AI tool usage for security and compliance.
EOF
