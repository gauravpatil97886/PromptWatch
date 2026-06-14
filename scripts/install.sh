#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Installing PromptWatch..."

# Require Python 3.11+
python_bin=$(command -v python3 || command -v python)
version=$("$python_bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required="3.11"
if python3 -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)"; then
    echo "    Python $version — OK"
else
    echo "ERROR: Python 3.11+ required (found $version)"; exit 1
fi

# Install with pip into a venv inside the project
if [ ! -d "$REPO_DIR/.venv" ]; then
    "$python_bin" -m venv "$REPO_DIR/.venv"
fi
"$REPO_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$REPO_DIR/.venv/bin/pip" install --quiet -e "$REPO_DIR"

# Symlink pw into ~/.local/bin
mkdir -p "$HOME/.local/bin"
ln -sf "$REPO_DIR/.venv/bin/pw"       "$HOME/.local/bin/pw"
ln -sf "$REPO_DIR/.venv/bin/promptwatch-proxy" "$HOME/.local/bin/promptwatch-proxy"

# Create default config dir
mkdir -p "$HOME/.promptwatch"
if [ ! -f "$HOME/.promptwatch/.env" ]; then
    cat > "$HOME/.promptwatch/.env" << 'EOF'
# PromptWatch — edit to override defaults
# PW_PROXY_PORT=9099
# PW_UPSTREAM_BASE_URL=https://api.anthropic.com
# PW_ENCRYPT_LOGS=true
# PW_CLAUDE_CLI_CMD=claude
EOF
fi

echo ""
echo "==> Done!  Commands available:"
echo "    pw proxy          # start the API proxy"
echo "    pw ask 'hello'    # send via claude CLI, logged"
echo "    pw logs           # view recent interactions"
echo "    pw stats          # usage stats"
echo "    pw dashboard      # open web dashboard"
echo ""
echo "==> To use the proxy for a session (run this EACH time, do NOT add to .bashrc):"
echo "    pw proxy &"
echo "    export ANTHROPIC_BASE_URL=http://127.0.0.1:9099"
echo ""
echo "    WARNING: Do NOT add ANTHROPIC_BASE_URL to .bashrc — all Claude tools"
echo "    will break silently when the proxy is not running."
