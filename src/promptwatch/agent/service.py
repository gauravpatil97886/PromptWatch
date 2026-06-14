"""
Install the agent as an OS service plus a fail-open `claude` wrapper.

- Linux  → systemd **user** unit (`~/.config/systemd/user/pw.service`)
- macOS  → launchd agent  (`~/Library/LaunchAgents/com.promptwatch.agent.plist`)
- Wrapper → `~/.local/bin/claude-tracked`: routes Claude through the local agent
  ONLY when the agent's /healthz responds, otherwise runs Claude directly. This
  is what removes the "ANTHROPIC_BASE_URL breaks Claude when the proxy is down" footgun.
"""

import platform
import shutil
import sys
from pathlib import Path

from ..common.config import get_settings

SYSTEMD_UNIT = Path.home() / ".config/systemd/user/pw.service"
LAUNCHD_PLIST = Path.home() / "Library/LaunchAgents/com.promptwatch.agent.plist"
WRAPPER_PATH = Path.home() / ".local/bin/claude-tracked"


def _agent_cmd() -> str:
    """Best command to launch the forwarder, preferring an installed console script."""
    exe = shutil.which("pw") or shutil.which("promptwatch")
    if exe:
        return f"{exe} proxy"
    return f"{sys.executable} -m promptwatch.cli.main proxy"


def _write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def install_wrapper() -> Path:
    s = get_settings()
    url = f"http://{s.proxy_host}:{s.proxy_port}"
    script = f"""#!/usr/bin/env bash
# PromptWatch fail-open wrapper: route Claude through the local agent only if it is up.
AGENT="{url}"
if curl -fsS --max-time 1 "$AGENT/healthz" >/dev/null 2>&1; then
  export ANTHROPIC_BASE_URL="$AGENT"
fi
exec claude "$@"
"""
    _write(WRAPPER_PATH, script, 0o755)
    return WRAPPER_PATH


def _install_systemd() -> Path:
    unit = f"""[Unit]
Description=PromptWatch (forwarder)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={_agent_cmd()}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"""
    _write(SYSTEMD_UNIT, unit)
    return SYSTEMD_UNIT


def _install_launchd() -> Path:
    cmd = _agent_cmd().split()
    args = "".join(f"    <string>{c}</string>\n" for c in cmd)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.promptwatch.agent</string>
  <key>ProgramArguments</key><array>
{args}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
"""
    _write(LAUNCHD_PLIST, plist)
    return LAUNCHD_PLIST


def install() -> dict:
    """Install service unit + wrapper for the current OS. Returns created paths + hints."""
    system = platform.system()
    wrapper = install_wrapper()
    if system == "Linux":
        unit = _install_systemd()
        hint = "systemctl --user daemon-reload && systemctl --user enable --now pw.service"
    elif system == "Darwin":
        unit = _install_launchd()
        hint = f"launchctl load {LAUNCHD_PLIST}"
    else:
        return {"os": system, "wrapper": str(wrapper), "unit": None,
                "hint": "Service install is supported on Linux/macOS only; run `pw proxy` manually."}
    return {"os": system, "wrapper": str(wrapper), "unit": str(unit), "hint": hint}
