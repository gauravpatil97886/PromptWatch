"""
Poll the ChoiceTrack backend for notifications sent to this device.
Delivers via:
  1. Desktop popup  (notify-send on Linux, osascript on macOS)
  2. Terminal alert (bold coloured banner in stderr)

Enabled when PW_BACKEND_URL is set.
"""

import asyncio
import logging
import os
import subprocess
import sys

import httpx

from .identity import agent_key, server_url

logger = logging.getLogger("pw.notifier")

_INTERVAL = int(os.getenv("PW_NOTIFY_POLL_SEC", "15"))

# ANSI colours
_RED   = "\033[1;31m"
_AMBER = "\033[1;33m"
_BLUE  = "\033[1;34m"
_CYAN  = "\033[1;36m"
_WHITE = "\033[1;37m"
_RESET = "\033[0m"

_SEV_LABEL = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}
_SEV_COLOR = {3: _RED,   2: _AMBER,   1: _BLUE}


# ── Desktop notification ───────────────────────────────────────────────────────

def _desktop_notify(title: str, message: str, sev: int) -> None:
    """Fire a native desktop popup — works on Linux (notify-send) and macOS."""
    urgency = {3: "critical", 2: "normal", 1: "low"}.get(sev, "normal")
    icon    = {3: "dialog-error", 2: "dialog-warning", 1: "dialog-information"}.get(sev, "dialog-information")
    short   = message[:200]  # notify-send truncates anyway

    try:
        # Linux — notify-send
        subprocess.Popen(
            ["notify-send", "--urgency", urgency, "--icon", icon,
             "--app-name", "ChoiceTrack Security", "--expire-time", "10000",
             title, short],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return
    except FileNotFoundError:
        pass

    try:
        # macOS fallback
        script = f'display notification "{short}" with title "{title}" sound name "Basso"'
        subprocess.Popen(
            ["osascript", "-e", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass  # neither available — terminal-only


# ── Terminal banner ────────────────────────────────────────────────────────────

def _terminal_notify(n: dict) -> None:
    sev   = n.get("severity", 2)
    title = n.get("title", "Security Notification")
    msg   = n.get("message", "")
    by    = n.get("sent_by", "IT Security Team")
    ts    = n.get("ts", "")[:16].replace("T", " ")
    col   = _SEV_COLOR.get(sev, _BLUE)
    label = _SEV_LABEL.get(sev, "INFO")
    bar   = "═" * 62

    lines = [
        f"\n{col}{bar}{_RESET}",
        f"{col}  🔔  CHOICETRACK SECURITY ALERT  ─  {label}{_RESET}",
        f"{col}{bar}{_RESET}",
        f"{_WHITE}  {title}{_RESET}",
        f"  {msg}",
        f"  {_CYAN}From:{_RESET} {by}   {_CYAN}Sent:{_RESET} {ts} IST",
        f"{col}{bar}{_RESET}\n",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


# ── Poll logic ─────────────────────────────────────────────────────────────────

async def _poll_once(device: str, url: str, key: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            resp = await c.get(
                f"{url}/api/v1/notifications",
                params={"device": device, "unread": "true"},
                headers={"X-Agent-Key": key},
            )
            if resp.status_code != 200:
                return

            for n in resp.json():
                # Show both desktop popup AND terminal banner
                _desktop_notify(n.get("title", "Alert"), n.get("message", ""), n.get("severity", 2))
                _terminal_notify(n)

                # Mark as read so it doesn't show again
                try:
                    await c.post(
                        f"{url}/api/v1/notifications/{n['id']}/ack",
                        headers={"X-Agent-Key": key},
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("notifier poll error: %s", exc)


async def run_poller(device: str) -> None:
    """Long-running background coroutine. Started by the forwarder lifespan."""
    url, key = server_url(), agent_key()
    if not url or not key:
        return  # not enrolled / no collector — nothing to poll
    logger.info("Notification poller active — device=%s server=%s poll=%ds",
                device, url, _INTERVAL)
    while True:
        await _poll_once(device, url, key)
        await asyncio.sleep(_INTERVAL)
