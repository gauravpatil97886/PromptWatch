"""Thin wrapper around the `claude` CLI that logs every interaction."""

import subprocess
import sys

from ..common.compliance import redact as _redact_pii
from ..common.config import get_settings
from ..common.redact import redact as _redact_secrets
from ..common.security import analyze as _analyze
from ..common.storage import Store


def run(prompt: str) -> int:
    settings = get_settings()
    store = Store(settings)

    # Pass the full prompt as a single argument via --print (non-interactive mode).
    # The original code did prompt.split() which broke multi-word prompts.
    result = subprocess.run(
        [settings.claude_cli_cmd, "--print", prompt],
        text=True,
        capture_output=True,
    )

    response = result.stdout.strip() or result.stderr.strip()
    # Same pipeline as the proxy: detect on raw text, then mask before storage.
    alert_level, alert_reason = _analyze(prompt, None, None)
    stored_prompt, stored_response = prompt, response
    if settings.redact_secrets:
        stored_prompt, stored_response = _redact_secrets(stored_prompt)[0], _redact_secrets(stored_response)[0]
    if settings.redact_pii:
        stored_prompt, stored_response = _redact_pii(stored_prompt)[0], _redact_pii(stored_response)[0]
    store.save(source="cli", prompt=stored_prompt, response=stored_response,
               alert_level=alert_level, alert_reason=alert_reason)

    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    return result.returncode
