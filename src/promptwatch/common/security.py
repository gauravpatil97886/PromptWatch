"""
Rule-based threat detection for Claude interactions (monitor-only).

Returns an alert level + human-readable reason. Designed for low false-positive
rate so the dashboard stays signal-rich. The credential patterns here are also
reused by `redact.py` to mask secrets before storage/transmission.

Levels: 0 = clean, 1 = low, 2 = medium, 3 = high.
"""

import re
from typing import Optional

CLEAN, LOW, MEDIUM, HIGH = 0, 1, 2, 3

# Default token threshold for the "very large prompt" low-severity flag.
# Overridable by the server settings store / PW_LARGE_PROMPT_TOKENS.
LARGE_PROMPT_TOKENS = 60_000

# ── Prompt injection / jailbreak patterns ───────────────────────────────────────
_INJECTION = [
    r"ignore (all |previous |prior )?(instructions?|prompts?|rules?|guidelines?)",
    r"\byou are now\b",
    r"\bjailbreak\b",
    r"\bDAN\b",
    r"act as (an? )?(unrestricted|unfiltered|evil|hacker)",
    r"pretend (you are|to be).{0,40}(unrestricted|evil|hacker|no.?limit)",
    r"bypass (safety|filter|restriction|censorship)",
    r"(disregard|forget|ignore).{0,30}(previous|prior|earlier).{0,30}(instruction|prompt|rule)",
    r"you have no (restrictions?|limits?|guidelines?)",
    r"(enable|unlock|disable).{0,20}(developer|god|unrestricted).{0,20}mode",
]

# ── Credential / secret patterns ────────────────────────────────────────────────
# Specific, prefix- or assignment-anchored to keep false positives low.
# (compiled regex, human label) — also consumed by redact.py.
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{4,}"),      "password literal"),
    (re.compile(r"(?i)api[_\-]?key\s*[:=]\s*\S{8,}"),              "api key literal"),
    (re.compile(r"(?i)secret[_\-]?key\s*[:=]\s*\S{8,}"),           "secret key literal"),
    (re.compile(r"(?i)access[_\-]?token\s*[:=]\s*\S{8,}"),         "access token literal"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),                    "Anthropic API key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),                           "OpenAI-style key"),
    (re.compile(r"AKIA[A-Z0-9]{16}"),                              "AWS access key id"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                           "GitHub token"),
    (re.compile(r"AIza[A-Za-z0-9_\-]{35}"),                        "Google API key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),                 "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key block"),
]

# ── Data exfiltration hints ─────────────────────────────────────────────────────
# Tightened: only secret-adjacent verbs, not "any URL in the prompt".
_EXFILTRATION = [
    r"(send|email|upload|exfiltrate|leak|post).{0,40}(password|secret|key|credential|token)",
    r"(dump|extract|steal|exfiltrate).{0,30}(database|table|users?|records?|customer data)",
    r"(curl|wget|fetch|requests?\.post).{0,80}(password|secret|key|token|cookie)",
]


def analyze(
    prompt: str,
    tokens_in: Optional[int],
    client_ip: Optional[str] = None,   # reserved; no longer auto-flagged (see note)
    *,
    large_prompt_tokens: int = LARGE_PROMPT_TOKENS,
) -> tuple[int, Optional[str]]:
    """
    Returns (alert_level, alert_reason).

    Note: a non-local `client_ip` is NOT treated as an alert. In agent/central
    deployments every request is non-local by design, so that rule produced an
    alert on every interaction. Unexpected-source detection now belongs to the
    server (device allowlist), not this per-request analyzer.
    """
    reasons: list[str] = []
    level = CLEAN
    text = prompt.lower()

    for pat in _INJECTION:
        if re.search(pat, text):
            reasons.append("prompt injection attempt")
            level = max(level, MEDIUM)
            break

    for pat, label in _CREDENTIAL_PATTERNS:
        if pat.search(prompt):
            reasons.append(f"possible credential in prompt ({label})")
            level = max(level, HIGH)
            break

    for pat in _EXFILTRATION:
        if re.search(pat, text):
            reasons.append("possible data exfiltration intent")
            level = max(level, MEDIUM)
            break

    if tokens_in and tokens_in > large_prompt_tokens:
        reasons.append(f"very large prompt ({tokens_in:,} tokens)")
        level = max(level, LOW)

    return level, "; ".join(reasons) if reasons else None
