"""
Secret redaction — mask detected credentials in text before it is stored
locally or shipped to the central collector.

Monitor-only posture: detection (security.analyze) runs on the RAW text so the
alert is accurate; redaction then masks the secret value so the stored/shipped
copy never contains it. Fail-open: redaction never raises into the request path.

Reuses the credential patterns from `security.py` so detection and masking stay
in sync. PII/PHI/PCI masking is layered on top by `compliance.py`.
"""

from .security import _CREDENTIAL_PATTERNS


def _mask(match: "object") -> str:
    """Replace a matched secret with a short, non-reversible placeholder."""
    token = match.group(0)
    # Keep a tiny prefix for triage when the secret has a recognizable scheme
    # (e.g. "sk-ant"); otherwise mask entirely.
    head = token[:6] if token[:3] in ("sk-", "AKI", "ghp", "AIz", "xox") else ""
    return f"{head}…[redacted:{len(token)} chars]"


def redact(text: str) -> tuple[str, int]:
    """
    Return (redacted_text, count). `count` is how many secrets were masked.
    Best-effort and fail-open: on any error the original text is returned.
    """
    if not text:
        return text, 0
    try:
        count = 0
        out = text
        for pattern, _label in _CREDENTIAL_PATTERNS:
            out, n = pattern.subn(_mask, out)
            count += n
        return out, count
    except Exception:
        return text, 0
