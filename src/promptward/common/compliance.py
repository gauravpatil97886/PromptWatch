"""
AI-governance / compliance detection.

Three layers, all monitor-only and additive to `security.py`:
  1. Sensitive-data detectors (PII / PHI / PCI) used for DLP + the redaction layer.
  2. AUP policy packs — named, configurable org rules ("no customer PII", etc.).
  3. Model governance — allow/deny which Claude models may be used.

Everything returns plain dicts so the collector can persist findings and the
dashboard can render a violation register without extra types crossing layers.
"""

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .security import CLEAN, HIGH, LOW, MEDIUM

# ── Sensitive-data detectors ────────────────────────────────────────────────────
# (compiled regex, label, category, severity). Categories: PII | PHI | PCI.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,2}[ .\-]?)?(?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]?\d{4}(?!\d)")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[ \-]?(?!00)\d{2}[ \-]?(?!0000)\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
# Lightweight PHI signal: medical/health terms near an identifier-ish context.
_PHI_TERMS = re.compile(r"(?i)\b(diagnos\w+|patient|prescription|ICD-?10|medical record|mrn)\b")


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan(text: str) -> list[dict]:
    """Return sensitive-data findings: [{category, label, severity, count}]."""
    if not text:
        return []
    findings: list[dict] = []

    def _add(label: str, category: str, severity: int, count: int) -> None:
        if count:
            findings.append({"category": category, "label": label,
                             "severity": severity, "count": count})

    _add("email address", "PII", LOW, len(_EMAIL.findall(text)))
    _add("phone number", "PII", LOW, len(_PHONE.findall(text)))
    _add("US SSN", "PII", HIGH, len(_SSN.findall(text)))
    _add("IBAN", "PCI", MEDIUM, len(_IBAN.findall(text)))
    cards = [m.group(0) for m in _CARD.finditer(text) if _luhn_ok(m.group(0))]
    _add("payment card number", "PCI", HIGH, len(cards))
    _add("health/medical term", "PHI", MEDIUM, len(_PHI_TERMS.findall(text)))
    return findings


# ── AUP policy packs ────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Policy:
    key: str
    title: str
    pattern: str          # regex (case-insensitive)
    severity: int
    category: str = "AUP"
    enabled: bool = True


DEFAULT_POLICIES: list[Policy] = [
    Policy("no-secrets-in-prompt", "Secret material in prompt",
           r"-----BEGIN .*PRIVATE KEY-----|\b(client_secret|service_account)\b", HIGH),
    Policy("no-prod-db-dumps", "Production database content",
           r"\b(prod(uction)?\s+(db|database)|select \* from)\b", MEDIUM),
    Policy("no-legal-medical-advice", "Legal/medical advice use",
           r"\b(is this legal|medical advice|diagnos\w+ me)\b", LOW),
]


def evaluate_policies(text: str, policies: Optional[Iterable[Policy]] = None) -> list[dict]:
    """Return AUP violations: [{key, title, category, severity}]. Case-insensitive."""
    if not text:
        return []
    out: list[dict] = []
    for p in policies if policies is not None else DEFAULT_POLICIES:
        if p.enabled and re.search(p.pattern, text, re.IGNORECASE):
            out.append({"key": p.key, "title": p.title,
                        "category": p.category, "severity": p.severity})
    return out


# ── Model governance ────────────────────────────────────────────────────────────
def check_model(model: Optional[str], allow: Iterable[str] = (),
                deny: Iterable[str] = ()) -> Optional[dict]:
    """Flag off-policy model use. allow=() means 'any not denied'."""
    if not model:
        return None
    allow, deny = list(allow), list(deny)
    if any(d in model for d in deny):
        return {"key": "model-denied", "title": f"Denied model: {model}",
                "category": "model-governance", "severity": MEDIUM}
    if allow and not any(a in model for a in allow):
        return {"key": "model-not-allowed", "title": f"Off-policy model: {model}",
                "category": "model-governance", "severity": LOW}
    return None


def worst_severity(findings: Iterable[dict]) -> int:
    return max((f.get("severity", CLEAN) for f in findings), default=CLEAN)


# ── PII/PHI/PCI redaction (data minimisation) ────────────────────────────────────
_PII_SUBS = [
    (_SSN, "‹ssn redacted›"),
    (_EMAIL, "‹email redacted›"),
    (_IBAN, "‹iban redacted›"),
    (_PHONE, "‹phone redacted›"),
]


def redact(text: str) -> tuple[str, int]:
    """
    Mask sensitive data (PII/PCI) before storage/transmission. Cards keep the last
    four digits (Luhn-validated); other identifiers are fully masked. Fail-open:
    returns the original text on any error.
    """
    if not text:
        return text, 0
    try:
        count = {"n": 0}

        def _card(m):
            s = m.group(0)
            if _luhn_ok(s):
                count["n"] += 1
                last4 = "".join(c for c in s if c.isdigit())[-4:]
                return f"‹card ••{last4}›"
            return s

        out = _CARD.sub(_card, text)        # longest/most-specific first
        for pat, repl in _PII_SUBS:
            out, k = pat.subn(repl, out)
            count["n"] += k
        return out, count["n"]
    except Exception:
        return text, 0
