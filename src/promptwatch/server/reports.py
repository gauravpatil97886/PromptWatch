"""
Compliance reporting + export.

- `compliance_summary()` aggregates the violation register from stored interactions.
- `interactions_csv()` exports metadata (no prompt/response by default) for SIEM/audit.
- `siem_post()` ships events to a webhook (Splunk HEC / generic JSON collector).
- `FRAMEWORKS` maps PromptWatch controls to common frameworks for the compliance status view.
"""

import csv
import io
from typing import Optional

import httpx

from ..common.config import get_settings
from ..common.storage import Store

# Category tags that `collector.evaluate` writes into alert_reason.
_CATEGORIES = ("PII", "PHI", "PCI", "AUP", "model-governance",
               "prompt injection", "credential", "exfiltration")

FRAMEWORKS = {
    "EU AI Act": ["transparency/disclosure", "logging of AI use", "risk monitoring"],
    "NIST AI RMF": ["MAP: inventory of AI use", "MEASURE: incident logging", "MANAGE: response"],
    "ISO/IEC 42001": ["AI management system", "operational controls", "monitoring & audit"],
    "SOC 2": ["access logging", "data retention", "tamper-evident audit trail"],
    "GDPR": ["PII detection", "data minimisation (redaction)", "retention limits"],
}


def compliance_summary(limit: int = 10000) -> dict:
    """Counts of flagged interactions by category + severity, from stored reasons."""
    rows = Store(get_settings()).list_recent(limit)
    by_category = {c: 0 for c in _CATEGORIES}
    by_severity = {1: 0, 2: 0, 3: 0}
    flagged = 0
    for r in rows:
        lvl = r.get("alert_level") or 0
        if lvl > 0:
            flagged += 1
            by_severity[lvl] = by_severity.get(lvl, 0) + 1
        reason = (r.get("alert_reason") or "")
        for c in _CATEGORIES:
            if c.lower() in reason.lower():
                by_category[c] += 1
    return {
        "total": len(rows),
        "flagged": flagged,
        "by_severity": by_severity,
        "by_category": {k: v for k, v in by_category.items() if v},
        "frameworks": FRAMEWORKS,
    }


def interactions_csv(limit: int = 10000, include_content: bool = False) -> str:
    """CSV export of interaction metadata for SIEM/audit. Content excluded by default."""
    rows = Store(get_settings()).list_recent(limit)
    cols = ["ts", "device_name", "sys_user", "os_info", "model",
            "tokens_in", "tokens_out", "alert_level", "alert_reason", "agent_id"]
    if include_content:
        cols += ["prompt", "response"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in cols})
    return buf.getvalue()


async def siem_post(webhook_url: str, events: list[dict], token: Optional[str] = None) -> bool:
    """Forward events to a SIEM webhook. Returns True on a 2xx."""
    headers = {"Authorization": f"Splunk {token}"} if token else {}
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(webhook_url, json={"events": events}, headers=headers)
            return r.status_code < 300
    except Exception:
        return False
