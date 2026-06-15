"""
Central collector — the server-side ingest the agent ships to.

Endpoints (contract assumed by agent/shipper.py and agent/notifier.py):
    POST /api/v1/enroll                      org enroll token → per-agent key
    POST /api/v1/sessions                    ingest one interaction  (X-Agent-Key)
    GET  /api/v1/notifications               poll pushes for a device (X-Agent-Key)
    POST /api/v1/notifications/{id}/ack      mark a push delivered    (X-Agent-Key)
    GET  /healthz                            liveness

Agents authenticate with their per-agent key (hashed at rest). The collector
re-runs `security.analyze` server-side so detection rules are enforced centrally
even if an older agent shipped without them.
"""

import logging
import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from ..common import compliance
from ..common.config import get_settings
from ..common.redact import redact as _redact_secrets
from ..common.security import analyze as security_analyze
from ..common.storage import Store
from .server_store import ServerStore

logger = logging.getLogger("pw.collector")


def _apply_redaction(redact_secrets: bool, redact_pii: bool, prompt: str, response: str) -> tuple[str, str]:
    """Defense-in-depth: re-mask at the collector in case an agent shipped raw."""
    if redact_secrets:
        prompt, response = _redact_secrets(prompt)[0], _redact_secrets(response)[0]
    if redact_pii:
        prompt, response = compliance.redact(prompt)[0], compliance.redact(response)[0]
    return prompt, response


def _truthy(v, default: bool) -> bool:
    return default if v is None else str(v).strip().lower() in ("1", "true", "yes", "on")


def _csv_list(v) -> list:
    return [s.strip() for s in (v or "").split(",") if s.strip()]


class EnrollBody(BaseModel):
    enroll_token: str
    device_name: str
    hostname: str | None = None
    os: str | None = None
    arch: str | None = None
    sys_user: str | None = None


class SessionBody(BaseModel):
    source: str = "proxy"
    prompt: str = ""
    response: str = ""
    model: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    device_name: str | None = None
    hostname: str | None = None
    sys_user: str | None = None
    os_info: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None
    alert_level: int = 0
    alert_reason: str | None = None
    agent_id: str | None = None


def evaluate(body: "SessionBody", *, large_prompt_tokens: int = 60_000,
             model_allow=(), model_deny=()) -> tuple[int, str | None]:
    """Combine security + compliance analysis into (alert_level, reason)."""
    level, reason = security_analyze(body.prompt, body.tokens_in, body.client_ip,
                                     large_prompt_tokens=large_prompt_tokens)
    reasons = [reason] if reason else []
    if body.alert_level > level:
        level, reasons = body.alert_level, [body.alert_reason or ""]

    hits = compliance.scan(body.prompt) + compliance.evaluate_policies(body.prompt)
    model_hit = compliance.check_model(body.model, allow=model_allow, deny=model_deny)
    if model_hit:
        hits.append(model_hit)
    if hits:
        level = max(level, compliance.worst_severity(hits))
        reasons += [f"{h['category']}: {h.get('label') or h.get('title')}" for h in hits]

    return level, ("; ".join(r for r in reasons if r) or None)


def build_collector() -> FastAPI:
    settings = get_settings()
    store = Store(settings)
    sstore = ServerStore(settings)
    sstore.ensure_enroll_token()  # idempotent
    app = FastAPI(title="Promptward Collector")

    def _require_agent(key: str | None) -> str:
        agent_id = sstore.verify_agent_key(key or "")
        if not agent_id:
            raise HTTPException(status_code=401, detail="invalid agent key")
        return agent_id

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.post("/api/v1/enroll")
    async def enroll(body: EnrollBody) -> dict:
        if not sstore.verify_enroll_token(body.enroll_token):
            raise HTTPException(status_code=401, detail="invalid enroll token")
        agent_id, key = sstore.create_agent(
            body.device_name,
            {"hostname": body.hostname, "os": body.os, "arch": body.arch,
             "sys_user": body.sys_user},
        )
        return {"agent_id": agent_id, "agent_key": key}

    @app.post("/api/v1/rotate")
    async def rotate(x_agent_key: str | None = Header(default=None)) -> dict:
        """An agent rotates its own key (presents the current key, gets a new one)."""
        agent_id = _require_agent(x_agent_key)
        new_key = sstore.rotate_agent_key(agent_id)
        return {"agent_id": agent_id, "agent_key": new_key}

    @app.post("/api/v1/sessions")
    async def ingest(body: SessionBody, x_agent_key: str | None = Header(default=None)) -> dict:
        agent_id = _require_agent(x_agent_key)
        await asyncio.to_thread(sstore.touch_agent, agent_id)
        # Effective settings: admin UI overrides (DB) fall back to env/config.
        cfg = sstore.all_settings()
        rs = _truthy(cfg.get("redact_secrets"), settings.redact_secrets)
        rp = _truthy(cfg.get("redact_pii"), settings.redact_pii)
        lpt = int(cfg.get("large_prompt_tokens") or 60_000)
        # Re-evaluate centrally on RAW text (security + compliance); trust higher severity.
        level, reason = evaluate(body, large_prompt_tokens=lpt,
                                 model_allow=_csv_list(cfg.get("model_allow")),
                                 model_deny=_csv_list(cfg.get("model_deny")))
        # Bind identity to the authenticated agent record, not the (spoofable) payload.
        rec = sstore.get_agent(agent_id) or {}
        prompt, response = _apply_redaction(rs, rp, body.prompt, body.response)
        await asyncio.to_thread(
            store.save,
            source=body.source, prompt=prompt, response=response,
            model=body.model, tokens_in=body.tokens_in, tokens_out=body.tokens_out,
            device_name=rec.get("device_name") or body.device_name,
            hostname=rec.get("hostname") or body.hostname,
            sys_user=rec.get("sys_user") or body.sys_user,
            os_info=rec.get("os") or body.os_info, client_ip=body.client_ip,
            user_agent=body.user_agent, alert_level=level, alert_reason=reason,
            agent_id=agent_id, received_at=datetime.now(timezone.utc).isoformat(),
        )
        return {"ok": True}

    @app.get("/api/v1/notifications")
    async def notifications(device: str, unread: bool = True,
                            x_agent_key: str | None = Header(default=None)) -> list[dict]:
        _require_agent(x_agent_key)
        return sstore.list_notifications(device, unread=unread)

    @app.post("/api/v1/notifications/{notif_id}/ack")
    async def ack(notif_id: int, x_agent_key: str | None = Header(default=None)) -> dict:
        _require_agent(x_agent_key)
        sstore.ack_notification(notif_id)
        return {"ok": True}

    return app
