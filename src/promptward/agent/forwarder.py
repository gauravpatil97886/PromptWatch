"""
Transparent HTTPS proxy for the Anthropic API.

Per-machine session:
    pw proxy &
    export ANTHROPIC_BASE_URL=http://127.0.0.1:9099

For org-wide central deployment:
    # On server: pw proxy --host 0.0.0.0
    # On each machine: export ANTHROPIC_BASE_URL=http://<server-ip>:9099
                       export PW_DEVICE_NAME=john-macbook   # optional override

Do NOT add ANTHROPIC_BASE_URL to .bashrc permanently.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncIterator

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from .shipper import post_session as _backend_post, drain_loop as _drain_loop
from ..common.config import get_machine_meta, get_settings
from .notifier import run_poller as _run_poller
from ..common.redact import redact as _redact
from ..common.compliance import redact as _redact_pii
from ..common.security import analyze as security_analyze
from ..common.storage import Store

logger = logging.getLogger("pw.proxy")

_STRIP_REQ_HEADERS  = {"host", "content-length", "transfer-encoding", "accept-encoding"}
_STRIP_RESP_HEADERS = {"transfer-encoding", "content-encoding"}

# Capture machine identity once at startup
_SETTINGS     = get_settings()
_MACHINE_META = get_machine_meta()
_DEVICE_NAME  = _SETTINGS.device_name


def _maybe_redact(prompt: str, response: str) -> tuple[str, str]:
    """Mask secrets + PII before storage/transmission, per settings."""
    if _SETTINGS.redact_secrets:
        prompt, response = _redact(prompt)[0], _redact(response)[0]
    if _SETTINGS.redact_pii:
        prompt, response = _redact_pii(prompt)[0], _redact_pii(response)[0]
    return prompt, response


def _parse_os_from_ua(ua: str) -> str:
    """Extract OS hint from Claude Code user-agent string."""
    ua_lower = ua.lower()
    if "linux"   in ua_lower: return "Linux"
    if "darwin"  in ua_lower: return "macOS"
    if "windows" in ua_lower: return "Windows"
    if "win32"   in ua_lower: return "Windows"
    return _MACHINE_META["os"]   # fall back to local OS


def _build_app() -> FastAPI:
    settings = get_settings()
    store    = Store(settings)
    client   = httpx.AsyncClient(base_url=settings.upstream_base_url, timeout=300)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "Promptward agent  device=%s  host=%s:%d  upstream=%s",
            _DEVICE_NAME, settings.proxy_host, settings.proxy_port, settings.upstream_base_url,
        )
        # Background tasks: notification poller + spool drain (both no-op if unenrolled)
        poller = asyncio.create_task(_run_poller(_DEVICE_NAME))
        drainer = asyncio.create_task(_drain_loop())
        yield
        poller.cancel()
        drainer.cancel()
        await client.aclose()

    app = FastAPI(lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict:
        """Liveness probe — used by the fail-open wrapper and service checks."""
        return {"ok": True, "device": _DEVICE_NAME}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(path: str, request: Request) -> Response:
        body_bytes = await request.body()
        client_ip  = request.client.host if request.client else "unknown"
        ua         = request.headers.get("user-agent", "")

        # Allow client to override device name via header (useful for central proxy)
        device_override = request.headers.get("x-pw-device", "")
        device  = device_override or _DEVICE_NAME
        os_info = _parse_os_from_ua(ua) if ua else _MACHINE_META["os"]

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _STRIP_REQ_HEADERS
        }

        upstream_req = client.build_request(
            method=request.method,
            url=f"/{path}",
            headers=headers,
            params=request.query_params,
            content=body_bytes,
        )

        upstream_resp = await client.send(upstream_req, stream=True)

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in _STRIP_RESP_HEADERS
        }

        if "/messages" not in path:
            return StreamingResponse(
                upstream_resp.aiter_bytes(),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
            )

        try:
            body_json = json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError:
            body_json = {}

        meta = {
            "device_name": device,
            "hostname":    _MACHINE_META["hostname"],
            "sys_user":    _MACHINE_META["sys_user"],
            "os_info":     os_info,
            "client_ip":   client_ip,
            "user_agent":  ua,
        }

        if body_json.get("stream", False):
            return _stream_response(store, body_json, upstream_resp, resp_headers, meta)

        return await _buffer_response(store, body_json, upstream_resp, resp_headers, meta)

    return app


def _stream_response(
    store: Store, body_json: dict,
    upstream_resp: httpx.Response, resp_headers: dict, meta: dict,
) -> StreamingResponse:
    collected: list[bytes] = []

    async def stream_and_collect() -> AsyncGenerator[bytes, None]:
        async for chunk in upstream_resp.aiter_bytes():
            collected.append(chunk)
            yield chunk
        asyncio.create_task(
            _log_sse(store, body_json, b"".join(collected).decode(errors="replace"), meta)
        )

    return StreamingResponse(
        stream_and_collect(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


async def _buffer_response(
    store: Store, body_json: dict,
    upstream_resp: httpx.Response, resp_headers: dict, meta: dict,
) -> Response:
    chunks: list[bytes] = []
    async for chunk in upstream_resp.aiter_bytes():
        chunks.append(chunk)
    full_body = b"".join(chunks)
    asyncio.create_task(
        _log_json(store, body_json, full_body.decode(errors="replace"), meta)
    )
    return Response(content=full_body, status_code=upstream_resp.status_code, headers=resp_headers)


async def _log_json(store: Store, req: dict, body: str, meta: dict) -> None:
    try:
        resp    = json.loads(body) if body.strip() else {}
        content = resp.get("content", [])
        resp_text = " ".join(
            b.get("text", "") for b in content if isinstance(b, dict)
        ) if isinstance(content, list) else str(content)
        usage  = resp.get("usage", {})
        prompt = json.dumps(req.get("messages", []), ensure_ascii=False)
        ti     = usage.get("input_tokens")
        # Detect on the RAW text, then mask before storing/shipping.
        alv, areason = security_analyze(prompt, ti, meta.get("client_ip"))
        prompt, resp_text = _maybe_redact(prompt, resp_text)
        kw = dict(source="proxy", prompt=prompt, response=resp_text,
                  model=resp.get("model") or req.get("model"),
                  tokens_in=ti, tokens_out=usage.get("output_tokens"),
                  **meta, alert_level=alv, alert_reason=areason)
        await asyncio.to_thread(store.save, **kw)
        asyncio.create_task(_backend_post(**kw))
    except Exception as exc:
        logger.warning("log_json failed: %s", exc)


async def _log_sse(store: Store, req: dict, sse: str, meta: dict) -> None:
    try:
        parts: list[str] = []
        tokens_in = tokens_out = None
        model: str | None = None

        for line in sse.splitlines():
            if not line.startswith("data:"): continue
            data = line[5:].strip()
            if data == "[DONE]": continue
            try: ev = json.loads(data)
            except json.JSONDecodeError: continue
            t = ev.get("type", "")
            if t == "content_block_delta":
                d = ev.get("delta", {})
                if d.get("type") == "text_delta":
                    parts.append(d.get("text", ""))
            elif t == "message_start":
                msg   = ev.get("message", {})
                model = model or msg.get("model")
                tokens_in = msg.get("usage", {}).get("input_tokens")
            elif t == "message_delta":
                to = ev.get("usage", {}).get("output_tokens")
                if to: tokens_out = to

        prompt = json.dumps(req.get("messages", []), ensure_ascii=False)
        response = "".join(parts)
        # Detect on the RAW text, then mask before storing/shipping.
        alv, areason = security_analyze(prompt, tokens_in, meta.get("client_ip"))
        prompt, response = _maybe_redact(prompt, response)
        kw = dict(source="proxy", prompt=prompt, response=response,
                  model=model or req.get("model"),
                  tokens_in=tokens_in, tokens_out=tokens_out,
                  **meta, alert_level=alv, alert_reason=areason)
        await asyncio.to_thread(store.save, **kw)
        asyncio.create_task(_backend_post(**kw))
    except Exception as exc:
        logger.warning("log_sse failed: %s", exc)


def run() -> None:
    settings = get_settings()
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(
        _build_app(),
        host=settings.proxy_host,
        port=settings.proxy_port,
        log_level="warning",
    )


if __name__ == "__main__":
    run()
