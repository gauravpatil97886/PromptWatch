"""
Dashboard access control (Phase 0 — shared token).

A single `dashboard_token` gates the dashboard and its read APIs. Tokens are
compared in constant time. Browsers authenticate once via `/login?token=…`,
which sets an HttpOnly cookie; APIs may also pass `Authorization: Bearer <token>`
or `X-Dashboard-Token: <token>`.

Phase 3 replaces this with per-user accounts + RBAC, but keeps the same dependency
surface so call sites don't change.
"""

import hashlib
import hmac
import ipaddress
import secrets

COOKIE_NAME = "cta_token"
# Paths reachable without a token (login form + liveness).
PUBLIC_PATHS = frozenset({"/login", "/healthz", "/favicon.ico"})


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


def hash_key(key: str) -> str:
    """SHA-256 hex digest used to store agent keys / enroll tokens at rest."""
    return hashlib.sha256(key.encode()).hexdigest()


def new_token(prefix: str = "", nbytes: int = 32) -> str:
    """Generate a URL-safe secret, optionally prefixed (e.g. 'cta_')."""
    return f"{prefix}{secrets.token_urlsafe(nbytes)}"


def new_id(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def extract_token(request) -> str:
    """Pull a token from Authorization bearer, custom header, or cookie."""
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (
        request.headers.get("x-dashboard-token", "")
        or request.cookies.get(COOKIE_NAME, "")
    )
