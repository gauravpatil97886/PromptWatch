import getpass
import platform
import socket
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


DATA_DIR = Path.home() / ".promptward"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=DATA_DIR / ".env",
        env_prefix="PW_",
        extra="ignore",
    )

    # Proxy
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 9099
    upstream_base_url: str = "https://api.anthropic.com"

    # Storage
    db_path: Path = DATA_DIR / "interactions.db"
    encrypt_logs: bool = True
    key_file: Path = DATA_DIR / ".secret.key"

    # Privacy posture (monitor-only). When true, detected secrets are masked in
    # prompt/response BEFORE they are stored locally or shipped to the collector.
    redact_secrets: bool = True
    # Mask PII/PHI/PCI (emails, SSNs, cards, IBANs, phones) before store/transmit.
    redact_pii: bool = True

    # Agent↔server channel security: when true, the agent refuses to send the
    # enroll token or agent key to a non-HTTPS collector (loopback exempt).
    require_https: bool = True

    # Data retention. 0 = keep forever; >0 = delete interactions older than N days.
    retention_days: int = 90

    # Claude CLI command on this machine
    claude_cli_cmd: str = "claude"

    # Device identity — set PW_DEVICE_NAME in .env or shell to override
    # Falls back to system hostname automatically
    device_name: str = ""
    org_name: str = "Organization"

    # Collector (central ingest). Agents on other machines connect here, so the
    # default binds all interfaces; it is gated by per-agent keys.
    collector_host: str = "0.0.0.0"
    collector_port: int = 9090

    # Dashboard
    dashboard_host: str = "127.0.0.1"   # use 0.0.0.0 to expose to the team (token required)
    dashboard_port: int = 9100
    # Shared access token for the dashboard. REQUIRED when dashboard_host is not
    # loopback. Empty = allowed only on loopback (local dev). Full RBAC: Phase 3.
    dashboard_token: str = ""


def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    s = Settings()
    if not s.device_name:
        # Auto-detect: prefer hostname, fall back to machine node name
        try:
            s.device_name = socket.gethostname().split(".")[0]
        except Exception:
            s.device_name = platform.node() or "unknown"
    return s


def get_machine_meta() -> dict:
    """Collect local machine details once at startup."""
    return {
        "hostname": socket.gethostname(),
        "os":       platform.system() + " " + platform.release(),
        "arch":     platform.machine(),
        "sys_user": _safe_user(),
    }


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
