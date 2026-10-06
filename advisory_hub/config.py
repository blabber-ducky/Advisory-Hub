"""Application configuration, loaded from the environment.

Every setting here must also appear in ``.env.example`` and in
``docs/operations.md`` §3 — see CLAUDE.md §2.1.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # ─── Core ────────────────────────────────────────────────────────────────
    database_url: str = "postgresql+psycopg://advisory_hub:advisory_hub@localhost:5432/advisory_hub"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "dev-only-insecure-key-change-me"  # noqa: S105 — placeholder; startup refuses it in production
    environment: Literal["development", "production", "test"] = "production"

    # ─── Storage ─────────────────────────────────────────────────────────────
    blob_root: Path = Path("/data/blobs")
    inbox_path: Path = Path("/data/inbox")
    processing_path: Path = Path("/data/processing")
    archive_path: Path = Path("/data/archive")
    failed_path: Path = Path("/data/failed")

    # ─── Ingestion (Phase 1) ─────────────────────────────────────────────────
    inbox_poll_seconds: int = 30
    #: Caps for .eml/.msg files uploaded from the tracker page (per file / per upload).
    upload_max_bytes: int = 52_428_800  # 50 MB
    upload_max_files: int = 20
    pdf_max_bytes: int = 52_428_800
    pdf_max_pages: int = 500
    pdf_timeout_seconds: int = 120
    ocr_enabled: bool = False

    # ─── Enrichment (Phase 1) ────────────────────────────────────────────────
    nvd_enabled: bool = True
    nvd_api_key: str | None = None

    # ─── VirusTotal IOC lookups ───────────────────────────────────────────────
    #: Analyst-triggered per-IOC checks, not an automatic sweep — see
    #: docs/decisions.md. Unset key means the "Check on VirusTotal" action is
    #: still visible but returns a clear "not configured" error, never
    #: silently hidden.
    vt_enabled: bool = True
    vt_api_key: str | None = None

    # ─── Integration credentials (Phase 2) ───────────────────────────────────
    fernet_key: str | None = None
    fernet_key_previous: str | None = None
    outbound_allowlist: str = ""

    # ─── Inventory CSV ingest (Phase 2b) ─────────────────────────────────────
    csv_max_bytes: int = 20_971_520  # 20 MB
    csv_max_rows: int = 200_000

    # ─── Inventory API sync (Phase 2c) ───────────────────────────────────────
    inventory_sync_poll_seconds: int = 300

    # ─── Daily status export (backup) ────────────────────────────────────────
    #: The worker writes every advisory's status as an importable CSV here on
    #: this cron schedule (UTC), keeping the last ``status_export_keep_days``
    #: files. See core.services.status_export and docs/operations.md §4.
    status_export_enabled: bool = True
    status_export_cron: str = "0 2 * * *"
    status_export_dir: Path = Path("/data/exports")
    status_export_keep_days: int = 30

    # ─── HTTPS served by the app itself (no proxy) ───────────────────────────
    #: When on, ``python -m advisory_hub.serve`` serves HTTPS on the app port,
    #: using tls_cert_file/tls_key_file if both exist, or generating a
    #: self-signed certificate for ``tls_hostnames`` if neither does. See
    #: core.security.tls and docs/operations.md §7.
    https_enabled: bool = False
    tls_cert_file: Path = Path("/data/certs/server.crt")
    tls_key_file: Path = Path("/data/certs/server.key")
    #: Comma-separated DNS names / IPs users browse to (e.g. the NAT address).
    #: Goes into a generated certificate; localhost and 127.0.0.1 are added.
    tls_hostnames: str = ""

    # ─── Web ─────────────────────────────────────────────────────────────────
    session_cookie_secure: bool = True
    session_max_age_seconds: int = 43_200
    #: The address users reach the app at, e.g. https://advisoryhub.example —
    #: required for Microsoft sign-in: the redirect URI registered in Entra is
    #: <public_base_url>/auth/entra/callback. Deliberately configured, never
    #: derived from request headers (spoofable behind a proxy). D-049.
    public_base_url: str = ""

    # ─── Observability ───────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    @field_validator("secret_key")
    @classmethod
    def _reject_default_secret_in_production(cls, v: str, info: object) -> str:
        # Deliberately not raising here: config is imported by tooling (alembic,
        # CLI) where a placeholder is harmless. The hard check happens at app
        # startup — see advisory_hub.main.create_app.
        return v

    @property
    def allowlisted_hosts(self) -> tuple[str, ...]:
        return tuple(h.strip().lower() for h in self.outbound_allowlist.split(",") if h.strip())

    @property
    def tls_hostname_list(self) -> list[str]:
        return [h.strip() for h in self.tls_hostnames.split(",") if h.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def data_paths(self) -> tuple[Path, ...]:
        return (
            self.blob_root,
            self.inbox_path,
            self.processing_path,
            self.archive_path,
            self.failed_path,
        )


INSECURE_SECRET_KEYS = frozenset(
    {
        "dev-only-insecure-key-change-me",
        "CHANGE_ME_dev_only_do_not_use_in_production",
        "CHANGE_ME",
        "",
    }
)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


class _SettingsProxy:
    """Lazy proxy that always delegates to the current cached ``Settings``.

    ``from .config import settings`` binds whatever object exists at import
    time. If that were a concrete ``Settings`` instance, every importing module
    would hold a permanent snapshot and ``get_settings.cache_clear()`` could
    never take effect — which breaks test isolation and would block any future
    config reload. The proxy defers every attribute lookup instead.
    """

    __slots__ = ()

    def __getattr__(self, name: str) -> object:
        return getattr(get_settings(), name)

    def __repr__(self) -> str:
        return repr(get_settings())


settings: Settings = _SettingsProxy()  # type: ignore[assignment]
