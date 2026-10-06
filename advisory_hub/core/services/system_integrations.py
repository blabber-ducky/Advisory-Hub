"""Admin-panel-configurable global integrations (NVD, VirusTotal).

Precedence, resolved fresh on every call — nothing is cached at import
time, so a change in the admin panel takes effect on the very next request,
no restart needed:

1. A `SystemIntegration` row exists and `enabled = False` → the integration
   is off, full stop, regardless of any env var. An admin explicitly
   turning it off must actually turn it off.
2. A `SystemIntegration` row exists, `enabled = True`, and it has a
   credential → use that (decrypted) key.
3. A `SystemIntegration` row exists, `enabled = True`, but has no
   credential yet (admin turned it on without setting a key) → fall back
   to the env var, same as if there were no row at all.
4. No `SystemIntegration` row exists → the original, pre-admin-panel
   behaviour: `settings.nvd_enabled`/`nvd_api_key`,
   `settings.vt_enabled`/`vt_api_key`. Every existing env-var-only
   deployment keeps working exactly as before with zero configuration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ..models.enums import API_KEY_KINDS, CredentialAuthType, SystemIntegrationKind
from ..models.inventory import IntegrationCredential
from ..models.system import SystemIntegration
from ..security.crypto import decrypt_credential, encrypt_credential
from .audit import Actor
from .audit import record as audit_record

__all__ = [
    "EntraApp",
    "EntraSettingsError",
    "ResolvedCredential",
    "entra_app",
    "entra_client_secret",
    "get_integration",
    "list_integrations",
    "resolve_credential",
    "save_entra_settings",
    "set_api_key",
    "set_enabled",
    "set_entra_enabled",
]


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    enabled: bool
    api_key: str | None
    #: Where the key/enabled state actually came from — shown in the admin
    #: panel so "using the environment variable" vs. "configured here" is
    #: never ambiguous.
    source: str  # "admin_panel" | "environment" | "none"


def get_integration(db: DbSession, kind: SystemIntegrationKind) -> SystemIntegration | None:
    return db.scalar(select(SystemIntegration).where(SystemIntegration.kind == kind))


def list_integrations(db: DbSession) -> dict[SystemIntegrationKind, SystemIntegration | None]:
    """The API-key integrations (NVD, VirusTotal) — see `API_KEY_KINDS`."""
    rows = {row.kind: row for row in db.scalars(select(SystemIntegration))}
    return {kind: rows.get(kind) for kind in API_KEY_KINDS}


def _env_default(kind: SystemIntegrationKind) -> tuple[bool, str | None]:
    if kind is SystemIntegrationKind.NVD:
        return settings.nvd_enabled, settings.nvd_api_key
    return settings.vt_enabled, settings.vt_api_key


def resolve_credential(db: DbSession, kind: SystemIntegrationKind) -> ResolvedCredential:
    row = get_integration(db, kind)
    if row is not None:
        if not row.enabled:
            return ResolvedCredential(enabled=False, api_key=None, source="admin_panel")
        if row.credential is not None:
            payload = decrypt_credential(row.credential.ciphertext)
            return ResolvedCredential(
                enabled=True, api_key=payload.get("api_key"), source="admin_panel"
            )
    env_enabled, env_key = _env_default(kind)
    if env_key:
        return ResolvedCredential(enabled=env_enabled, api_key=env_key, source="environment")
    return ResolvedCredential(enabled=env_enabled, api_key=None, source="none")


def set_api_key(
    db: DbSession, kind: SystemIntegrationKind, *, api_key: str, actor: Actor
) -> SystemIntegration:
    """Encrypts and stores a new key, enabling the integration. The key is
    never returned by this function or read back by any caller — write-only,
    same discipline as inventory-source credentials (CLAUDE.md §2.3)."""
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("api_key is required")

    row = get_integration(db, kind)
    credential = IntegrationCredential(
        auth_type=CredentialAuthType.API_KEY, ciphertext=encrypt_credential({"api_key": api_key})
    )
    db.add(credential)
    db.flush()

    if row is None:
        row = SystemIntegration(kind=kind, enabled=True, credential_id=credential.id)
        db.add(row)
    else:
        row.credential_id = credential.id
        row.enabled = True
    row.updated_by_id = actor.user_id
    db.flush()

    audit_record(
        db,
        actor=actor,
        action="system_integration.key_set",
        entity_type="system_integration",
        entity_id=row.id,
        detail={"kind": kind.value},
    )
    db.flush()
    return row


def set_enabled(
    db: DbSession, kind: SystemIntegrationKind, *, enabled: bool, actor: Actor
) -> SystemIntegration:
    row = get_integration(db, kind)
    if row is None:
        row = SystemIntegration(kind=kind, enabled=enabled)
        db.add(row)
    else:
        row.enabled = enabled
    row.updated_by_id = actor.user_id
    db.flush()

    audit_record(
        db,
        actor=actor,
        action="system_integration.enabled_changed",
        entity_type="system_integration",
        entity_id=row.id,
        detail={"kind": kind.value, "enabled": enabled},
    )
    db.flush()
    return row


# ─── Entra ID apps (sign-in, mailbox sync) — D-049 ────────────────────────────
#
# Each is its own app registration: a leaked sign-in secret must not be able
# to read mail. Non-secret settings live in `SystemIntegration.config`; the
# client secret only in the encrypted credential, never returned.

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
ENTRA_KINDS = (SystemIntegrationKind.ENTRA_SSO, SystemIntegrationKind.MAILBOX_SYNC)

#: Non-secret settings each Entra app accepts.
ENTRA_CONFIG_KEYS: dict[SystemIntegrationKind, tuple[str, ...]] = {
    SystemIntegrationKind.ENTRA_SSO: ("tenant_id", "client_id"),
    SystemIntegrationKind.MAILBOX_SYNC: (
        "tenant_id",
        "client_id",
        "mailbox",
        "folder",
        "poll_seconds",
    ),
}
MAILBOX_POLL_DEFAULT = 120
MAILBOX_POLL_MIN = 60


class EntraSettingsError(ValueError):
    """Invalid or incomplete settings; the message is safe to show an admin."""


@dataclass(frozen=True, slots=True)
class EntraApp:
    kind: SystemIntegrationKind
    enabled: bool
    config: dict[str, str]
    has_secret: bool
    row: SystemIntegration | None

    @property
    def tenant_id(self) -> str:
        return self.config.get("tenant_id", "")

    @property
    def client_id(self) -> str:
        return self.config.get("client_id", "")

    def missing(self) -> list[str]:
        """What still has to be set before it can be enabled."""
        gaps = [
            k
            for k in ENTRA_CONFIG_KEYS[self.kind]
            if k != "poll_seconds" and not self.config.get(k)
        ]
        if not self.has_secret:
            gaps.append("client_secret")
        if self.kind is SystemIntegrationKind.ENTRA_SSO and not settings.public_base_url:
            gaps.append("PUBLIC_BASE_URL (environment)")
        return gaps


def entra_app(db: DbSession, kind: SystemIntegrationKind) -> EntraApp:
    """Settings for one Entra app. Off unless a row says enabled — there is
    no environment-variable fallback for these."""
    if kind not in ENTRA_KINDS:
        raise ValueError(kind)
    row = get_integration(db, kind)
    config = {k: str(v) for k, v in (row.config if row else {}).items()}
    return EntraApp(
        kind=kind,
        enabled=bool(row and row.enabled),
        config=config,
        has_secret=bool(row and row.credential_id),
        row=row,
    )


def entra_client_secret(db: DbSession, kind: SystemIntegrationKind) -> str | None:
    """Decrypted client secret — for the outbound token request only, never
    for display or any API response."""
    row = get_integration(db, kind)
    if row is None or row.credential is None:
        return None
    return decrypt_credential(row.credential.ciphertext).get("client_secret")


def save_entra_settings(
    db: DbSession,
    kind: SystemIntegrationKind,
    *,
    config: dict[str, str],
    client_secret: str | None,
    actor: Actor,
) -> EntraApp:
    """Validate and store settings; a blank ``client_secret`` keeps the
    current one. Changing anything that identifies the app or mailbox while
    enabled is allowed — it applies on the next sign-in / sync cycle."""
    if kind not in ENTRA_KINDS:
        raise ValueError(kind)
    cleaned = {k: (config.get(k) or "").strip() for k in ENTRA_CONFIG_KEYS[kind]}
    for key in ("tenant_id", "client_id"):
        if cleaned[key] and not _GUID.match(cleaned[key]):
            label = "Tenant ID" if key == "tenant_id" else "Client (application) ID"
            raise EntraSettingsError(f"{label} must be a GUID, as shown in the Entra portal.")
    if kind is SystemIntegrationKind.MAILBOX_SYNC:
        if cleaned["mailbox"] and not re.match(
            r"^[^@\s/]+@[^@\s/]+\.[^@\s/]+$", cleaned["mailbox"]
        ):
            raise EntraSettingsError("Mailbox must be an email address (the mailbox's UPN).")
        cleaned["folder"] = "/".join(p.strip() for p in cleaned["folder"].split("/") if p.strip())
        poll = cleaned["poll_seconds"] or str(MAILBOX_POLL_DEFAULT)
        if not poll.isdigit() or int(poll) < MAILBOX_POLL_MIN:
            raise EntraSettingsError(f"Poll interval must be at least {MAILBOX_POLL_MIN} seconds.")
        cleaned["poll_seconds"] = poll

    row = get_integration(db, kind)
    if row is None:
        row = SystemIntegration(kind=kind, enabled=False, config={})
        db.add(row)
    previous = {k: str(v) for k, v in (row.config or {}).items()}
    row.config = dict(cleaned)
    secret = (client_secret or "").strip()
    if secret:
        credential = IntegrationCredential(
            auth_type=CredentialAuthType.OAUTH_CLIENT_CREDENTIALS,
            ciphertext=encrypt_credential({"client_secret": secret}),
        )
        db.add(credential)
        db.flush()
        row.credential_id = credential.id
    row.updated_by_id = actor.user_id
    db.flush()

    changed = sorted(k for k in cleaned if previous.get(k, "") != cleaned[k])
    audit_record(
        db,
        actor=actor,
        action="system_integration.config_set",
        entity_type="system_integration",
        entity_id=row.id,
        # Non-secret values only; the secret is recorded as "rotated", never shown.
        detail={
            "kind": kind.value,
            "changed": {k: cleaned[k] for k in changed},
            "client_secret": "rotated" if secret else "unchanged",
        },
    )
    db.flush()
    app = entra_app(db, kind)
    if app.enabled and app.missing():
        raise EntraSettingsError("Can't leave it enabled without: " + ", ".join(app.missing()))
    return app


def set_entra_enabled(
    db: DbSession, kind: SystemIntegrationKind, *, enabled: bool, actor: Actor
) -> EntraApp:
    app = entra_app(db, kind)
    if enabled and app.missing():
        raise EntraSettingsError("Set these first: " + ", ".join(app.missing()))
    set_enabled(db, kind, enabled=enabled, actor=actor)
    return entra_app(db, kind)
