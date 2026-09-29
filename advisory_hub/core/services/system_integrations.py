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

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ..models.enums import CredentialAuthType, SystemIntegrationKind
from ..models.inventory import IntegrationCredential
from ..models.system import SystemIntegration
from ..security.crypto import decrypt_credential, encrypt_credential
from .audit import Actor
from .audit import record as audit_record

__all__ = [
    "ResolvedCredential",
    "get_integration",
    "list_integrations",
    "resolve_credential",
    "set_api_key",
    "set_enabled",
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
    rows = {row.kind: row for row in db.scalars(select(SystemIntegration))}
    return {kind: rows.get(kind) for kind in SystemIntegrationKind}


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
