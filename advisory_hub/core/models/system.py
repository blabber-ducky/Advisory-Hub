"""App-wide integration settings, configurable from the admin panel.

Distinct from `core.models.inventory.InventorySource` — those are a
user-creatable list of inventory feeds; a `SystemIntegration` is a
singleton (at most one row per `SystemIntegrationKind`) for the handful of
global, app-wide API integrations (NVD, VirusTotal) that previously could
only be configured via environment variables and a container restart.

Reuses `IntegrationCredential`/`core.security.crypto` — the same
Fernet-encrypted, write-only-from-every-caller's-perspective credential
storage the inventory sources already use (CLAUDE.md §2.3). No new
encryption mechanism was worth building for the same shape of secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKey, enum_column
from .enums import SystemIntegrationKind
from .inventory import IntegrationCredential

if TYPE_CHECKING:
    from .user import User


class SystemIntegration(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "system_integration"

    kind: Mapped[SystemIntegrationKind] = enum_column(SystemIntegrationKind, nullable=False)
    #: An admin explicitly turning this off overrides any env-var fallback —
    #: see core.services.system_integrations.resolve_credential().
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Non-secret settings (tenant/client IDs, mailbox, folder). Secrets live
    #: only in the encrypted `credential`.
    config: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("integration_credential.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )

    credential: Mapped[IntegrationCredential | None] = relationship()
    updated_by: Mapped[User | None] = relationship()

    __table_args__ = (UniqueConstraint("kind", name="uq_system_integration_kind"),)


class MailboxSyncState(Base, UUIDPrimaryKey, TimestampMixin):
    """Where mailbox sync has got to — one row. Reset whenever the mailbox or
    folder setting changes. See core.services.mailbox_sync."""

    __tablename__ = "mailbox_sync_state"

    #: "<mailbox>|<folder path>" this state belongs to; a mismatch resets it.
    target: Mapped[str] = mapped_column(Text, nullable=False)
    folder_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Graph `@odata.deltaLink` — the next cycle fetches only changes since.
    delta_link: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(Text, nullable=True)  # ok | error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    skipped_too_large_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
