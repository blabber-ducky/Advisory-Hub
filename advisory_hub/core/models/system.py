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
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, UniqueConstraint
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
