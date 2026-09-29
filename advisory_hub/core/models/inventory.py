"""Inventory sources, snapshots, and scan results — Phase 2.

See docs/inventory-matching.md for the design and docs/data-model.md for the
schema this mirrors exactly. `integration_credential.ciphertext` is the only
column that ever holds secret material, and it is never read back out
through any service that returns to a caller — see CLAUDE.md §2.3.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .advisory import Advisory, Blob
from .base import Base, TimestampMixin, UUIDPrimaryKey, enum_column
from .enums import (
    CredentialAuthType,
    InventoryItemKind,
    InventoryMode,
    InventorySourceKind,
    MatchConfidence,
    MatchMethod,
    ScanStatus,
    SyncStatus,
)

if TYPE_CHECKING:
    from .user import User


class IntegrationCredential(Base, UUIDPrimaryKey, TimestampMixin):
    """Never returned by any API — write-only from the caller's perspective.
    See core.security.crypto for the Fernet encrypt/decrypt helpers."""

    __tablename__ = "integration_credential"

    auth_type: Mapped[CredentialAuthType] = enum_column(CredentialAuthType, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InventorySource(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "inventory_source"

    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    kind: Mapped[InventorySourceKind] = enum_column(InventorySourceKind, nullable=False)
    mode: Mapped[InventoryMode] = enum_column(InventoryMode, nullable=False)
    #: Non-secret: base URL, tenant/subscription IDs, column mappings.
    config: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("integration_credential.id", ondelete="SET NULL"),
        nullable=True,
    )
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[SyncStatus] = enum_column(
        SyncStatus, nullable=False, default=SyncStatus.NEVER
    )
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    credential: Mapped[IntegrationCredential | None] = relationship()


class InventorySnapshot(Base, UUIDPrimaryKey, TimestampMixin):
    """Immutable. Scans always run against a named snapshot so results stay
    reproducible even after the next sync."""

    __tablename__ = "inventory_snapshot"

    source_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("inventory_source.id", ondelete="CASCADE"), index=True
    )
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mode: Mapped[InventoryMode] = enum_column(InventoryMode, nullable=False)
    device_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    software_row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    raw_file_blob_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("blob.id", ondelete="SET NULL"), nullable=True
    )
    is_latest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    source: Mapped[InventorySource] = relationship()
    uploaded_by: Mapped[User | None] = relationship()
    raw_file: Mapped[Blob | None] = relationship()

    __table_args__ = (
        # Partial unique index: at most one is_latest=true row per source.
        Index(
            "uq_inventory_snapshot_latest_per_source",
            "source_id",
            unique=True,
            postgresql_where=text("is_latest"),
        ),
    )


class InventorySoftware(Base, UUIDPrimaryKey, TimestampMixin):
    """The aggregate view — "how many endpoints run product X version Y".
    Populated by both CSV and API sources."""

    __tablename__ = "inventory_software"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("inventory_snapshot.id", ondelete="CASCADE"), index=True
    )
    vendor_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    product_raw: Mapped[str] = mapped_column(Text, nullable=False)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    product: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    version_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_normalized: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_parts: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    kind: Mapped[InventoryItemKind] = enum_column(
        InventoryItemKind, nullable=False, default=InventoryItemKind.SOFTWARE
    )
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    snapshot: Mapped[InventorySnapshot] = relationship()

    __table_args__ = (
        Index("ix_inventory_software_snapshot_vendor_product", "snapshot_id", "vendor", "product"),
    )


class InventoryDevice(Base, UUIDPrimaryKey, TimestampMixin):
    """`DETAILED` (API) sources only."""

    __tablename__ = "inventory_device"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("inventory_snapshot.id", ondelete="CASCADE"), index=True
    )
    #: Source-native ID — the thing you hand to ops.
    device_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Owner, OU, location, tags — whatever the source gives.
    attributes: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)

    snapshot: Mapped[InventorySnapshot] = relationship()


class InventoryDeviceSoftware(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "inventory_device_software"

    device_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("inventory_device.id", ondelete="CASCADE"), index=True
    )
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    version_normalized: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_parts: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)

    device: Mapped[InventoryDevice] = relationship()


class VendorAlias(Base, UUIDPrimaryKey, TimestampMixin):
    """Maps the ten ways every vendor writes its own name onto one canonical
    form. Seeded, then extended by admins as mismatches surface."""

    __tablename__ = "vendor_alias"

    alias: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    canonical_vendor: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    canonical_product: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanRun(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "scan_run"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    initiated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    #: Exactly which snapshots were scanned — so a re-run is reproducible.
    snapshot_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(PgUUID(as_uuid=True)), nullable=False, default=list
    )
    status: Mapped[ScanStatus] = enum_column(ScanStatus, nullable=False, default=ScanStatus.QUEUED)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    affected_device_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    advisory: Mapped[Advisory] = relationship()
    initiated_by: Mapped[User | None] = relationship()
    matches: Mapped[list[ScanMatch]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class ScanMatch(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "scan_match"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_run.id", ondelete="CASCADE"), index=True
    )
    #: Null for non-CVE product matches.
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("inventory_snapshot.id", ondelete="CASCADE")
    )
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    matched_version: Mapped[str] = mapped_column(Text, nullable=False)
    affected_range: Mapped[str] = mapped_column(Text, nullable=False)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: DETAILED sources only — capped; the full list is paginated separately.
    device_ids: Mapped[list[uuid.UUID] | None] = mapped_column(
        ARRAY(PgUUID(as_uuid=True)), nullable=True
    )
    match_method: Mapped[MatchMethod] = enum_column(MatchMethod, nullable=False)
    confidence: Mapped[MatchConfidence] = enum_column(MatchConfidence, nullable=False, index=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    scan_run: Mapped[ScanRun] = relationship(back_populates="matches")
    snapshot: Mapped[InventorySnapshot] = relationship()
