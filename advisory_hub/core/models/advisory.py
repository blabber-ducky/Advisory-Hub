"""Advisories and everything derived from them.

Anything the parser inferred is stored with its method/provenance and surfaced
as evidence, not as fact — see CLAUDE.md §2.2.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDPrimaryKey, enum_column
from .enums import (
    AckChannel,
    AdvisoryStatus,
    AdvisoryType,
    ClaimSource,
    EnrichmentStatus,
    ExtractionMethod,
    FlagKind,
    IocRemediationStatus,
    IocType,
    Priority,
    RelationDetectedBy,
    RelationKind,
    Severity,
    SourceMethod,
    TtpKind,
)

if TYPE_CHECKING:
    from .user import User


class Blob(Base, UUIDPrimaryKey, TimestampMixin):
    """Content-addressed immutable storage index. Bytes live on the volume."""

    __tablename__ = "blob"

    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Sniffed, never trusted from the email's own Content-Type.
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    original_filename: Mapped[str | None] = mapped_column(Text, nullable=True)


class Source(Base, UUIDPrimaryKey, TimestampMixin):
    """A regulator or issuing body."""

    __tablename__ = "source"

    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    short_code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    #: Sender addresses/domains mapped to this source, most specific first.
    sender_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    default_type_hint: Mapped[AdvisoryType | None] = enum_column(AdvisoryType, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Advisory(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "advisory"

    source_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("source.id", ondelete="RESTRICT"), index=True
    )
    #: How ``source_id`` was decided. MANUAL survives re-parsing.
    source_method: Mapped[SourceMethod] = enum_column(
        SourceMethod, nullable=False, default=SourceMethod.SENDER
    )
    #: The regulator's own advisory number, e.g. "DOH-2026550".
    external_ref: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    type: Mapped[AdvisoryType] = enum_column(AdvisoryType, nullable=False)
    type_confidence: Mapped[Decimal | None] = mapped_column(Numeric(3, 2), nullable=True)
    #: The regulator's own Type: value, verbatim. Unreliable — see D-017.
    source_type_raw: Mapped[str | None] = mapped_column(String(64), nullable=True)

    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[Severity | None] = enum_column(Severity, nullable=True, index=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)

    status: Mapped[AdvisoryStatus] = enum_column(
        AdvisoryStatus, nullable=False, default=AdvisoryStatus.NEW, index=True
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )

    # ─── SLA: two clocks, both starting at received_at. See D-018. ───────────
    priority: Mapped[Priority | None] = enum_column(Priority, nullable=True, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    ack_channel: Mapped[AckChannel | None] = enum_column(AckChannel, nullable=True)
    ack_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    resolution_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # ─── Provenance ──────────────────────────────────────────────────────────
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    upstream_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: sha256 of the raw message — the idempotency key.
    dedupe_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    message_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    #: Normalised title, for re-issue detection. See D-020.
    title_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False, default="0")
    raw_email_blob_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("blob.id", ondelete="RESTRICT"), nullable=True
    )

    search_vector: Mapped[str | None] = mapped_column(TSVECTOR, nullable=True)

    source: Mapped[Source] = relationship()
    attachments: Mapped[list[AdvisoryAttachment]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    cves: Mapped[list[AdvisoryCve]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    iocs: Mapped[list[AdvisoryIoc]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    products: Mapped[list[AdvisoryProduct]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    ttps: Mapped[list[AdvisoryTtp]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    flags: Mapped[list[AdvisoryFlag]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_advisory_status_severity", "status", "severity"),
        Index("ix_advisory_source_received", "source_id", "received_at"),
        Index("ix_advisory_search_vector", "search_vector", postgresql_using="gin"),
    )


class AdvisoryAttachment(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "advisory_attachment"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    blob_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("blob.id", ondelete="RESTRICT")
    )
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extracted_text_blob_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("blob.id", ondelete="SET NULL"), nullable=True
    )
    extraction_method: Mapped[ExtractionMethod | None] = enum_column(
        ExtractionMethod, nullable=True
    )
    extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    advisory: Mapped[Advisory] = relationship(back_populates="attachments")


class AdvisoryCve(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "advisory_cve"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    #: Provenance: any of SUBJECT, EMAIL_BODY, PDF. The union rule needs this.
    found_in: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    cvss_v3_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    #: Unbounded: a CVSS 4.0 vector carrying threat and environmental metrics
    #: runs past 170 characters, and NVD emits exactly that. A bounded column
    #: here failed on live data.
    cvss_v3_vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_v4_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_v4_vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    nvd_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    nvd_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    enrichment_status: Mapped[EnrichmentStatus] = enum_column(
        EnrichmentStatus, nullable=False, default=EnrichmentStatus.PENDING, index=True
    )
    last_enriched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    advisory: Mapped[Advisory] = relationship(back_populates="cves")

    __table_args__ = (UniqueConstraint("advisory_id", "cve_id"),)


class CveCpe(Base, UUIDPrimaryKey, TimestampMixin):
    """NVD CPE configuration data — keyed by CVE, shared across advisories.

    This is what makes inventory matching accurate rather than string-guessing.
    """

    __tablename__ = "cve_cpe"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    cpe_uri: Mapped[str] = mapped_column(Text, nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    product: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    version_start: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_start_inclusive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version_end: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_end_inclusive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("cve_id", "cpe_uri", "version_start", "version_end"),
        Index("ix_cve_cpe_vendor_product", "vendor", "product"),
    )


class AdvisoryIoc(Base, UUIDPrimaryKey, TimestampMixin):
    """An indicator. ``defanged_value`` is what every surface renders."""

    __tablename__ = "advisory_ioc"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    ioc_type: Mapped[IocType] = enum_column(IocType, nullable=False, index=True)
    #: Raw label from the regulator when it didn't map to the enum.
    ioc_type_raw: Mapped[str | None] = mapped_column(String(120), nullable=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    defanged_value: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_page: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: PDF_TABLE, CSV_SIDECAR, XLSX_SIDECAR, REGEX_FALLBACK
    extraction_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: `None` = "not manually overridden — follow the advisory's own
    #: status" (see `ADVISORY_STATUS_TO_IOC_STATUS`). A set value is an
    #: explicit per-IOC override. See `core.services.iocs.effective_status()`.
    remediation_status: Mapped[IocRemediationStatus | None] = enum_column(
        IocRemediationStatus, nullable=True
    )

    advisory: Mapped[Advisory] = relationship(back_populates="iocs")

    __table_args__ = (UniqueConstraint("advisory_id", "ioc_type", "value"),)


class AdvisoryProduct(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "advisory_product"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    vendor: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    product: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    #: Raw, as written: "< 17.0.9", "Builds below 16.0.5561.1001", "R81.10".
    version_expression: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: `none_as_null=True` — without it, SQLAlchemy stores a Python `None`
    #: as a literal JSON `null` (`'null'::jsonb`), not a true SQL `NULL`.
    #: The ORM read path masks this (JSON `null` deserialises back to
    #: `None`), but any SQL-level `IS NOT NULL` filter would then wrongly
    #: match every row, parsed or not — caught only by directly inspecting
    #: the real ah-test corpus after a live reparse, not by unit tests
    #: (which only ever read through the ORM). See D-033.
    parsed_range: Mapped[dict[str, object] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    fixed_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_of_claim: Mapped[ClaimSource] = enum_column(ClaimSource, nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="products")


class AdvisoryTtp(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "advisory_ttp"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[TtpKind] = enum_column(TtpKind, nullable=False)
    value: Mapped[str] = mapped_column(String(200), nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="ttps")

    __table_args__ = (UniqueConstraint("advisory_id", "kind", "value"),)


class AdvisoryFlag(Base, UUIDPrimaryKey, TimestampMixin):
    """Cross-validation findings. Detect regulator data errors; never silently
    correct them — see D-019."""

    __tablename__ = "advisory_flag"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[FlagKind] = enum_column(FlagKind, nullable=False, index=True)
    #: Both conflicting values, so an analyst can judge for themselves.
    detail: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )

    advisory: Mapped[Advisory] = relationship(back_populates="flags")


class AdvisoryTicket(Base, UUIDPrimaryKey, TimestampMixin):
    """A ticket raised in an ITSM tool for this advisory (D-050). Link only:
    the ticket's workflow lives in the ITSM tool."""

    __tablename__ = "advisory_ticket"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    system: Mapped[str] = mapped_column(String(32), nullable=False)  # "IVANTI"
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "ServiceReq#"
    number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rec_id: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: The classification the analyst chose, as sent.
    service: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    subcategory: Mapped[str] = mapped_column(Text, nullable=False)
    team: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    attachment_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    #: Set when the ticket was created but something after it failed
    #: (e.g. attaching the PDF).
    warning: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by: Mapped[User | None] = relationship()


class RelatedAdvisory(Base, UUIDPrimaryKey, TimestampMixin):
    """Links re-issues. Never auto-merges — see D-020."""

    __tablename__ = "related_advisory"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    related_advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[RelationKind] = enum_column(RelationKind, nullable=False)
    detected_by: Mapped[RelationDetectedBy] = enum_column(RelationDetectedBy, nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(3, 2), nullable=True)

    __table_args__ = (
        UniqueConstraint("advisory_id", "related_advisory_id", "kind"),
        CheckConstraint("advisory_id <> related_advisory_id", name="no_self_relation"),
    )


class Comment(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "comment"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_status_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    author: Mapped[User | None] = relationship()

    __table_args__ = (
        # Layer 1 of the mandatory-comment rule — see D-006.
        CheckConstraint("length(btrim(body)) > 0", name="body_not_blank"),
    )


class StatusChange(Base, UUIDPrimaryKey, TimestampMixin):
    """The audit trail for status transitions.

    ``comment_id`` is NOT NULL: the schema itself enforces the mandatory
    comment, so no future caller can regress it. See D-006.
    """

    __tablename__ = "status_change"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("advisory.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[AdvisoryStatus | None] = enum_column(AdvisoryStatus, nullable=True)
    to_status: Mapped[AdvisoryStatus] = enum_column(AdvisoryStatus, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    comment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("comment.id", ondelete="RESTRICT"), nullable=False
    )

    comment: Mapped[Comment] = relationship()
    actor: Mapped[User | None] = relationship()


class VtLookup(Base, UUIDPrimaryKey, TimestampMixin):
    """A cached VirusTotal reputation check for one IOC value.

    Keyed globally by ``(ioc_type, value)``, not per ``advisory_ioc`` row —
    the same indicator often appears across several advisories (a shared
    campaign infrastructure IP, a reused C2 domain), and the check result is
    a property of the *value*, not of any one advisory's citation of it. See
    CLAUDE.md §2.2 — this is enrichment evidence, displayed with its own
    provenance, never presented as a verdict the app itself made.
    """

    __tablename__ = "vt_lookup"

    ioc_type: Mapped[IocType] = enum_column(IocType, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[EnrichmentStatus] = enum_column(
        EnrichmentStatus, nullable=False, default=EnrichmentStatus.PENDING
    )
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    checked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user_account.id", ondelete="SET NULL"), nullable=True
    )
    malicious_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    suspicious_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    harmless_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    undetected_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reputation: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: VT's own timestamp for when its engines last scanned this value —
    #: distinct from `checked_at`, which is when *we* last asked.
    last_analysis_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    permalink: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    checked_by: Mapped[User | None] = relationship()

    __table_args__ = (UniqueConstraint("ioc_type", "value", name="uq_vt_lookup_type_value"),)
