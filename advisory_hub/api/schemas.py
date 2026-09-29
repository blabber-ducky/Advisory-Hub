"""Pydantic request/response models for `/api/v1`.

Pure serialization — no business logic. Nullability and field selection here
mirror what the ORM models actually guarantee (CLAUDE.md §2.2): a claim is
shown with its confidence/method, never presented as fact.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from ..core.models.enums import (
    AckChannel,
    AdvisoryStatus,
    AdvisoryType,
    ClaimSource,
    CredentialAuthType,
    EnrichmentStatus,
    ExtractionMethod,
    FlagKind,
    InventoryMode,
    InventorySourceKind,
    IocType,
    MatchConfidence,
    MatchMethod,
    RelationKind,
    ScanStatus,
    Severity,
    SyncStatus,
    TtpKind,
)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    short_code: str
    is_active: bool


class CveOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    found_in: list[str]
    cvss_v3_score: Decimal | None
    cvss_v3_vector: str | None
    cvss_v4_score: Decimal | None
    cvss_v4_vector: str | None
    nvd_description: str | None
    nvd_published_at: datetime | None
    enrichment_status: EnrichmentStatus


class IocOut(BaseModel):
    """`value` is deliberately absent — only the defanged form crosses the API,
    same as the UI. See CLAUDE.md §2.3."""

    model_config = ConfigDict(from_attributes=True)

    ioc_type: IocType
    ioc_type_raw: str | None
    defanged_value: str
    context: str | None


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    vendor: str | None
    product: str
    version_expression: str | None
    fixed_version: str | None
    source_of_claim: ClaimSource


class TtpOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: TtpKind
    value: str


class FlagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: FlagKind
    detail: dict[str, object] | None
    resolved_at: datetime | None


class AttachmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    content_type: str | None
    page_count: int | None
    extraction_method: ExtractionMethod | None


class AdvisorySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    external_ref: str | None
    source: SourceOut
    type: AdvisoryType
    type_confidence: Decimal | None
    severity: Severity | None
    status: AdvisoryStatus
    title: str
    received_at: datetime
    ack_due_at: datetime | None
    resolution_due_at: datetime | None
    acknowledged_at: datetime | None


class AdvisoryDetail(AdvisorySummary):
    description: str | None
    source_type_raw: str | None
    cvss_score: Decimal | None
    assignee_id: uuid.UUID | None
    upstream_reference: str | None
    published_at: datetime | None
    detected_on: date | None
    cves: list[CveOut]
    iocs: list[IocOut]
    products: list[ProductOut]
    ttps: list[TtpOut]
    flags: list[FlagOut]
    attachments: list[AttachmentOut]


class AdvisoryPage(BaseModel):
    items: list[AdvisorySummary]
    next_cursor: str | None


class AdvisoryPatch(BaseModel):
    """PATCH body. Only fields actually present in the JSON are applied —
    routers must read this with `model_dump(exclude_unset=True)`. Status is
    not settable here; see `StatusChangeRequest`."""

    assignee_id: uuid.UUID | None = None
    type: AdvisoryType | None = None
    severity: Severity | None = None


class CommentOut(BaseModel):
    """Built explicitly by the router, not via `from_attributes` — `author` is
    a `User | None` relationship, not a string, so it needs unwrapping."""

    id: uuid.UUID
    author_display_name: str | None
    body: str
    is_status_change: bool
    created_at: datetime


class CommentCreate(BaseModel):
    body: str = Field(min_length=1)


class StatusChangeRequest(BaseModel):
    to_status: AdvisoryStatus
    comment: str = Field(min_length=1)
    ack_channel: AckChannel | None = None


class StatusChangeOut(BaseModel):
    """Built explicitly by the router — see `CommentOut`."""

    id: uuid.UUID
    from_status: AdvisoryStatus | None
    to_status: AdvisoryStatus
    actor_display_name: str | None
    comment: CommentOut
    created_at: datetime


class RelatedAdvisoryOut(BaseModel):
    kind: RelationKind
    advisory: AdvisorySummary


# ─── Inventory sources (Phase 2a) ────────────────────────────────────────────


class InventorySourceOut(BaseModel):
    """Built explicitly by the router — `has_credential` is derived, not a
    real column, and `credential_id` itself never crosses the API (CLAUDE.md
    §2.3: write-only credentials, no exceptions)."""

    id: uuid.UUID
    name: str
    kind: InventorySourceKind
    mode: InventoryMode
    config: dict[str, object]
    has_credential: bool
    schedule_cron: str | None
    is_active: bool
    last_sync_at: datetime | None
    last_sync_status: SyncStatus
    last_sync_error: str | None
    created_at: datetime


class InventorySourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: InventorySourceKind
    config: dict[str, object] = Field(default_factory=dict)
    #: Write-only. Never echoed back — see `InventorySourceOut.has_credential`.
    credential: dict[str, str] | None = None
    credential_auth_type: CredentialAuthType | None = None
    schedule_cron: str | None = None


class InventorySourcePatch(BaseModel):
    """PATCH body. Only fields actually present in the JSON are applied —
    the router reads this with `model_dump(exclude_unset=True)`. `name` and
    `kind` are immutable after creation."""

    config: dict[str, object] | None = None
    credential: dict[str, str] | None = None
    credential_auth_type: CredentialAuthType | None = None
    schedule_cron: str | None = None
    is_active: bool | None = None


class ConnectionTestOut(BaseModel):
    ok: bool
    message: str


class SyncHistoryEntryOut(BaseModel):
    action: str
    actor_label: str | None
    detail: dict[str, object] | None
    created_at: datetime


# ─── CSV inventory ingest (Phase 2b) ─────────────────────────────────────────


class ParsedRowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    line_number: int
    vendor: str | None
    product: str
    version: str | None
    device_count: int
    kind: str


class RowErrorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    line_number: int
    message: str


class CsvPreviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    blob_id: uuid.UUID
    headers: list[str]
    mapping: dict[str, str | None]
    preview_rows: list[ParsedRowOut]
    errors: list[RowErrorOut]
    total_rows: int
    matched_row_count: int


class CsvCommitRequest(BaseModel):
    blob_id: uuid.UUID
    mapping: dict[str, str | None]


class InventorySnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    taken_at: datetime
    mode: InventoryMode
    device_count: int | None
    software_row_count: int
    is_latest: bool
    raw_file_blob_id: uuid.UUID | None


class ScanSnapshotChoiceOut(BaseModel):
    """One row per source's current `is_latest` snapshot — the picker the
    "Scan inventory" trigger offers."""

    model_config = ConfigDict(from_attributes=True)

    snapshot_id: uuid.UUID
    source_id: uuid.UUID
    source_name: str
    taken_at: datetime
    device_count: int | None
    software_row_count: int


class ScanTriggerRequest(BaseModel):
    #: Empty/omitted means "every active source's latest snapshot".
    snapshot_ids: list[uuid.UUID] = Field(default_factory=list)


class ScanMatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str | None
    snapshot_id: uuid.UUID
    vendor: str | None
    product: str
    matched_version: str
    affected_range: str
    device_count: int
    match_method: MatchMethod
    confidence: MatchConfidence
    rationale: str


class ScanCoverageGapOut(BaseModel):
    vendor: str
    product: str


class ScanRunOut(BaseModel):
    id: uuid.UUID
    advisory_id: uuid.UUID
    snapshot_ids: list[uuid.UUID]
    status: ScanStatus
    started_at: datetime | None
    finished_at: datetime | None
    match_count: int
    affected_device_count: int | None
    error: str | None
    matches: list[ScanMatchOut]
    coverage_gaps: list[ScanCoverageGapOut]


class ScanRunSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    snapshot_ids: list[uuid.UUID]
    status: ScanStatus
    started_at: datetime | None
    finished_at: datetime | None
    match_count: int
    affected_device_count: int | None


class VtLookupOut(BaseModel):
    """A cached or freshly-performed VirusTotal check — evidence, with its
    own provenance, never presented as a verdict this app made. `error` is
    populated only for `status == ERROR`."""

    model_config = ConfigDict(from_attributes=True)

    status: EnrichmentStatus
    checked_at: datetime | None
    malicious_count: int | None
    suspicious_count: int | None
    harmless_count: int | None
    undetected_count: int | None
    reputation: int | None
    last_analysis_at: datetime | None
    permalink: str | None
    error: str | None


class VtCheckRequest(BaseModel):
    force: bool = False
