"""Persist a parsed advisory.

The single write path for ingestion. Everything happens in one transaction, so
a partially-ingested advisory can never be observed. Re-ingesting the same
message updates rather than duplicates (CLAUDE.md §2.2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ...ingest.parser import ParsedAdvisory
from ..models.advisory import (
    Advisory,
    AdvisoryAttachment,
    AdvisoryCve,
    AdvisoryFlag,
    AdvisoryIoc,
    AdvisoryProduct,
    AdvisoryTtp,
    Blob,
    RelatedAdvisory,
)
from ..models.base import utcnow
from ..models.enums import (
    SLA_HOURS,
    AdvisoryStatus,
    EnrichmentStatus,
    FlagKind,
    Priority,
    RelationDetectedBy,
    RelationKind,
)
from ..storage.blobs import BlobStore
from .audit import Actor, record
from .sources import resolve_source, unknown_sender_detail

#: Window for spotting a re-issue under a new reference number (D-020).
REISSUE_WINDOW = timedelta(days=14)


@dataclass(slots=True)
class IngestResult:
    advisory: Advisory | None
    created: bool
    duplicate: bool = False
    reason: str | None = None

    @property
    def advisory_id(self) -> uuid.UUID | None:
        return self.advisory.id if self.advisory else None


def ingest_parsed_advisory(
    db: DbSession,
    parsed: ParsedAdvisory,
    blobs: BlobStore,
    *,
    actor: Actor | None = None,
) -> IngestResult:
    """Persist a parsed advisory. Idempotent on the raw-message hash."""
    actor = actor or Actor.system("ingest")
    message = parsed.message

    existing = db.scalar(select(Advisory).where(Advisory.dedupe_hash == message.dedupe_hash))
    if existing is not None:
        return IngestResult(
            advisory=existing, created=False, duplicate=True, reason="DUPLICATE_HASH"
        )

    resolution = resolve_source(db, message.sender_email, parsed.external_ref)

    raw_blob = _store_blob(
        db, blobs, message.raw_bytes, filename=None, content_type="application/vnd.ms-outlook"
    )

    advisory = Advisory(
        source_id=resolution.source.id,
        source_method=resolution.method,
        external_ref=parsed.external_ref,
        type=parsed.type,
        type_confidence=parsed.type_confidence,
        source_type_raw=parsed.source_type_raw,
        title=parsed.title,
        description=parsed.description,
        body_text=parsed.body_text,
        severity=parsed.severity,
        cvss_score=parsed.cvss_score,
        status=AdvisoryStatus.NEW,
        priority=parsed.priority,
        published_at=parsed.published_at,
        detected_on=parsed.detected_on,
        upstream_reference=parsed.upstream_reference,
        received_at=message.sent_at or utcnow(),
        ingested_at=utcnow(),
        dedupe_hash=message.dedupe_hash,
        message_id=message.message_id,
        title_fingerprint=parsed.title_fingerprint,
        parser_version=parsed.parser_version,
        raw_email_blob_id=raw_blob.id,
    )
    _apply_sla(advisory)
    db.add(advisory)
    db.flush()

    _write_children(db, advisory, parsed, blobs)

    flags = list(parsed.flags)
    if not resolution.sender_matched:
        flags.append((FlagKind.UNKNOWN_SENDER, unknown_sender_detail(message, resolution)))
    for kind, detail in flags:
        db.add(AdvisoryFlag(advisory_id=advisory.id, kind=kind, detail=detail))

    _link_possible_reissues(db, advisory)

    advisory.search_vector = func.to_tsvector(
        "english", f"{advisory.title} {advisory.description or ''} {advisory.body_text or ''}"
    )

    record(
        db,
        actor=actor,
        action="advisory.ingested",
        entity_type="advisory",
        entity_id=advisory.id,
        detail={
            "external_ref": advisory.external_ref,
            "type": advisory.type.value,
            "severity": advisory.severity.value if advisory.severity else None,
            "cves": len(parsed.cves),
            "iocs": len(parsed.iocs),
            "flags": [k.value for k, _ in flags],
            "parser_version": parsed.parser_version,
        },
    )
    return IngestResult(advisory=advisory, created=True)


def _apply_sla(advisory: Advisory) -> None:
    """Set both regulator clocks from ``received_at`` — see D-018."""
    if advisory.priority is None:
        return
    ack_hours, resolve_hours = SLA_HOURS[Priority(advisory.priority)]
    advisory.ack_due_at = advisory.received_at + timedelta(hours=ack_hours)
    advisory.resolution_due_at = advisory.received_at + timedelta(hours=resolve_hours)


def _write_children(
    db: DbSession, advisory: Advisory, parsed: ParsedAdvisory, blobs: BlobStore
) -> None:
    for cve_id, provenance in sorted(parsed.cves.items()):
        db.add(
            AdvisoryCve(
                advisory_id=advisory.id,
                cve_id=cve_id,
                found_in=sorted(set(provenance)),
                enrichment_status=EnrichmentStatus.PENDING,
            )
        )

    for ioc in parsed.iocs:
        db.add(
            AdvisoryIoc(
                advisory_id=advisory.id,
                ioc_type=ioc.ioc_type,
                ioc_type_raw=ioc.type_raw,
                value=ioc.value,
                defanged_value=ioc.defanged_value,
                context=ioc.context,
                extraction_source=ioc.extraction_source,
            )
        )

    for ttp in parsed.ttps:
        db.add(AdvisoryTtp(advisory_id=advisory.id, kind=ttp.kind, value=ttp.value))

    seen_products: set[tuple[str | None, str, str | None]] = set()
    for claim in parsed.products:
        key = (claim.vendor, claim.product, claim.version_expression)
        if key in seen_products:
            continue
        seen_products.add(key)
        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor=claim.vendor,
                product=claim.product,
                version_expression=claim.version_expression,
                fixed_version=claim.fixed_version,
                parsed_range=claim.parsed_range,
                source_of_claim=claim.source_of_claim,
            )
        )

    for result in parsed.attachments:
        att = result.attachment
        blob = _store_blob(
            db, blobs, att.data, filename=att.filename, content_type=att.content_type
        )
        text_blob = None
        if result.extraction and result.extraction.ok and result.extraction.text:
            text_blob = _store_blob(
                db,
                blobs,
                result.extraction.text.encode("utf-8"),
                filename=f"{att.filename}.txt",
                content_type="text/plain",
            )
        db.add(
            AdvisoryAttachment(
                advisory_id=advisory.id,
                blob_id=blob.id,
                filename=att.filename,
                content_type=att.content_type,
                page_count=result.extraction.page_count if result.extraction else None,
                extracted_text_blob_id=text_blob.id if text_blob else None,
                extraction_method=result.method,
                extraction_error=result.extraction.error if result.extraction else None,
            )
        )


def _store_blob(
    db: DbSession, blobs: BlobStore, data: bytes, *, filename: str | None, content_type: str | None
) -> Blob:
    """Store bytes and register them, reusing the row when already present."""
    stored = blobs.put_bytes(data)
    blob = db.scalar(select(Blob).where(Blob.sha256 == stored.sha256))
    if blob is None:
        blob = Blob(
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            content_type=content_type,
            original_filename=filename,
        )
        db.add(blob)
        db.flush()
    return blob


def _link_possible_reissues(db: DbSession, advisory: Advisory) -> None:
    """Link — never merge — advisories that look like re-issues (D-020).

    ``DOH-2026550`` and ``DOH-2026552`` carry identical titles eight hours apart
    under different reference numbers. They are separate regulator
    notifications with separate SLA clocks, so both are kept.
    """
    if not advisory.title_fingerprint:
        return
    window_start = advisory.received_at - REISSUE_WINDOW
    candidates = db.scalars(
        select(Advisory).where(
            Advisory.id != advisory.id,
            Advisory.title_fingerprint == advisory.title_fingerprint,
            Advisory.received_at >= window_start,
        )
    ).all()
    for other in candidates:
        db.add(
            RelatedAdvisory(
                advisory_id=advisory.id,
                related_advisory_id=other.id,
                kind=RelationKind.POSSIBLE_REISSUE,
                detected_by=RelationDetectedBy.TITLE_FINGERPRINT,
            )
        )
        db.add(
            AdvisoryFlag(
                advisory_id=advisory.id,
                kind=FlagKind.POSSIBLE_REISSUE,
                detail={
                    "related_advisory_id": str(other.id),
                    "related_ref": other.external_ref,
                    "received_at": other.received_at.isoformat(),
                },
            )
        )
