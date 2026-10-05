"""Re-derive parsed fields from stored blobs.

Parsers improve; analyst work must survive them. Re-parsing rewrites only
derived fields and **never** touches ``status``, ``assignee``, comments,
acknowledgement, or status history — see docs/ingestion.md §15. The source
is re-resolved too, except one an analyst set (``SourceMethod.MANUAL``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from ...ingest.message import ParsedMessage, parse_body_fields
from ...ingest.parser import PARSER_VERSION, parse_advisory
from ...logging import get_logger
from ..models.advisory import (
    Advisory,
    AdvisoryCve,
    AdvisoryFlag,
    AdvisoryIoc,
    AdvisoryProduct,
    AdvisoryTtp,
    Blob,
    Source,
)
from ..models.enums import FlagKind, SourceMethod
from ..storage.blobs import BlobStore, FilesystemBlobStore
from .audit import Actor, record
from .sources import SourceResolution, resolve_source, unknown_sender_detail

log = get_logger(__name__)

#: Rewritten by a re-parse. Everything not listed here is analyst-owned.
DERIVED_FIELDS = (
    "external_ref",
    "type",
    "type_confidence",
    "source_type_raw",
    "title",
    "description",
    "body_text",
    "severity",
    "cvss_score",
    "priority",
    "published_at",
    "detected_on",
    "upstream_reference",
    "title_fingerprint",
    "parser_version",
)

#: Never rewritten. Listed explicitly so the guarantee is testable.
PRESERVED_FIELDS = (
    "status",
    "assignee_id",
    "acknowledged_at",
    "acknowledged_by_id",
    "ack_channel",
    "ack_due_at",
    "resolution_due_at",
    "received_at",
    "dedupe_hash",
    "created_at",
)


@dataclass(slots=True)
class ReparseReport:
    changed: int = 0
    unchanged: int = 0
    failed: int = 0
    lines: list[str] = field(default_factory=list)


def reparse_advisories(
    db: DbSession,
    *,
    since: str | date | None = None,
    parser_version_below: int | None = None,
    dry_run: bool = True,
    limit: int | None = None,
    blobs: BlobStore | None = None,
    actor: Actor | None = None,
) -> ReparseReport:
    from ...config import settings

    blobs = blobs or FilesystemBlobStore(settings.blob_root)
    actor = actor or Actor.system("reparse")
    report = ReparseReport()

    stmt = select(Advisory).order_by(Advisory.received_at)
    if since:
        cutoff = date.fromisoformat(since) if isinstance(since, str) else since
        stmt = stmt.where(
            Advisory.received_at >= datetime.combine(cutoff, datetime.min.time(), tzinfo=UTC)
        )
    # parser_version is a free-form string, so the "below N" comparison is done
    # in Python (see `_version_of`) rather than with a fragile SQL cast.
    if limit:
        stmt = stmt.limit(limit)

    for advisory in db.scalars(stmt).all():
        if parser_version_below is not None and _version_of(advisory) >= parser_version_below:
            continue
        try:
            changed = _reparse_one(db, advisory, blobs, dry_run=dry_run, report=report)
        except Exception as exc:  # one bad advisory must not stop the whole run
            report.failed += 1
            report.lines.append(f"  FAILED  {advisory.external_ref}: {type(exc).__name__}: {exc}")
            continue
        if changed:
            report.changed += 1
        else:
            report.unchanged += 1

    if not dry_run and report.changed:
        record(
            db,
            actor=actor,
            action="advisory.reparsed",
            detail={"changed": report.changed, "parser_version": PARSER_VERSION},
        )
    return report


def _reparse_one(
    db: DbSession, advisory: Advisory, blobs: BlobStore, *, dry_run: bool, report: ReparseReport
) -> bool:
    if advisory.raw_email_blob_id is None:
        raise ValueError("no raw message blob — cannot re-parse")
    blob = db.get(Blob, advisory.raw_email_blob_id)
    if blob is None:
        raise ValueError("raw message blob row is missing")

    raw = blobs.get_bytes(blob.sha256)
    message = _rebuild_message(raw, blob.original_filename or "")
    parsed = parse_advisory(message)

    diffs: list[str] = []
    for name in DERIVED_FIELDS:
        before = getattr(advisory, name)
        after = getattr(parsed, name, None)
        if name == "parser_version":
            after = parsed.parser_version
        if _differs(before, after):
            diffs.append(f"{name}: {_short(before)} → {_short(after)}")

    # Source: re-resolved from the sender and the (possibly new) reference,
    # unless an analyst set it — MANUAL is never overridden.
    resolution = None
    if advisory.source_method is not SourceMethod.MANUAL:
        resolution = resolve_source(db, message.sender_email, parsed.external_ref)
        before_source = db.get(Source, advisory.source_id)
        moved = resolution.source.id != advisory.source_id
        if moved or resolution.method != advisory.source_method:
            diffs.append(
                f"source: {before_source.short_code if before_source else '?'}"
                f" ({advisory.source_method.value.lower()}) → "
                f"{resolution.source.short_code} ({resolution.method.value.lower()})"
            )

    before_cves = {c.cve_id for c in advisory.cves}
    after_cves = set(parsed.cves)
    if before_cves != after_cves:
        diffs.append(f"cves: {len(before_cves)} → {len(after_cves)}")
    before_iocs = len(advisory.iocs)
    if before_iocs != len(parsed.iocs):
        diffs.append(f"iocs: {before_iocs} → {len(parsed.iocs)}")

    if not diffs:
        return False

    report.lines.append(f"  {advisory.external_ref or advisory.id}")
    report.lines.extend(f"      {d}" for d in diffs)

    if dry_run:
        return True

    for name in DERIVED_FIELDS:
        setattr(advisory, name, getattr(parsed, name, None))
    advisory.parser_version = parsed.parser_version

    if resolution is not None:
        advisory.source_id = resolution.source.id
        advisory.source_method = resolution.method

    # Replace derived children; analyst-owned rows are untouched. Flags the
    # parser didn't produce are kept: POSSIBLE_REISSUE comes from ingest-time
    # linking (its relation rows survive), and UNKNOWN_SENDER is reconciled
    # below so an analyst's resolution of it isn't lost.
    for model in (AdvisoryCve, AdvisoryIoc, AdvisoryProduct, AdvisoryTtp):
        db.execute(delete(model).where(model.advisory_id == advisory.id))
    db.execute(
        delete(AdvisoryFlag).where(
            AdvisoryFlag.advisory_id == advisory.id,
            AdvisoryFlag.kind.not_in(_KEPT_FLAGS),
        )
    )
    db.flush()

    from .ingestion import _write_children  # local import avoids a cycle

    _write_children(db, advisory, parsed, blobs)
    for kind, detail in parsed.flags:
        if kind not in _KEPT_FLAGS:
            db.add(AdvisoryFlag(advisory_id=advisory.id, kind=kind, detail=detail))
    if resolution is not None:
        _reconcile_unknown_sender(db, advisory, message, resolution)

    advisory.search_vector = func.to_tsvector(
        "english", f"{advisory.title} {advisory.description or ''} {advisory.body_text or ''}"
    )
    return True


#: Flags a re-parse doesn't recreate from the parser's output.
_KEPT_FLAGS = (FlagKind.POSSIBLE_REISSUE, FlagKind.UNKNOWN_SENDER)


def _reconcile_unknown_sender(
    db: DbSession, advisory: Advisory, message: ParsedMessage, resolution: SourceResolution
) -> None:
    """Keep exactly one UNKNOWN_SENDER flag while the sender is unrecognised
    (the existing row, with any resolution, if there is one); none once it is."""
    existing = db.scalars(
        select(AdvisoryFlag).where(
            AdvisoryFlag.advisory_id == advisory.id,
            AdvisoryFlag.kind == FlagKind.UNKNOWN_SENDER,
        )
    ).all()
    if resolution.sender_matched:
        for flag in existing:
            db.delete(flag)
        return
    detail = unknown_sender_detail(message, resolution)
    if existing:
        existing[0].detail = detail
        for extra in existing[1:]:
            db.delete(extra)
    else:
        db.add(AdvisoryFlag(advisory_id=advisory.id, kind=FlagKind.UNKNOWN_SENDER, detail=detail))


_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _rebuild_message(raw: bytes, filename: str) -> ParsedMessage:
    """Re-parse a stored message from bytes, without touching the inbox."""
    import tempfile
    from pathlib import Path

    from ...ingest.message import parse_message

    # The raw-message blob is stored without a filename, so its format comes
    # from the bytes: Outlook .msg is an OLE2 compound file; anything else is
    # RFC 822 (.eml) — uploads and mail-rule drops can be either.
    suffix = Path(filename).suffix.lower() or (".msg" if raw.startswith(_OLE2_MAGIC) else ".eml")
    with tempfile.TemporaryDirectory(prefix="advhub-reparse-") as tmp:
        path = Path(tmp) / f"message{suffix}"
        path.write_bytes(raw)
        return parse_message(path)


def _version_of(advisory: Advisory) -> int:
    try:
        return int(advisory.parser_version or "0")
    except ValueError:
        return 0


def _differs(before: object, after: object) -> bool:
    if before is None and after is None:
        return False
    return str(before) != str(after)


def _short(value: object, limit: int = 60) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


__all__ = [
    "DERIVED_FIELDS",
    "PRESERVED_FIELDS",
    "ReparseReport",
    "parse_body_fields",
    "reparse_advisories",
]
