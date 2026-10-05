"""Ingestion orchestration: file → parsed advisory → database.

Ties the watcher, parser, and persistence together. Every failure disposition is
explicit — nothing is silently dropped, and the original file always survives.
"""

from __future__ import annotations

import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
from ..core.services.audit import Actor
from ..core.services.ingestion import ingest_parsed_advisory
from ..core.storage.blobs import BlobStore, FilesystemBlobStore
from ..db import session_scope
from ..logging import get_logger
from .message import MessageParseError, parse_message
from .parser import parse_advisory
from .watcher import Inbox, safe_message_name

log = get_logger(__name__)


@dataclass(slots=True)
class IngestOutcome:
    path: Path
    status: str  # INGESTED | DUPLICATE | FAILED | QUEUED
    advisory_id: str | None = None
    external_ref: str | None = None
    error: str | None = None
    source_code: str | None = None
    #: SourceMethod value — "NONE" means no source was detected.
    source_method: str | None = None


def ingest_file(
    path: Path, *, blobs: BlobStore | None = None, actor: Actor | None = None
) -> IngestOutcome:
    """Parse and persist one message. Never raises for parse failures."""
    blobs = blobs or FilesystemBlobStore(settings.blob_root)
    try:
        message = parse_message(path)
    except MessageParseError as exc:
        return IngestOutcome(path, "FAILED", error=f"MESSAGE_PARSE: {exc}")
    except Exception as exc:  # untrusted input: never let one message kill the worker
        return IngestOutcome(path, "FAILED", error=f"MESSAGE_PARSE: {type(exc).__name__}: {exc}")

    try:
        parsed = parse_advisory(message)
    except Exception as exc:
        return IngestOutcome(path, "FAILED", error=f"ADVISORY_PARSE: {type(exc).__name__}: {exc}")

    try:
        with session_scope() as db:
            result = ingest_parsed_advisory(db, parsed, blobs, actor=actor)
            advisory_id = str(result.advisory_id) if result.advisory_id else None
            ref = result.advisory.external_ref if result.advisory else None
            source_code = result.advisory.source.short_code if result.advisory else None
            method = result.advisory.source_method.value if result.advisory else None
            status = "DUPLICATE" if result.duplicate else "INGESTED"
    except Exception as exc:
        return IngestOutcome(path, "FAILED", error=f"PERSIST: {type(exc).__name__}: {exc}")

    return IngestOutcome(
        path,
        status,
        advisory_id=advisory_id,
        external_ref=ref,
        source_code=source_code,
        source_method=method,
    )


def process_inbox(*, limit: int = 50, inbox: Inbox | None = None) -> list[IngestOutcome]:
    """Claim and process a batch, recovering anything a previous crash left."""
    inbox = inbox or Inbox()
    blobs = FilesystemBlobStore(settings.blob_root)
    outcomes: list[IngestOutcome] = []

    claimed = [*inbox.recover_orphans(), *inbox.claim_batch(limit=limit)]
    for path in claimed:
        outcome = _process_one(path, inbox, blobs)
        outcomes.append(outcome)

    if outcomes:
        log.info(
            "inbox.batch_complete",
            total=len(outcomes),
            ingested=sum(o.status == "INGESTED" for o in outcomes),
            duplicates=sum(o.status == "DUPLICATE" for o in outcomes),
            failed=sum(o.status == "FAILED" for o in outcomes),
        )
    return outcomes


class UploadRejectedError(ValueError):
    """An upload failed validation; nothing was written."""


def ingest_uploads(
    uploads: Sequence[tuple[str, bytes]],
    *,
    actor: Actor | None = None,
    inbox: Inbox | None = None,
) -> list[IngestOutcome]:
    """Ingest .eml/.msg files uploaded through the web UI.

    Each file goes through the inbox exactly like a Power Automate drop —
    deposited, claimed, then archived or moved to ``failed/`` — so an upload
    leaves the same trail as any other message, and a crash mid-request
    leaves the file in the inbox for the poller rather than losing it.
    Every file is validated before any is written: all or nothing.
    """
    if not uploads:
        raise UploadRejectedError("Choose at least one .eml or .msg file.")
    if len(uploads) > settings.upload_max_files:
        raise UploadRejectedError(
            f"Too many files ({len(uploads)}); upload at most {settings.upload_max_files} at once."
        )
    for filename, data in uploads:
        if safe_message_name(filename) is None:
            raise UploadRejectedError(f"{filename!r} is not an email file (.eml or .msg).")
        if not data:
            raise UploadRejectedError(f"{filename!r} is empty.")
        if len(data) > settings.upload_max_bytes:
            limit_mb = settings.upload_max_bytes // (1024 * 1024)
            raise UploadRejectedError(f"{filename!r} is larger than {limit_mb} MB.")

    inbox = inbox or Inbox()
    blobs = FilesystemBlobStore(settings.blob_root)
    outcomes: list[IngestOutcome] = []
    for filename, data in uploads:
        deposited = inbox.deposit(filename, data)
        claimed = inbox.claim(deposited)
        if claimed is None:
            # The worker's poller claimed it first; it will be processed there.
            outcomes.append(IngestOutcome(deposited, "QUEUED"))
            continue
        outcomes.append(_process_one(claimed, inbox, blobs, actor=actor))

    log.info(
        "inbox.upload_complete",
        total=len(outcomes),
        ingested=sum(o.status == "INGESTED" for o in outcomes),
        duplicates=sum(o.status == "DUPLICATE" for o in outcomes),
        failed=sum(o.status == "FAILED" for o in outcomes),
        queued=sum(o.status == "QUEUED" for o in outcomes),
    )
    return outcomes


def _process_one(
    path: Path, inbox: Inbox, blobs: BlobStore, *, actor: Actor | None = None
) -> IngestOutcome:
    try:
        outcome = ingest_file(path, blobs=blobs, actor=actor)
    except Exception as exc:  # belt and braces around the worker loop
        outcome = IngestOutcome(path, "FAILED", error=f"UNEXPECTED: {type(exc).__name__}: {exc}")

    if outcome.status == "FAILED":
        inbox.fail_file(
            path,
            {
                "error": outcome.error,
                "file": path.name,
                "traceback": traceback.format_exc(limit=6) if _has_active_exception() else None,
            },
        )
        return outcome

    archived = inbox.archive_file(path)
    log.info(
        "advisory.ingested" if outcome.status == "INGESTED" else "advisory.duplicate",
        file=path.name,
        external_ref=outcome.external_ref,
        advisory_id=outcome.advisory_id,
        archived_to=str(archived),
    )
    return outcome


def _has_active_exception() -> bool:
    import sys

    return sys.exc_info()[0] is not None
