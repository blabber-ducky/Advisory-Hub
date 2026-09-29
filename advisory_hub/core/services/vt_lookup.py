"""VirusTotal IOC reputation checks — orchestration.

An analyst clicks "Check on VirusTotal" for one IOC; this looks up the raw
value server-side (never sent to the browser — the web/API callers only
ever pass an `AdvisoryIoc` id), calls `enrich.virustotal`, and persists the
result keyed by `(ioc_type, value)` so the same indicator across different
advisories shares one cached check. See `core.models.advisory.VtLookup`'s
docstring and docs/decisions.md.

Caching has two purposes here, not one: avoiding VT's tight rate limit on
repeat clicks, *and* giving every advisory that cites the same indicator a
consistent answer without re-querying per advisory.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...enrich.virustotal import (
    VtClient,
    VtError,
    VtRateLimitedError,
    VtUnauthorizedError,
    VtUnsupportedIocTypeError,
    is_supported,
)
from ..models.advisory import AdvisoryIoc, VtLookup
from ..models.base import utcnow
from ..models.enums import EnrichmentStatus, IocType, SystemIntegrationKind
from . import system_integrations
from .audit import Actor
from .audit import record as audit_record

#: VT's verdicts don't change minute to minute — a day-old check is still
#: useful, and re-querying it burns the tight rate-limit budget for nothing.
STALE_AFTER_OK = timedelta(hours=24)
#: Shorter for "not found" — VT could index a very fresh IOC later the
#: same day.
STALE_AFTER_NOT_FOUND = timedelta(hours=6)
#: Short for a transport failure — worth a quick retry, not a full day's wait.
STALE_AFTER_ERROR = timedelta(minutes=10)

__all__ = [
    "BulkEnqueueResult",
    "IocNotFoundError",
    "VtDisabledError",
    "VtError",
    "VtUnauthorizedError",
    "VtUnsupportedIocTypeError",
    "cached_lookups_for",
    "check_ioc",
    "enqueue_bulk_check",
    "get_cached_lookup",
]


class IocNotFoundError(Exception):
    def __init__(self, ioc_id: uuid.UUID) -> None:
        super().__init__(f"IOC {ioc_id} not found")
        self.ioc_id = ioc_id


class VtDisabledError(Exception):
    """An admin turned VirusTotal off in the admin panel, or it was never
    enabled — distinct from `VtUnauthorizedError` (configured but the key
    is wrong)."""


def get_cached_lookup(db: DbSession, ioc_type: IocType, value: str) -> VtLookup | None:
    return db.scalar(select(VtLookup).where(VtLookup.ioc_type == ioc_type, VtLookup.value == value))


def cached_lookups_for(db: DbSession, iocs: list[AdvisoryIoc]) -> dict[uuid.UUID, VtLookup]:
    """One query for every IOC on an advisory — avoids N+1 when rendering
    the IOC table. Keyed by `advisory_ioc.id`, even though the underlying
    cache row is keyed by `(ioc_type, value)`, since that's what the
    template needs to look a result up per row."""
    if not iocs:
        return {}
    pairs = {(ioc.ioc_type, ioc.value) for ioc in iocs}
    values = {value for _, value in pairs}
    # `value.in_(...)` is a cheap pre-filter; the exact (type, value) match
    # is done in Python since SQLAlchemy has no clean tuple-IN across an
    # Enum column without a raw composite literal.
    rows = db.scalars(select(VtLookup).where(VtLookup.value.in_(values))).all()
    by_key = {(row.ioc_type, row.value): row for row in rows if (row.ioc_type, row.value) in pairs}
    return {
        ioc.id: by_key[(ioc.ioc_type, ioc.value)]
        for ioc in iocs
        if (ioc.ioc_type, ioc.value) in by_key
    }


def _is_fresh(lookup: VtLookup) -> bool:
    if lookup.checked_at is None:
        return False
    age = utcnow() - lookup.checked_at
    if lookup.status == EnrichmentStatus.OK:
        return age < STALE_AFTER_OK
    if lookup.status == EnrichmentStatus.NOT_FOUND:
        return age < STALE_AFTER_NOT_FOUND
    if lookup.status == EnrichmentStatus.ERROR:
        return age < STALE_AFTER_ERROR
    return False


def check_ioc(db: DbSession, ioc_id: uuid.UUID, *, actor: Actor, force: bool = False) -> VtLookup:
    """Returns a fresh-enough cached result, or performs (and persists) a
    live VirusTotal lookup.

    Raises `VtDisabledError` / `VtUnsupportedIocTypeError` / `VtUnauthorizedError`
    directly — these are configuration/data problems, not "this attempt
    failed" outcomes, so they are never written into the cache as an
    `ERROR` row (that would block a legitimate retry once the real problem
    is fixed). A transport failure (`VtError`/`VtRateLimitedError`) *is*
    persisted as `ERROR`, with a short staleness window, so repeated clicks
    during an outage don't keep hammering VirusTotal.
    """
    ioc = db.get(AdvisoryIoc, ioc_id)
    if ioc is None:
        raise IocNotFoundError(ioc_id)

    if not is_supported(ioc.ioc_type):
        raise VtUnsupportedIocTypeError(ioc.ioc_type)

    existing = get_cached_lookup(db, ioc.ioc_type, ioc.value)
    if existing is not None and not force and _is_fresh(existing):
        # A fresh cached result is still returned even if VT has since been
        # disabled — disabling blocks new lookups, not reads of what was
        # already checked while it was enabled.
        return existing

    resolved = system_integrations.resolve_credential(db, SystemIntegrationKind.VIRUSTOTAL)
    if not resolved.enabled:
        raise VtDisabledError("VirusTotal is disabled")

    lookup = existing or VtLookup(ioc_type=ioc.ioc_type, value=ioc.value)

    with VtClient(api_key=resolved.api_key) as client:
        try:
            result = client.lookup(ioc.ioc_type, ioc.value)
        except VtUnauthorizedError:
            # A subclass of VtError — must be excluded from the broad catch
            # below explicitly, or it would be silently persisted as a
            # per-lookup ERROR instead of propagating as the distinct
            # "not configured" condition it actually is.
            raise
        except (VtError, VtRateLimitedError) as exc:
            lookup.status = EnrichmentStatus.ERROR
            lookup.error = str(exc)
            lookup.checked_at = utcnow()
            lookup.checked_by_id = actor.user_id
            db.add(lookup)
            db.flush()
            audit_record(
                db,
                actor=actor,
                action="ioc.vt_check_failed",
                entity_type="advisory_ioc",
                entity_id=ioc.id,
                detail={"ioc_type": ioc.ioc_type.value, "error": str(exc)},
            )
            db.flush()
            return lookup

    if result is None:
        lookup.status = EnrichmentStatus.NOT_FOUND
        lookup.error = None
        lookup.malicious_count = None
        lookup.suspicious_count = None
        lookup.harmless_count = None
        lookup.undetected_count = None
        lookup.reputation = None
        lookup.last_analysis_at = None
        lookup.permalink = None
    else:
        lookup.status = EnrichmentStatus.OK
        lookup.error = None
        lookup.malicious_count = result.malicious_count
        lookup.suspicious_count = result.suspicious_count
        lookup.harmless_count = result.harmless_count
        lookup.undetected_count = result.undetected_count
        lookup.reputation = result.reputation
        lookup.last_analysis_at = result.last_analysis_at
        lookup.permalink = result.permalink

    lookup.checked_at = utcnow()
    lookup.checked_by_id = actor.user_id
    db.add(lookup)
    db.flush()

    audit_record(
        db,
        actor=actor,
        action="ioc.vt_checked",
        entity_type="advisory_ioc",
        entity_id=ioc.id,
        detail={
            "ioc_type": ioc.ioc_type.value,
            "status": lookup.status.value,
            "malicious_count": lookup.malicious_count,
        },
    )
    db.flush()
    return lookup


@dataclass(frozen=True, slots=True)
class BulkEnqueueResult:
    queued: list[uuid.UUID]
    #: VT has no lookup endpoint for these types — never enqueued.
    skipped_unsupported: list[uuid.UUID]
    skipped_not_found: list[uuid.UUID]


def enqueue_bulk_check(
    db: DbSession, ioc_ids: list[uuid.UUID], *, actor: Actor
) -> BulkEnqueueResult:
    """Queues one RQ job per IOC on the `vt_check` queue — never calls
    VirusTotal directly, so a multi-select bulk action returns immediately
    instead of blocking a web request for however long the free-tier rate
    limit takes to drain the batch. Each job self-paces against a
    Redis-backed limiter shared across job executions — see
    `worker.jobs._acquire_vt_slot()` for why an in-memory limiter can't do
    this across queued jobs."""
    from redis import Redis
    from rq import Queue

    from ...config import settings
    from ...worker.jobs import check_ioc_job

    queued: list[uuid.UUID] = []
    skipped_unsupported: list[uuid.UUID] = []
    skipped_not_found: list[uuid.UUID] = []

    iocs = {
        row.id: row for row in db.scalars(select(AdvisoryIoc).where(AdvisoryIoc.id.in_(ioc_ids)))
    }
    queue = Queue("vt_check", connection=Redis.from_url(settings.redis_url))

    for ioc_id in ioc_ids:
        ioc = iocs.get(ioc_id)
        if ioc is None:
            skipped_not_found.append(ioc_id)
            continue
        if not is_supported(ioc.ioc_type):
            skipped_unsupported.append(ioc_id)
            continue
        queue.enqueue(check_ioc_job, str(ioc_id))
        queued.append(ioc_id)

    if queued:
        audit_record(
            db,
            actor=actor,
            action="ioc.vt_bulk_check_queued",
            entity_type="advisory_ioc",
            entity_id=None,
            detail={"count": len(queued), "ioc_ids": [str(i) for i in queued]},
        )
        db.flush()

    return BulkEnqueueResult(
        queued=queued, skipped_unsupported=skipped_unsupported, skipped_not_found=skipped_not_found
    )
