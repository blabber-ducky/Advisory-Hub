"""Advisory read paths plus the status-change chokepoint.

Everything here is a query except `change_status()` — the single write path
for advisory status. See CLAUDE.md §2.2: no other caller may write
`advisory.status`, `status_change`, or a status-change `comment` directly.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import Select, Subquery, and_, func, or_, select
from sqlalchemy.orm import InstrumentedAttribute, selectinload
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import (
    Advisory,
    AdvisoryCve,
    AdvisoryFlag,
    AdvisoryIoc,
    Comment,
    RelatedAdvisory,
    Source,
    StatusChange,
)
from ..models.base import utcnow
from ..models.enums import (
    ALLOWED_TRANSITIONS,
    AckChannel,
    AdvisoryStatus,
    AdvisoryType,
    FlagKind,
    IocType,
    Severity,
    SourceMethod,
)
from .audit import Actor, record


class _Unset:
    """Sentinel distinguishing 'field omitted' from 'field explicitly null'
    for `update_advisory()`'s PATCH semantics."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<unset>"


UNSET = _Unset()

#: Statuses that count as "open" for dashboard purposes.
OPEN_STATUSES = frozenset(
    {
        AdvisoryStatus.NEW,
        AdvisoryStatus.ACKNOWLEDGED,
        AdvisoryStatus.TRIAGED,
        AdvisoryStatus.IN_PROGRESS,
        AdvisoryStatus.AWAITING_VENDOR,
    }
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

DEFAULT_SORT = "-received_at"

#: The tracker's sort keys and their human labels, in picker order. A leading
#: `-` means descending. `ioc_type_count` counts *distinct kinds* of indicator
#: (two hashes and a domain = 2), `ioc_count` counts indicators; the two rank
#: an advisory differently and analysts triage on both — a handful of hashes
#: is one piece of work, the same count spread over hashes, domains, IPs and a
#: registry key is another. Anything not in here falls back to `DEFAULT_SORT`.
SORT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("-received_at", "Newest first"),
    ("received_at", "Oldest first"),
    ("severity", "Severity (critical first)"),
    ("-ioc_type_count", "Most IOC types"),
    ("ioc_type_count", "Fewest IOC types"),
    ("-ioc_count", "Most IOCs"),
    ("ioc_count", "Fewest IOCs"),
)

#: Sort keys backed by an aggregate over `advisory_ioc` rather than an
#: `advisory` column — these need the join `_ioc_aggregate()` builds.
_IOC_SORT_KEYS = frozenset({"ioc_count", "ioc_type_count"})

_SORT_COLUMNS: dict[str, InstrumentedAttribute[object]] = {
    "received_at": Advisory.received_at,
    # Native PG enum ordering follows declaration order, and `Severity`
    # declares CRITICAL first — so ascending is critical-first, and NULL
    # (unrated) sorts last, which is what the picker's label promises.
    "severity": Advisory.severity,
    "status": Advisory.status,
    "title": Advisory.title,
    "ack_due_at": Advisory.ack_due_at,
    "resolution_due_at": Advisory.resolution_due_at,
}


def normalise_sort(sort: str | None) -> str:
    """Coerce a caller-supplied sort key to one the tracker actually offers.

    Sort keys arrive from a query parameter, so anything at all can turn up;
    an unknown key silently becomes the default rather than erroring.
    """
    return sort if sort in {key for key, _ in SORT_OPTIONS} else DEFAULT_SORT


@dataclass(slots=True)
class AdvisoryFilters:
    status: list[AdvisoryStatus] = field(default_factory=list)
    type: list[AdvisoryType] = field(default_factory=list)
    severity: list[Severity] = field(default_factory=list)
    source_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None
    q: str | None = None
    unacknowledged_only: bool = False
    open_only: bool = False

    def is_empty(self) -> bool:
        return not any(
            (
                self.status,
                self.type,
                self.severity,
                self.source_id,
                self.assignee_id,
                self.q,
                self.unacknowledged_only,
                self.open_only,
            )
        )


@dataclass(slots=True)
class AdvisoryListResult:
    items: list[Advisory]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        return max(1, -(-self.total // self.page_size))

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1


def _apply_filters(
    stmt: Select[tuple[Advisory]], filters: AdvisoryFilters
) -> Select[tuple[Advisory]]:
    if filters.status:
        stmt = stmt.where(Advisory.status.in_(filters.status))
    if filters.type:
        stmt = stmt.where(Advisory.type.in_(filters.type))
    if filters.severity:
        stmt = stmt.where(Advisory.severity.in_(filters.severity))
    if filters.source_id:
        stmt = stmt.where(Advisory.source_id == filters.source_id)
    if filters.assignee_id:
        stmt = stmt.where(Advisory.assignee_id == filters.assignee_id)
    if filters.unacknowledged_only:
        stmt = stmt.where(Advisory.acknowledged_at.is_(None))
    if filters.open_only:
        stmt = stmt.where(Advisory.status.in_(OPEN_STATUSES))
    if filters.q:
        # plainto_tsquery tolerates arbitrary user input without raising on
        # stray operators the way websearch/tsquery syntax can.
        stmt = stmt.where(
            or_(
                Advisory.search_vector.op("@@")(func.plainto_tsquery("english", filters.q)),
                Advisory.external_ref.ilike(f"%{filters.q}%"),
            )
        )
    return stmt


def list_advisories(
    db: DbSession,
    filters: AdvisoryFilters | None = None,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    sort: str = DEFAULT_SORT,
) -> AdvisoryListResult:
    filters = filters or AdvisoryFilters()
    page = max(1, page)
    page_size = min(max(1, page_size), MAX_PAGE_SIZE)

    base = select(Advisory)
    base = _apply_filters(base, filters)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0

    stmt = (
        select(Advisory)
        .options(selectinload(Advisory.source))
        .join(Source, Advisory.source_id == Source.id)
    )
    stmt = _apply_filters(stmt, filters)
    stmt = _apply_sort(stmt, sort)
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    items = list(db.scalars(stmt).unique().all())
    return AdvisoryListResult(items=items, total=total, page=page, page_size=page_size)


def _ioc_aggregate() -> Subquery:
    """Per-advisory IOC totals — how many indicators, and how many distinct
    kinds of indicator. Grouped by `advisory_id`, so joining it can never
    duplicate an advisory row."""
    return (
        select(
            AdvisoryIoc.advisory_id.label("advisory_id"),
            func.count().label("ioc_count"),
            func.count(func.distinct(AdvisoryIoc.ioc_type)).label("ioc_type_count"),
        )
        .group_by(AdvisoryIoc.advisory_id)
        .subquery()
    )


def _apply_sort(stmt: Select[tuple[Advisory]], sort: str) -> Select[tuple[Advisory]]:
    descending = sort.startswith("-")
    key = sort.lstrip("-")

    if key in _IOC_SORT_KEYS:
        agg = _ioc_aggregate()
        column = agg.c.ioc_count if key == "ioc_count" else agg.c.ioc_type_count
        # LEFT JOIN, so advisories with no IOCs at all are still listed — and
        # COALESCE so they sort as 0 rather than NULL, which Postgres would
        # otherwise place *first* on a descending sort.
        expr = func.coalesce(column, 0)
        stmt = stmt.outerjoin(agg, agg.c.advisory_id == Advisory.id)
        # Ties dominate here — most advisories carry no IOCs at all — so fall
        # back to the default recency order instead of an arbitrary one.
        return stmt.order_by(
            expr.desc() if descending else expr.asc(),
            Advisory.received_at.desc(),
            Advisory.id.desc(),
        )

    advisory_column = _SORT_COLUMNS.get(key, Advisory.received_at)
    if descending:
        return stmt.order_by(advisory_column.desc(), Advisory.id.desc())
    return stmt.order_by(advisory_column.asc(), Advisory.id.asc())


# ─── Cursor pagination — REST API only; the web UI uses offset paging ───────


class InvalidCursorError(Exception):
    def __init__(self, cursor: str) -> None:
        super().__init__(f"Invalid cursor: {cursor!r}")
        self.cursor = cursor


@dataclass(slots=True)
class CursorPage:
    items: list[Advisory]
    next_cursor: str | None


def _encode_cursor(advisory: Advisory) -> str:
    raw = f"{advisory.received_at.isoformat()}|{advisory.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, id_str = raw.rsplit("|", 1)
        return datetime.fromisoformat(ts_str), uuid.UUID(id_str)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidCursorError(cursor) from exc


def list_advisories_cursor(
    db: DbSession,
    filters: AdvisoryFilters | None = None,
    *,
    cursor: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> CursorPage:
    """Keyset pagination on `(received_at, id)` descending — stable under
    concurrent inserts, unlike offset pagination. For the REST API; the web
    UI's page-number pagination (`list_advisories`) is unaffected."""
    filters = filters or AdvisoryFilters()
    limit = min(max(1, limit), MAX_PAGE_SIZE)

    stmt = (
        select(Advisory)
        .options(selectinload(Advisory.source))
        .join(Source, Advisory.source_id == Source.id)
    )
    stmt = _apply_filters(stmt, filters)

    if cursor:
        after_received_at, after_id = _decode_cursor(cursor)
        stmt = stmt.where(
            or_(
                Advisory.received_at < after_received_at,
                and_(Advisory.received_at == after_received_at, Advisory.id < after_id),
            )
        )

    stmt = stmt.order_by(Advisory.received_at.desc(), Advisory.id.desc()).limit(limit + 1)
    rows = list(db.scalars(stmt).unique().all())

    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = _encode_cursor(rows[-1])

    return CursorPage(items=rows, next_cursor=next_cursor)


def get_advisory(db: DbSession, advisory_id: uuid.UUID) -> Advisory | None:
    stmt = (
        select(Advisory)
        .where(Advisory.id == advisory_id)
        .options(
            selectinload(Advisory.source),
            selectinload(Advisory.attachments),
            selectinload(Advisory.cves),
            selectinload(Advisory.iocs),
            selectinload(Advisory.products),
            selectinload(Advisory.ttps),
            selectinload(Advisory.flags),
        )
    )
    return db.scalar(stmt)


def get_comments(db: DbSession, advisory_id: uuid.UUID) -> list[Comment]:
    stmt = (
        select(Comment)
        .where(Comment.advisory_id == advisory_id)
        .options(selectinload(Comment.author))
        .order_by(Comment.created_at.desc())
    )
    return list(db.scalars(stmt).all())


def get_last_comment(db: DbSession, advisory_id: uuid.UUID) -> Comment | None:
    stmt = (
        select(Comment)
        .where(Comment.advisory_id == advisory_id)
        .order_by(Comment.created_at.desc())
        .limit(1)
    )
    return db.scalar(stmt)


def last_comments_for(db: DbSession, advisory_ids: list[uuid.UUID]) -> dict[uuid.UUID, Comment]:
    """Batch version — one query for a page of rows, not N."""
    if not advisory_ids:
        return {}
    ranked = (
        select(
            Comment,
            func.row_number()
            .over(partition_by=Comment.advisory_id, order_by=Comment.created_at.desc())
            .label("rn"),
        )
        .where(Comment.advisory_id.in_(advisory_ids))
        .subquery()
    )
    stmt = (
        select(Comment)
        .select_from(ranked)
        .join(Comment, Comment.id == ranked.c.id)
        .where(ranked.c.rn == 1)
    )
    return {c.advisory_id: c for c in db.scalars(stmt).all()}


@dataclass(slots=True)
class IocBreakdown:
    """How many indicators an advisory carries, broken down by kind.

    Both numbers are shown in the tracker, because they say different things:
    `total` is how much there is to work through, `type_count` is how many
    *kinds* of control the work touches. Six SHA256 hashes is one blocklist
    update; two hashes, two domains, an IP and a registry key is four.
    """

    counts: dict[IocType, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def type_count(self) -> int:
        return len(self.counts)

    @property
    def by_count(self) -> list[tuple[IocType, int]]:
        """Kinds most-numerous first, ties broken alphabetically so the chips
        render in the same order every time."""
        return sorted(self.counts.items(), key=lambda item: (-item[1], item[0].value))


def ioc_breakdowns_for(
    db: DbSession, advisory_ids: list[uuid.UUID]
) -> dict[uuid.UUID, IocBreakdown]:
    """Batch version — one query for a page of rows, not N. Only 11 of the
    135-message real corpus carry any IOCs at all; this is what lets the
    tracker table show that up front instead of an analyst discovering it
    by clicking through advisories one at a time.

    Advisories with no IOCs are absent from the result, not zero-filled —
    callers render nothing at all for them.
    """
    if not advisory_ids:
        return {}
    stmt = (
        select(AdvisoryIoc.advisory_id, AdvisoryIoc.ioc_type, func.count())
        .where(AdvisoryIoc.advisory_id.in_(advisory_ids))
        .group_by(AdvisoryIoc.advisory_id, AdvisoryIoc.ioc_type)
    )
    grouped: dict[uuid.UUID, dict[IocType, int]] = {}
    for advisory_id, ioc_type, count in db.execute(stmt).tuples().all():
        grouped.setdefault(advisory_id, {})[ioc_type] = count
    return {advisory_id: IocBreakdown(counts=counts) for advisory_id, counts in grouped.items()}


def get_status_history(db: DbSession, advisory_id: uuid.UUID) -> list[StatusChange]:
    stmt = (
        select(StatusChange)
        .where(StatusChange.advisory_id == advisory_id)
        .options(selectinload(StatusChange.comment), selectinload(StatusChange.actor))
        .order_by(StatusChange.created_at.desc())
    )
    return list(db.scalars(stmt).all())


def get_related_advisories(
    db: DbSession, advisory_id: uuid.UUID
) -> list[tuple[RelatedAdvisory, Advisory]]:
    stmt = (
        select(RelatedAdvisory, Advisory)
        .join(Advisory, Advisory.id == RelatedAdvisory.related_advisory_id)
        .where(RelatedAdvisory.advisory_id == advisory_id)
        .order_by(Advisory.received_at.desc())
    )
    return [(rel, adv) for rel, adv in db.execute(stmt).all()]


def sources_for_filter(db: DbSession) -> list[Source]:
    stmt = select(Source).where(Source.is_active.is_(True)).order_by(Source.name)
    return list(db.scalars(stmt).all())


# ─── Status change — the mandatory-comment chokepoint ───────────────────────


class AdvisoryNotFoundError(Exception):
    def __init__(self, advisory_id: uuid.UUID) -> None:
        super().__init__(f"Advisory {advisory_id} not found")
        self.advisory_id = advisory_id


class InvalidStatusTransitionError(Exception):
    def __init__(self, from_status: AdvisoryStatus, to_status: AdvisoryStatus) -> None:
        super().__init__(f"Cannot move from {from_status.value} to {to_status.value}")
        self.from_status = from_status
        self.to_status = to_status


class MissingCommentError(Exception):
    def __init__(self) -> None:
        super().__init__("A comment is required for every status change")


class MissingAckChannelError(Exception):
    def __init__(self) -> None:
        super().__init__("An acknowledgement channel is required when acknowledging")


def next_statuses(current: AdvisoryStatus) -> list[AdvisoryStatus]:
    """The legal transitions out of `current`, for populating a status picker."""
    return sorted(ALLOWED_TRANSITIONS.get(current, frozenset()), key=lambda s: s.value)


def change_status(
    db: DbSession,
    advisory_id: uuid.UUID,
    *,
    to_status: AdvisoryStatus,
    comment_body: str,
    actor: Actor,
    ack_channel: AckChannel | None = None,
) -> StatusChange:
    """The single chokepoint for advisory status transitions.

    Validates the transition, writes the mandatory comment and the audit
    record, and updates the advisory — all in the caller's transaction. Never
    bypass this to write `advisory.status` directly (CLAUDE.md §2.2). The
    caller commits.
    """
    advisory = db.get(Advisory, advisory_id, with_for_update=True)
    if advisory is None:
        raise AdvisoryNotFoundError(advisory_id)

    body = comment_body.strip()
    if not body:
        raise MissingCommentError()

    if to_status not in ALLOWED_TRANSITIONS.get(advisory.status, frozenset()):
        raise InvalidStatusTransitionError(advisory.status, to_status)

    if to_status is AdvisoryStatus.ACKNOWLEDGED and ack_channel is None:
        raise MissingAckChannelError()

    from_status = advisory.status

    comment = Comment(
        advisory_id=advisory.id,
        author_id=actor.user_id,
        body=body,
        is_status_change=True,
    )
    db.add(comment)
    db.flush()

    status_change = StatusChange(
        advisory_id=advisory.id,
        from_status=from_status,
        to_status=to_status,
        actor_id=actor.user_id,
        comment_id=comment.id,
    )
    db.add(status_change)

    advisory.status = to_status
    if to_status is AdvisoryStatus.ACKNOWLEDGED:
        advisory.acknowledged_at = utcnow()
        advisory.acknowledged_by_id = actor.user_id
        advisory.ack_channel = ack_channel

    record(
        db,
        actor=actor,
        action="advisory.status_changed",
        entity_type="advisory",
        entity_id=advisory.id,
        detail={
            "from": from_status.value,
            "to": to_status.value,
            "comment_id": str(comment.id),
        },
    )
    db.flush()
    return status_change


def add_comment(db: DbSession, advisory_id: uuid.UUID, *, body: str, actor: Actor) -> Comment:
    """A free comment — no status change. `change_status()` writes its own
    comment directly; this is for everything else."""
    advisory = db.get(Advisory, advisory_id)
    if advisory is None:
        raise AdvisoryNotFoundError(advisory_id)

    text = body.strip()
    if not text:
        raise MissingCommentError()

    comment = Comment(
        advisory_id=advisory_id, author_id=actor.user_id, body=text, is_status_change=False
    )
    db.add(comment)
    db.flush()
    record(
        db,
        actor=actor,
        action="advisory.comment_added",
        entity_type="advisory",
        entity_id=advisory_id,
        detail={"comment_id": str(comment.id)},
    )
    db.flush()
    return comment


def update_advisory(
    db: DbSession,
    advisory_id: uuid.UUID,
    *,
    assignee_id: uuid.UUID | _Unset | None = UNSET,
    type: AdvisoryType | _Unset = UNSET,
    severity: Severity | _Unset | None = UNSET,
    actor: Actor,
) -> Advisory:
    """PATCH semantics: only fields the caller actually passed are touched.
    Status is deliberately not settable here — see `change_status()`."""
    advisory = db.get(Advisory, advisory_id)
    if advisory is None:
        raise AdvisoryNotFoundError(advisory_id)

    changes: dict[str, object] = {}
    if not isinstance(assignee_id, _Unset):
        changes["assignee_id"] = str(assignee_id) if assignee_id else None
        advisory.assignee_id = assignee_id
    if not isinstance(type, _Unset):
        changes["type"] = type.value
        advisory.type = type
    if not isinstance(severity, _Unset):
        changes["severity"] = severity.value if severity else None
        advisory.severity = severity

    if changes:
        record(
            db,
            actor=actor,
            action="advisory.updated",
            entity_type="advisory",
            entity_id=advisory.id,
            detail=changes,
        )
        db.flush()
    return advisory


# ─── Dashboard ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class DashboardStats:
    total_open: int = 0
    unacknowledged: int = 0
    ack_overdue: int = 0
    ack_due_soon: int = 0  # within 2 hours
    resolution_overdue: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    ingested_this_week: int = 0
    flagged_for_review: int = 0


def dashboard_stats(db: DbSession) -> DashboardStats:
    now = utcnow()
    stats = DashboardStats()

    open_stmt = select(func.count()).select_from(Advisory).where(Advisory.status.in_(OPEN_STATUSES))
    stats.total_open = db.scalar(open_stmt) or 0

    unacked_stmt = select(Advisory).where(
        Advisory.acknowledged_at.is_(None), Advisory.status != AdvisoryStatus.NOT_APPLICABLE
    )
    unacked = list(db.scalars(unacked_stmt).all())
    stats.unacknowledged = len(unacked)
    stats.ack_overdue = sum(1 for a in unacked if a.ack_due_at and a.ack_due_at < now)
    stats.ack_due_soon = sum(
        1 for a in unacked if a.ack_due_at and now <= a.ack_due_at < now + timedelta(hours=2)
    )

    stats.resolution_overdue = (
        db.scalar(
            select(func.count())
            .select_from(Advisory)
            .where(
                Advisory.status.in_(OPEN_STATUSES),
                Advisory.resolution_due_at.isnot(None),
                Advisory.resolution_due_at < now,
            )
        )
        or 0
    )

    stats.by_status = _count_by(db, Advisory.status)
    stats.by_severity = _count_by(db, Advisory.severity)
    stats.by_type = _count_by(db, Advisory.type)

    stats.ingested_this_week = (
        db.scalar(
            select(func.count())
            .select_from(Advisory)
            .where(Advisory.received_at >= now - timedelta(days=7))
        )
        or 0
    )

    stats.flagged_for_review = (
        db.scalar(
            select(func.count(func.distinct(AdvisoryFlag.advisory_id))).where(
                AdvisoryFlag.resolved_at.is_(None)
            )
        )
        or 0
    )

    return stats


def _count_by(db: DbSession, column: InstrumentedAttribute[object]) -> dict[str, int]:
    rows = db.execute(select(column, func.count()).group_by(column)).all()
    return {(v.value if v is not None else "UNSET"): c for v, c in rows}


# ─── Cross-referenced counts for the table (avoids N+1 in the template) ─────


def child_counts_for(
    db: DbSession, advisory_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict[str, int]]:
    if not advisory_ids:
        return {}
    counts: dict[uuid.UUID, dict[str, int]] = {aid: {"cves": 0, "iocs": 0} for aid in advisory_ids}
    for model, key in ((AdvisoryCve, "cves"), (AdvisoryIoc, "iocs")):
        rows = db.execute(
            select(model.advisory_id, func.count())
            .where(model.advisory_id.in_(advisory_ids))
            .group_by(model.advisory_id)
        ).all()
        for advisory_id, count in rows:
            counts[advisory_id][key] = count
    return counts


__all__ = [
    "DEFAULT_SORT",
    "SORT_OPTIONS",
    "UNSET",
    "AdvisoryFilters",
    "AdvisoryListResult",
    "AdvisoryNotFoundError",
    "CursorPage",
    "DashboardStats",
    "InvalidCursorError",
    "InvalidStatusTransitionError",
    "IocBreakdown",
    "MissingAckChannelError",
    "MissingCommentError",
    "add_comment",
    "change_status",
    "child_counts_for",
    "dashboard_stats",
    "get_advisory",
    "get_comments",
    "get_last_comment",
    "get_related_advisories",
    "get_status_history",
    "ioc_breakdowns_for",
    "last_comments_for",
    "list_advisories",
    "list_advisories_cursor",
    "next_statuses",
    "normalise_sort",
    "sources_for_filter",
    "update_advisory",
]


# ─── Source (manual override) ────────────────────────────────────────────────


class InvalidSourceError(Exception):
    """The chosen source doesn't exist, is inactive, or is the UNKNOWN bucket."""


def change_source(
    db: DbSession, advisory_id: uuid.UUID, *, source_id: uuid.UUID, actor: Actor
) -> Advisory:
    """Set an advisory's source by hand — for one the sender and reference
    couldn't identify, or got wrong.

    Marks it MANUAL, so a re-parse never overrides it, and resolves an open
    UNKNOWN_SENDER flag in the actor's name: choosing the source is the
    analyst's verdict on that sender. Choosing the source it already has
    still records the confirmation (and makes it MANUAL).
    """
    from .sources import UNKNOWN_SOURCE_CODE

    advisory = db.get(Advisory, advisory_id)
    if advisory is None:
        raise AdvisoryNotFoundError(advisory_id)
    source = db.get(Source, source_id)
    if source is None or not source.is_active or source.short_code == UNKNOWN_SOURCE_CODE:
        raise InvalidSourceError(source_id)
    if advisory.source_id == source.id and advisory.source_method is SourceMethod.MANUAL:
        return advisory

    previous = db.get(Source, advisory.source_id)
    previous_method = advisory.source_method
    advisory.source_id = source.id
    advisory.source_method = SourceMethod.MANUAL
    now = utcnow()
    for flag in advisory.flags:
        if flag.kind is FlagKind.UNKNOWN_SENDER and flag.resolved_at is None:
            flag.resolved_at = now
            flag.resolved_by_id = actor.user_id
    record(
        db,
        actor=actor,
        action="advisory.source_changed",
        entity_type="advisory",
        entity_id=advisory.id,
        detail={
            "external_ref": advisory.external_ref,
            "from": previous.short_code if previous else None,
            "from_method": previous_method.value,
            "to": source.short_code,
        },
    )
    return advisory


# ─── Bulk edits ──────────────────────────────────────────────────────────────

BULK_MAX = 200


@dataclass(slots=True)
class BulkResult:
    updated: list[str] = field(default_factory=list)  # references
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (reference, why)


def _label(advisory: Advisory | None, advisory_id: uuid.UUID) -> str:
    return (advisory.external_ref if advisory else None) or str(advisory_id)[:8]


def _status_label(status: AdvisoryStatus) -> str:
    return status.value.replace("_", " ").title()


def bulk_change_status(
    db: DbSession,
    advisory_ids: list[uuid.UUID],
    *,
    to_status: AdvisoryStatus,
    comment_body: str,
    actor: Actor,
    ack_channel: AckChannel | None = None,
) -> BulkResult:
    """``change_status()`` for each advisory — same comment, same rules. One
    whose transition isn't allowed is skipped with the reason; the rest go
    through (each in its own savepoint). The caller commits."""
    if not comment_body.strip():
        raise MissingCommentError()
    if to_status is AdvisoryStatus.ACKNOWLEDGED and ack_channel is None:
        raise MissingAckChannelError()
    result = BulkResult()
    for advisory_id in dict.fromkeys(advisory_ids[:BULK_MAX]):
        advisory = db.get(Advisory, advisory_id)
        label = _label(advisory, advisory_id)
        if advisory is None:
            result.skipped.append((label, "not found"))
            continue
        if advisory.status is to_status:
            result.skipped.append((label, f"already {_status_label(to_status)}"))
            continue
        try:
            with db.begin_nested():
                change_status(
                    db,
                    advisory_id,
                    to_status=to_status,
                    comment_body=comment_body,
                    actor=actor,
                    ack_channel=ack_channel,
                )
        except InvalidStatusTransitionError as exc:
            frm, to = _status_label(exc.from_status), _status_label(exc.to_status)
            result.skipped.append((label, f"can't go from {frm} to {to}"))
            continue
        result.updated.append(label)
    return result


def bulk_change_source(
    db: DbSession, advisory_ids: list[uuid.UUID], *, source_id: uuid.UUID, actor: Actor
) -> BulkResult:
    """``change_source()`` for each advisory. The caller commits."""
    source = db.get(Source, source_id)
    from .sources import UNKNOWN_SOURCE_CODE

    if source is None or not source.is_active or source.short_code == UNKNOWN_SOURCE_CODE:
        raise InvalidSourceError(source_id)
    result = BulkResult()
    for advisory_id in dict.fromkeys(advisory_ids[:BULK_MAX]):
        advisory = db.get(Advisory, advisory_id)
        label = _label(advisory, advisory_id)
        if advisory is None:
            result.skipped.append((label, "not found"))
            continue
        if advisory.source_id == source.id and advisory.source_method is SourceMethod.MANUAL:
            result.skipped.append((label, f"already {source.short_code}"))
            continue
        with db.begin_nested():
            change_source(db, advisory_id, source_id=source.id, actor=actor)
        result.updated.append(label)
    return result
