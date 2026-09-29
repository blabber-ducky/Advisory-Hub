"""Cross-advisory IOC tracking — the "IOC" tab.

`AdvisoryIoc.remediation_status` is a nullable override; the *effective*
status an analyst sees is either that override or, when unset, derived
from the parent advisory's own status via `ADVISORY_STATUS_TO_IOC_STATUS`
(CLAUDE.md-style "evidence, not truth": a derived value is computed fresh,
never silently duplicated into a stale column). Setting it independently
here does not change the advisory's own status — only this one indicator's
tracked state — and is visible back on the advisory detail page, since
both read the same column.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import Advisory, AdvisoryIoc
from ..models.enums import ADVISORY_STATUS_TO_IOC_STATUS, IocRemediationStatus, IocType
from .audit import Actor
from .audit import record as audit_record

__all__ = [
    "IocFilters",
    "IocListResult",
    "IocNotFoundError",
    "effective_status",
    "list_all_iocs",
    "list_iocs",
    "set_remediation_status",
]


class IocNotFoundError(Exception):
    def __init__(self, ioc_id: uuid.UUID) -> None:
        super().__init__(f"IOC {ioc_id} not found")
        self.ioc_id = ioc_id


def effective_status(ioc: AdvisoryIoc, advisory: Advisory) -> IocRemediationStatus:
    if ioc.remediation_status is not None:
        return ioc.remediation_status
    return ADVISORY_STATUS_TO_IOC_STATUS[advisory.status]


@dataclass(slots=True)
class IocFilters:
    ioc_type: list[IocType] = field(default_factory=list)
    status: list[IocRemediationStatus] = field(default_factory=list)
    advisory_id: uuid.UUID | None = None
    q: str | None = None


@dataclass(slots=True)
class IocListResult:
    items: list[AdvisoryIoc]
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
    stmt: Select[tuple[AdvisoryIoc]], filters: IocFilters
) -> Select[tuple[AdvisoryIoc]]:
    if filters.ioc_type:
        stmt = stmt.where(AdvisoryIoc.ioc_type.in_(filters.ioc_type))
    if filters.advisory_id:
        stmt = stmt.where(AdvisoryIoc.advisory_id == filters.advisory_id)
    if filters.q:
        stmt = stmt.where(AdvisoryIoc.defanged_value.ilike(f"%{filters.q}%"))
    return stmt


def _matching_rows(db: DbSession, filters: IocFilters) -> list[AdvisoryIoc]:
    """Every row matching `filters`, newest advisory first — pre-pagination.
    `filters.status` is the *effective* status, which can't be pushed into
    SQL (it depends on each row's parent advisory status too), so it's
    applied in Python after a DB-level fetch. Fine at this project's real
    scale (227 IOCs across 135 advisories); would need a materialised
    column if that ever stopped being true."""
    base = _apply_filters(select(AdvisoryIoc), filters)
    rows = list(
        db.scalars(
            base.join(Advisory, Advisory.id == AdvisoryIoc.advisory_id).order_by(
                Advisory.received_at.desc(), AdvisoryIoc.ioc_type
            )
        ).all()
    )
    if not filters.status:
        return rows
    return [row for row in rows if effective_status(row, row.advisory) in filters.status]


def list_iocs(
    db: DbSession, filters: IocFilters | None = None, *, page: int = 1, page_size: int = 50
) -> IocListResult:
    filters = filters or IocFilters()
    page = max(1, page)

    if not filters.status:
        base = _apply_filters(select(AdvisoryIoc), filters)
        total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
        stmt = (
            base.join(Advisory, Advisory.id == AdvisoryIoc.advisory_id)
            .order_by(Advisory.received_at.desc(), AdvisoryIoc.ioc_type)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        items = list(db.scalars(stmt).all())
        return IocListResult(items=items, total=total, page=page, page_size=page_size)

    matching = _matching_rows(db, filters)
    total = len(matching)
    start = (page - 1) * page_size
    items = matching[start : start + page_size]
    return IocListResult(items=items, total=total, page=page, page_size=page_size)


def list_all_iocs(db: DbSession, filters: IocFilters | None = None) -> list[AdvisoryIoc]:
    """Every matching row, unpaginated — backs the IOC tab's CSV export, so
    the export reflects the same filters currently applied to the table,
    not just the one page on screen."""
    return _matching_rows(db, filters or IocFilters())


def set_remediation_status(
    db: DbSession, ioc_id: uuid.UUID, status: IocRemediationStatus | None, *, actor: Actor
) -> AdvisoryIoc:
    """`status=None` clears the override, reverting to following the
    advisory's own status."""
    ioc = db.get(AdvisoryIoc, ioc_id)
    if ioc is None:
        raise IocNotFoundError(ioc_id)

    ioc.remediation_status = status
    db.flush()

    audit_record(
        db,
        actor=actor,
        action="ioc.remediation_status_changed",
        entity_type="advisory_ioc",
        entity_id=ioc.id,
        detail={"status": status.value if status else None},
    )
    db.flush()
    return ioc
