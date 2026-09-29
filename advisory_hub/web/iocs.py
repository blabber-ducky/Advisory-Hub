"""IOC tab — every indicator across every advisory, its remediation status
(defaulting to its advisory's own status; overridable per-IOC — see
`core.services.iocs`), and a multi-select bulk "Check on VirusTotal" action
that queues rate-limited RQ jobs (`core.services.vt_lookup.enqueue_bulk_check()`)
rather than calling VirusTotal synchronously.
"""

from __future__ import annotations

import csv
import io
import uuid
from enum import Enum
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession
from starlette.datastructures import QueryParams

from ..api.deps import current_principal, db_session
from ..core.models.base import utcnow
from ..core.models.enums import IocRemediationStatus, IocType, Role
from ..core.services import iocs as svc
from ..core.services import vt_lookup as vt_svc
from ..core.services.auth import PermissionDeniedError, Principal
from ..enrich.virustotal import is_supported as vt_is_supported

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _require_web_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return principal


@router.get("/iocs", response_class=HTMLResponse)
def index(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    filters = _parse_filters(request)
    page = _int_param(request, "page", default=1)
    result = svc.list_iocs(db, filters, page=page)
    context = _table_context(db, request, filters, result, principal)

    if request.headers.get("hx-request") == "true":
        return templates.TemplateResponse(request, "_iocs_table.html", context)
    context.update(
        {
            "title": "IOCs",
            "active_nav": "iocs",
            "types": list(IocType),
            "statuses": list(IocRemediationStatus),
        }
    )
    return templates.TemplateResponse(request, "iocs_index.html", context)


@router.get("/iocs/export")
def export_csv(
    request: Request,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(_require_web_principal),
) -> StreamingResponse:
    """CSV export of every IOC matching the tab's current filters (not just
    the page on screen) — including each indicator's cached VirusTotal
    result, so an analyst can hand a single file to someone who doesn't
    have access to this UI. `value` is deliberately omitted: only
    `defanged_value` is ever exported, matching the same
    never-render-a-clickable-indicator discipline the UI itself follows
    (CLAUDE.md §2.3)."""
    filters = _parse_filters(request)
    items = svc.list_all_iocs(db, filters)
    vt_lookups = vt_svc.cached_lookups_for(db, items)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "IOC Type",
            "Value (defanged)",
            "Advisory",
            "Remediation Status",
            "VT Status",
            "VT Malicious",
            "VT Suspicious",
            "VT Harmless",
            "VT Undetected",
            "VT Reputation",
            "VT Last Analysis",
            "VT Checked At",
            "VT Permalink",
        ]
    )
    for ioc in items:
        lookup = vt_lookups.get(ioc.id)
        writer.writerow(
            [
                ioc.ioc_type.value,
                ioc.defanged_value,
                ioc.advisory.external_ref or str(ioc.advisory_id),
                svc.effective_status(ioc, ioc.advisory).value,
                lookup.status.value if lookup else "NOT_CHECKED",
                lookup.malicious_count if lookup else "",
                lookup.suspicious_count if lookup else "",
                lookup.harmless_count if lookup else "",
                lookup.undetected_count if lookup else "",
                lookup.reputation if lookup else "",
                lookup.last_analysis_at.isoformat() if lookup and lookup.last_analysis_at else "",
                lookup.checked_at.isoformat() if lookup and lookup.checked_at else "",
                lookup.permalink if lookup else "",
            ]
        )
    buffer.seek(0)

    filename = f"iocs-export-{utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/iocs/{ioc_id}/status", response_class=HTMLResponse)
def set_status(
    ioc_id: uuid.UUID,
    request: Request,
    status_value: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    """`status_value=""` clears the override, reverting the IOC to following
    its advisory's own status."""
    try:
        principal.require_role(Role.ANALYST)
        parsed = IocRemediationStatus(status_value) if status_value else None
        ioc = svc.set_remediation_status(
            db,
            ioc_id,
            parsed,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.IocNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="IOC not found") from None
    except ValueError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid status") from None

    context = {"ioc": ioc, "effective_status": svc.effective_status(ioc, ioc.advisory)}
    return templates.TemplateResponse(request, "_ioc_status_cell.html", context)


@router.post("/iocs/bulk-check-vt", response_class=HTMLResponse)
async def bulk_check_vt(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    form = await request.form()
    ioc_ids = [uuid.UUID(str(v)) for v in form.getlist("ioc_ids")]

    try:
        principal.require_role(Role.ANALYST)
        result = vt_svc.enqueue_bulk_check(
            db, ioc_ids, actor=principal.to_actor(request.client.host if request.client else None)
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    filters = _parse_filters(request)
    page = _int_param(request, "page", default=1)
    list_result = svc.list_iocs(db, filters, page=page)
    context = _table_context(db, request, filters, list_result, principal)
    context["bulk_result"] = result
    return templates.TemplateResponse(request, "_iocs_table.html", context)


def _table_context(
    db: DbSession,
    request: Request,
    filters: svc.IocFilters,
    result: svc.IocListResult,
    principal: Principal,
) -> dict[str, object]:
    vt_lookups = vt_svc.cached_lookups_for(db, result.items)
    effective_statuses = {ioc.id: svc.effective_status(ioc, ioc.advisory) for ioc in result.items}
    return {
        "result": result,
        "filters": filters,
        "vt_lookups": vt_lookups,
        "effective_statuses": effective_statuses,
        "vt_supported_types": {t.value for t in IocType if vt_is_supported(t)},
        "can_edit": principal.user is not None and principal.user.role.satisfies(Role.ANALYST),
        "page_url": lambda page: _page_url(request, page),
        "current_query_string": str(request.query_params),
    }


def _page_url(request: Request, page: int) -> str:
    from urllib.parse import urlencode

    params = dict(request.query_params)
    params["page"] = str(page)
    return f"/iocs?{urlencode(params, doseq=True)}"


def _parse_filters(request: Request) -> svc.IocFilters:
    q = request.query_params
    return svc.IocFilters(
        ioc_type=_enum_list(q, "ioc_type", IocType),
        status=_enum_list(q, "status", IocRemediationStatus),
        q=q.get("q", "").strip() or None,
    )


def _enum_list[E: Enum](q: QueryParams, key: str, enum_cls: type[E]) -> list[E]:
    out: list[E] = []
    for raw in q.getlist(key):
        if not raw:
            continue
        try:
            out.append(enum_cls(raw))
        except ValueError:
            continue
    return out


def _int_param(request: Request, key: str, *, default: int) -> int:
    raw = request.query_params.get(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default
