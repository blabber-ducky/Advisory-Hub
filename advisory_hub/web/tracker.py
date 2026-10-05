"""Tracker + dashboard routes.

Thin — every query goes through ``core.services.advisories``. This module only
parses query parameters, calls the service, and picks a template.
"""

from __future__ import annotations

import uuid
from enum import Enum
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession
from starlette.datastructures import QueryParams

from ..api.deps import current_principal, db_session
from ..config import settings
from ..core.models.advisory import Advisory, AdvisoryAttachment, AdvisoryIoc, Blob
from ..core.models.base import utcnow
from ..core.models.enums import AckChannel, AdvisoryStatus, AdvisoryType, IocType, Role, Severity
from ..core.models.inventory import ScanRun
from ..core.services import advisories as svc
from ..core.services import inventory as inventory_svc
from ..core.services import iocs as iocs_svc
from ..core.services import scan as scan_svc
from ..core.services import vt_lookup as vt_svc
from ..core.services.auth import PermissionDeniedError, Principal
from ..core.storage.blobs import FilesystemBlobStore
from ..enrich.virustotal import is_supported as vt_is_supported

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _require_web_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    """Web routes redirect to /login rather than returning a bare 401.

    A 303 HTTPException with a Location header: browsers and htmx both follow
    redirects transparently at the network layer, so the JSON error body
    FastAPI's default handler attaches is never seen by either.
    """
    if principal is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return principal


@router.get("/", response_class=HTMLResponse)
def index(request: Request, db: DbSession = Depends(db_session)) -> object:
    principal = current_principal(request, db)
    if principal is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    filters = _parse_filters(request)
    page = _int_param(request, "page", default=1)
    sort = svc.normalise_sort(request.query_params.get("sort"))
    result = svc.list_advisories(db, filters, page=page, sort=sort)
    context = _table_context(db, request, filters, result)
    context.update(
        {
            "principal": principal,
            "title": "Tracker",
            "active_nav": "tracker",
            "stats": svc.dashboard_stats(db),
            "sources": svc.sources_for_filter(db),
            "statuses": list(AdvisoryStatus),
            "types": list(AdvisoryType),
            "severities": list(Severity),
            "sort": sort,
            "sort_options": svc.SORT_OPTIONS,
            "default_sort": svc.DEFAULT_SORT,
            "can_scan_inbox": principal.user is not None
            and principal.user.role.satisfies(Role.ANALYST),
            "inbox_scan_result": _inbox_scan_result(request),
        }
    )

    if request.headers.get("hx-request") == "true":
        # Filter/pagination requests re-render only the table region.
        return templates.TemplateResponse(request, "_tracker_table.html", context)
    return templates.TemplateResponse(request, "index.html", context)


@router.post("/inbox/scan")
def scan_inbox(
    request: Request,
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    """Claims and parses whatever's currently sitting in the watched inbox
    directory right now, rather than waiting for the worker's background
    poller's next sweep (`INBOX_POLL_SECONDS`) — the same
    `ingest.pipeline.process_inbox()` the poller and `advisory-hub watch`
    call. Safe to run concurrently with the poller: `Inbox.claim()`'s atomic
    rename means only one caller ever wins a given file."""
    try:
        principal.require_role(Role.ANALYST)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    from ..ingest.pipeline import process_inbox

    outcomes = process_inbox()
    counts = {"ingested": 0, "duplicates": 0, "failed": 0}
    for outcome in outcomes:
        if outcome.status == "INGESTED":
            counts["ingested"] += 1
        elif outcome.status == "DUPLICATE":
            counts["duplicates"] += 1
        else:
            counts["failed"] += 1

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = f"/?{urlencode(counts)}"
    return response


@router.post("/inbox/upload", response_class=HTMLResponse)
async def upload_messages(
    request: Request,
    files: list[UploadFile] = File(default=[]),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    """Ingest .eml/.msg files uploaded from the tracker page — through the
    same inbox → archive/failed path as a Power Automate drop (see
    `ingest.pipeline.ingest_uploads()`), attributed to the uploader."""
    try:
        principal.require_role(Role.ANALYST)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    from starlette.concurrency import run_in_threadpool

    from ..ingest.pipeline import UploadRejectedError, ingest_uploads

    uploads = [(f.filename or "", await f.read()) for f in files if f.filename]
    actor = principal.to_actor(request.client.host if request.client else None)
    try:
        outcomes = await run_in_threadpool(ingest_uploads, uploads, actor=actor)
    except UploadRejectedError as exc:
        return templates.TemplateResponse(request, "_upload_result.html", {"error": str(exc)})
    rows = [
        {"name": original, "outcome": outcome}
        for (original, _), outcome in zip(uploads, outcomes, strict=True)
    ]
    return templates.TemplateResponse(request, "_upload_result.html", {"rows": rows})


def _inbox_scan_result(request: Request) -> dict[str, int] | None:
    q = request.query_params
    if not {"ingested", "duplicates", "failed"} <= q.keys():
        return None
    try:
        return {
            "ingested": int(q["ingested"]),
            "duplicates": int(q["duplicates"]),
            "failed": int(q["failed"]),
        }
    except ValueError:
        return None


@router.get("/advisories/{advisory_id}", response_class=HTMLResponse)
def advisory_detail(
    advisory_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    """A full page, not an inline accordion — a direct, bookmarkable,
    shareable URL per advisory, one click from the tracker table."""
    advisory = svc.get_advisory(db, advisory_id)
    if advisory is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    context: dict[str, object] = {
        "principal": principal,
        "title": advisory.external_ref or "Advisory",
        "active_nav": "tracker",
        "advisory": advisory,
        "comments": svc.get_comments(db, advisory_id),
        "related": svc.get_related_advisories(db, advisory_id),
        "now": utcnow(),
        "next_statuses": svc.next_statuses(advisory.status),
        "vt_lookups": vt_svc.cached_lookups_for(db, advisory.iocs),
        "vt_supported_types": {t.value for t in IocType if vt_is_supported(t)},
        "ioc_effective_statuses": {
            ioc.id: iocs_svc.effective_status(ioc, advisory) for ioc in advisory.iocs
        },
        # Same service call, same chips as the tracker row this page was
        # reached from — so the summary can't drift between the two views.
        "ioc_breakdown": svc.ioc_breakdowns_for(db, [advisory_id]).get(advisory_id),
    }
    context.update(_scan_panel_context(db, advisory_id))
    return templates.TemplateResponse(request, "advisory_detail_page.html", context)


@router.post("/advisories/{advisory_id}/iocs/{ioc_id}/check-vt", response_class=HTMLResponse)
def check_ioc_vt(
    advisory_id: uuid.UUID,
    ioc_id: uuid.UUID,
    request: Request,
    force: bool = False,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    ioc = db.get(AdvisoryIoc, ioc_id)
    if ioc is None or ioc.advisory_id != advisory_id:
        raise HTTPException(status_code=404, detail="IOC not found on this advisory")

    context: dict[str, object] = {"advisory_id": advisory_id, "ioc": ioc}
    try:
        principal.require_role(Role.ANALYST)
        lookup = vt_svc.check_ioc(
            db,
            ioc_id,
            actor=principal.to_actor(request.client.host if request.client else None),
            force=force,
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except vt_svc.VtUnsupportedIocTypeError as exc:
        db.rollback()
        context["vt_error"] = str(exc)
        context["vt_error_label"] = "Unsupported type"
        return templates.TemplateResponse(request, "_vt_result.html", context)
    except vt_svc.VtUnauthorizedError as exc:
        db.rollback()
        context["vt_error"] = str(exc)
        context["vt_error_label"] = "VirusTotal not configured"
        return templates.TemplateResponse(request, "_vt_result.html", context)
    except vt_svc.VtDisabledError as exc:
        db.rollback()
        context["vt_error"] = str(exc)
        context["vt_error_label"] = "VirusTotal disabled"
        return templates.TemplateResponse(request, "_vt_result.html", context)

    context["lookup"] = lookup
    return templates.TemplateResponse(request, "_vt_result.html", context)


@router.post("/advisories/{advisory_id}/status", response_class=HTMLResponse)
def change_advisory_status(
    advisory_id: uuid.UUID,
    request: Request,
    to_status: str = Form(...),
    comment: str = Form(...),
    ack_channel: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    advisory = svc.get_advisory(db, advisory_id)
    if advisory is None:
        raise HTTPException(status_code=404, detail="Advisory not found")

    try:
        principal.require_role(Role.ANALYST)
        parsed_status = AdvisoryStatus(to_status)
        parsed_channel = AckChannel(ack_channel) if ack_channel else None
        svc.change_status(
            db,
            advisory_id,
            to_status=parsed_status,
            comment_body=comment,
            actor=principal.to_actor(request.client.host if request.client else None),
            ack_channel=parsed_channel,
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.AdvisoryNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Advisory not found") from None
    except (
        ValueError,
        svc.MissingCommentError,
        svc.InvalidStatusTransitionError,
        svc.MissingAckChannelError,
    ) as exc:
        # Unparseable enum value, blank comment, illegal transition, or a
        # missing ack channel — all surface as the same re-rendered form.
        db.rollback()
        return _status_form_error(
            request, advisory_id, db, str(exc), to_status, comment, ack_channel
        )

    response = Response(status_code=200)
    response.headers["HX-Refresh"] = "true"
    return response


def _status_form_error(
    request: Request,
    advisory_id: uuid.UUID,
    db: DbSession,
    message: str,
    to_status: str,
    comment: str,
    ack_channel: str,
) -> HTMLResponse:
    advisory = svc.get_advisory(db, advisory_id)
    context = {
        "advisory": advisory,
        "now": utcnow(),
        "next_statuses": svc.next_statuses(advisory.status) if advisory else [],
        "status_error": message,
        "to_status": to_status,
        "comment": comment,
        "ack_channel": ack_channel,
    }
    return templates.TemplateResponse(request, "_status_form.html", context)


@router.get("/advisories/{advisory_id}/scan-panel", response_class=HTMLResponse)
def scan_panel(
    advisory_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(_require_web_principal),
) -> object:
    advisory = svc.get_advisory(db, advisory_id)
    if advisory is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    context = _scan_panel_context(db, advisory_id)
    return templates.TemplateResponse(request, "_scan_panel.html", context)


@router.post("/advisories/{advisory_id}/scan", response_class=HTMLResponse)
async def scan_advisory(
    advisory_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    advisory = svc.get_advisory(db, advisory_id)
    if advisory is None:
        raise HTTPException(status_code=404, detail="Advisory not found")

    form = await request.form()
    snapshot_ids = [uuid.UUID(str(v)) for v in form.getlist("snapshot_ids")]
    if not snapshot_ids:
        snapshot_ids = [s.id for s in inventory_svc.latest_snapshots(db, active_only=True)]

    try:
        principal.require_role(Role.ANALYST)
        latest_run = scan_svc.run_scan(
            db,
            advisory_id,
            snapshot_ids,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except scan_svc.SnapshotNotFoundError as exc:
        db.rollback()
        context = _scan_panel_context(db, advisory_id)
        context["scan_error"] = str(exc)
        return templates.TemplateResponse(request, "_scan_panel.html", context)

    context = _scan_panel_context(db, advisory_id, latest_run=latest_run)
    return templates.TemplateResponse(request, "_scan_panel.html", context)


def _scan_panel_context(
    db: DbSession, advisory_id: uuid.UUID, *, latest_run: ScanRun | None = None
) -> dict[str, object]:
    history = scan_svc.scan_history(db, advisory_id)
    run = latest_run or (history[0] if history else None)
    return {
        "advisory_id": advisory_id,
        "snapshot_choices": inventory_svc.latest_snapshots(db, active_only=True),
        "latest_run": run,
        "coverage_gaps": scan_svc.coverage_gaps(db, run) if run is not None else [],
        "history": history,
    }


@router.get("/advisories/{advisory_id}/attachments/raw")
def download_raw_email(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(_require_web_principal),
) -> StreamingResponse:
    advisory = db.get(Advisory, advisory_id)
    if advisory is None or advisory.raw_email_blob_id is None:
        raise HTTPException(status_code=404, detail="Original message not found")
    blob = db.get(Blob, advisory.raw_email_blob_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="Blob not found")
    filename = f"{advisory.external_ref or advisory.id}.msg"
    return _stream_blob(blob, filename, blob.content_type or "application/octet-stream")


@router.get("/advisories/{advisory_id}/attachments/{attachment_id}")
def download_attachment(
    advisory_id: uuid.UUID,
    attachment_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(_require_web_principal),
) -> StreamingResponse:
    attachment = db.get(AdvisoryAttachment, attachment_id)
    if attachment is None or attachment.advisory_id != advisory_id:
        raise HTTPException(status_code=404, detail="Attachment not found")
    blob = db.get(Blob, attachment.blob_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="Blob not found")
    return _stream_blob(
        blob, attachment.filename, attachment.content_type or "application/octet-stream"
    )


def _stream_blob(blob: Blob, filename: str, content_type: str) -> StreamingResponse:
    store = FilesystemBlobStore(settings.blob_root)
    handle = store.open(blob.sha256)
    safe_name = filename.replace('"', "").replace("\r", "").replace("\n", "")
    return StreamingResponse(
        handle,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


# ─── Filter parsing ──────────────────────────────────────────────────────────


def _parse_filters(request: Request) -> svc.AdvisoryFilters:
    q = request.query_params
    filters = svc.AdvisoryFilters(
        status=_enum_list(q, "status", AdvisoryStatus),
        type=_enum_list(q, "type", AdvisoryType),
        severity=_enum_list(q, "severity", Severity),
        source_id=_uuid_param(q, "source_id"),
        q=q.get("q", "").strip() or None,
        unacknowledged_only=q.get("unacknowledged_only") == "1",
        open_only=q.get("open_only") == "1",
    )
    return filters


def _enum_list[E: Enum](q: QueryParams, key: str, enum_cls: type[E]) -> list[E]:
    values = q.getlist(key)
    out: list[E] = []
    for raw in values:
        if not raw:
            continue
        try:
            out.append(enum_cls(raw))
        except ValueError:
            continue
    return out


def _uuid_param(q: QueryParams, key: str) -> uuid.UUID | None:
    raw = q.get(key)
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


def _int_param(request: Request, key: str, *, default: int) -> int:
    raw = request.query_params.get(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _table_context(
    db: DbSession, request: Request, filters: svc.AdvisoryFilters, result: svc.AdvisoryListResult
) -> dict[str, object]:
    advisory_ids = [a.id for a in result.items]
    last_comments = svc.last_comments_for(db, advisory_ids)
    ioc_breakdowns = svc.ioc_breakdowns_for(db, advisory_ids)

    def page_url(page: int) -> str:
        params = dict(request.query_params)
        params["page"] = str(page)
        return f"/?{urlencode(params, doseq=True)}"

    return {
        "result": result,
        "filters": filters,
        "filters_active": not filters.is_empty(),
        "last_comments": last_comments,
        "ioc_breakdowns": ioc_breakdowns,
        "now": utcnow(),
        "page_url": page_url,
    }
