"""Web UI: import the manual spreadsheet tracker (thin — see
``core.services.tracker_import`` for every rule).

Upload → preview (nothing changes) → Apply. The upload is kept as a blob
between the two requests, the same way the inventory CSV import works, so
no server-side session state is needed.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import db_session
from ..core.models.base import utcnow
from ..core.models.enums import Role
from ..core.services import status_export
from ..core.services import tracker_import as svc
from ..core.services.audit import record
from ..core.services.auth import PermissionDeniedError, Principal
from .tracker import _require_web_principal

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_RESULT_KEYS = ("updated", "changes", "comments", "kept", "not_found")

#: Display order for the preview table — what will change first.
_OUTCOME_ORDER = {
    svc.Outcome.UPDATE: 0,
    svc.Outcome.COMMENT_ONLY: 1,
    svc.Outcome.KEPT: 2,
    svc.Outcome.NOT_FOUND: 3,
    svc.Outcome.UNCHANGED: 4,
    svc.Outcome.NOTHING: 5,
}


def _require_analyst(principal: Principal = Depends(_require_web_principal)) -> Principal:
    try:
        principal.require_role(Role.ANALYST)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    return principal


def _page(
    request: Request,
    principal: Principal,
    *,
    preview: svc.ImportPreview | None = None,
    error: str | None = None,
) -> HTMLResponse:
    changes = (
        sorted(preview.plan.changes, key=lambda c: (_OUTCOME_ORDER[c.outcome], c.entry.ref))
        if preview
        else []
    )
    result = None
    if all(k in request.query_params for k in _RESULT_KEYS):
        try:
            result = {k: int(request.query_params[k]) for k in _RESULT_KEYS}
        except ValueError:
            result = None
    return templates.TemplateResponse(
        request,
        "tracker_import.html",
        {
            "title": "Import manual tracker",
            "principal": principal,
            "active_nav": "tracker",
            "preview": preview,
            "changes": changes,
            "Outcome": svc.Outcome,
            "rules": svc.STATUS_RULES,
            "error": error,
            "result": result,
        },
    )


@router.get("/tracker-import", response_class=HTMLResponse)
def tracker_import_page(
    request: Request, principal: Principal = Depends(_require_analyst)
) -> HTMLResponse:
    return _page(request, principal)


@router.post("/tracker-import/preview", response_class=HTMLResponse)
async def tracker_import_preview(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(_require_analyst),
    db: DbSession = Depends(db_session),
) -> HTMLResponse:
    data = await file.read()
    try:
        preview = svc.preview_import(db, file_bytes=data, filename=file.filename or "tracker")
    except svc.TrackerImportError as exc:
        # Raised while reading the file, before anything is stored.
        return _page(request, principal, error=str(exc))
    db.commit()  # the stored upload, so Apply can re-read it
    return _page(request, principal, preview=preview)


@router.post("/tracker-import/apply")
def tracker_import_apply(
    request: Request,
    blob_id: uuid.UUID = Form(...),
    principal: Principal = Depends(_require_analyst),
    db: DbSession = Depends(db_session),
) -> Response:
    try:
        result = svc.apply_import(
            db,
            blob_id=blob_id,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
    except (svc.TrackerImportError, svc.TrackerBlobNotFoundError) as exc:
        # Both are raised before the first write. Anything failing *during*
        # the apply propagates instead: the request ends without a commit,
        # so the import is all-or-nothing.
        return _page(request, principal, error=str(exc))
    db.commit()
    counts = {
        "updated": result.advisories_updated,
        "changes": result.status_changes,
        "comments": result.comments_added,
        "kept": result.kept,
        "not_found": result.not_found,
    }
    return RedirectResponse(
        f"/tracker-import?{urlencode(counts)}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/status-export.csv")
def status_export_csv(
    request: Request,
    principal: Principal = Depends(_require_web_principal),
    db: DbSession = Depends(db_session),
) -> Response:
    """Every advisory's status, acknowledgement and comment history as a CSV
    the import page can restore from. Any signed-in user — it's what they
    can already read in the tracker — but audit-logged as a bulk export."""
    today = utcnow().date()
    entries = status_export.export_entries(db, today=today)
    text = svc.entries_to_csv(entries)
    record(
        db,
        actor=principal.to_actor(request.client.host if request.client else None),
        action="advisories.status_exported",
        detail={"rows": len(entries)},
    )
    db.commit()
    return Response(
        content=text.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{status_export.export_filename(today)}"'
            )
        },
    )


@router.get("/tracker-import/{blob_id}/csv")
def tracker_import_csv(
    blob_id: uuid.UUID,
    _principal: Principal = Depends(_require_analyst),
    db: DbSession = Depends(db_session),
) -> Response:
    try:
        text, filename = svc.converted_csv(db, blob_id)
    except (svc.TrackerImportError, svc.TrackerBlobNotFoundError):
        raise HTTPException(status_code=404, detail="Upload not found") from None
    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in filename)
    return Response(
        content=text.encode("utf-8-sig"),  # BOM so Excel opens it as UTF-8
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )
