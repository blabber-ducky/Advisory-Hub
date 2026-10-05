"""Affected Software tab — the estate-wide "what's currently affected"
view, sourced from every advisory's most recent completed scan
(`core.services.scan.list_affected_software()`). Read-only except for the
"Refresh all" action, which re-runs `scan.refresh_all_scans()` against each
already-scanned advisory's inventory sources' *current* latest snapshots.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import current_principal, db_session
from ..core.models.enums import Role
from ..core.services import scan as svc
from ..core.services.auth import PermissionDeniedError, Principal

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _require_web_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return principal


@router.get("/affected-software", response_class=HTMLResponse)
def index(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    context = _table_context(db, principal)
    if request.headers.get("hx-request") == "true":
        return templates.TemplateResponse(request, "_affected_software_table.html", context)
    context.update(
        {"principal": principal, "title": "Affected Software", "active_nav": "affected_software"}
    )
    return templates.TemplateResponse(request, "affected_software_index.html", context)


@router.post("/affected-software/refresh", response_class=HTMLResponse)
def refresh_all(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> object:
    try:
        principal.require_role(Role.ANALYST)
        report = svc.refresh_all_scans(
            db, actor=principal.to_actor(request.client.host if request.client else None)
        )
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    context = _table_context(db, principal)
    context["refresh_report"] = report
    return templates.TemplateResponse(request, "_affected_software_table.html", context)


def _table_context(db: DbSession, principal: Principal) -> dict[str, object]:
    return {
        "rows": svc.list_affected_software(db),
        "can_refresh": principal.user is not None and principal.user.role.satisfies(Role.ANALYST),
    }
