"""Admin panel — GUI configuration for global API integrations.

Currently NVD and VirusTotal, the two integrations that previously could
only be set via environment variables and a container restart. Inventory
API integrations (Desktop Central, Azure ARM, MS Graph) already have full
GUI management under the Inventory tab (source CRUD, per-source
credentials) — deliberately not folded in here, see docs/decisions.md.

ADMIN role required, matching docs/architecture.md §6 ("Admin: Analyst +
manage users, sources, inventory integrations, API tokens").
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import current_principal, db_session
from ..core.models.enums import Role, SystemIntegrationKind
from ..core.services import system_integrations as svc
from ..core.services.auth import PermissionDeniedError, Principal

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _require_web_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return principal


@router.get("/admin", response_class=HTMLResponse)
def index(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    if principal.user is None or not principal.user.role.satisfies(Role.ADMIN):
        raise HTTPException(status_code=403, detail="Admin role required")
    context = {
        "principal": principal,
        "title": "Admin",
        "active_nav": "admin",
        "integrations": _integration_rows(db),
    }
    return templates.TemplateResponse(request, "admin_index.html", context)


def _integration_rows(db: DbSession) -> list[dict[str, object]]:
    rows = svc.list_integrations(db)
    out: list[dict[str, object]] = []
    for kind in SystemIntegrationKind:
        row: dict[str, object] = {
            "kind": kind,
            "row": rows[kind],
            "resolved": svc.resolve_credential(db, kind),
        }
        out.append(row)
    return out


@router.post("/admin/integrations/{kind}/key", response_class=HTMLResponse)
def set_api_key(
    kind: SystemIntegrationKind,
    request: Request,
    api_key: str = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    try:
        principal.require_role(Role.ADMIN)
        svc.set_api_key(
            db,
            kind,
            api_key=api_key,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except ValueError as exc:
        db.rollback()
        context = {"integrations": _integration_rows(db), "form_error": str(exc)}
        return templates.TemplateResponse(request, "admin_index.html", context)

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/admin"
    return response


@router.post("/admin/integrations/{kind}/toggle", response_class=HTMLResponse)
def toggle_enabled(
    kind: SystemIntegrationKind,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    try:
        principal.require_role(Role.ADMIN)
        current = svc.get_integration(db, kind)
        currently_enabled = current.enabled if current is not None else True
        svc.set_enabled(
            db,
            kind,
            enabled=not currently_enabled,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/admin"
    return response
