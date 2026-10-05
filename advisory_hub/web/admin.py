"""Admin panel — user administration and global API integrations.

Users: add, change role, deactivate/reactivate, reset password. Every rule
(ADMIN only, no self-demotion, never lose the last admin) lives in
``core.services.users``; these routes translate its errors into the users
section, which each action re-renders in place.

Currently NVD and VirusTotal, the two integrations that previously could
only be set via environment variables and a container restart. Inventory
API integrations (Desktop Central, Azure ARM, MS Graph) already have full
GUI management under the Inventory tab (source CRUD, per-source
credentials) — deliberately not folded in here, see docs/decisions.md.

ADMIN role required, matching docs/architecture.md §6 ("Admin: Analyst +
manage users, sources, inventory integrations, API tokens").
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import current_principal, db_session
from ..core.models.enums import Role, SystemIntegrationKind
from ..core.services import system_integrations as svc
from ..core.services import users as users_svc
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
        **_users_context(db, principal),
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


# ─── Users ───────────────────────────────────────────────────────────────────


def _users_context(
    db: DbSession,
    principal: Principal,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> dict[str, object]:
    return {
        "principal": principal,
        "users": users_svc.list_users(db, principal),
        "roles": list(Role),
        "min_password_length": users_svc.MIN_PASSWORD_LENGTH,
        "users_error": error,
        "users_notice": notice,
    }


def _users_action(
    request: Request,
    db: DbSession,
    principal: Principal,
    action: Callable[[str | None], str],
) -> HTMLResponse:
    """Run ``action`` (which returns a confirmation message), commit, and
    re-render the users section — with the rule it broke, if it broke one."""
    ip = request.client.host if request.client else None
    try:
        # A savepoint, so a refused action undoes only its own writes.
        with db.begin_nested():
            notice = action(ip)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except users_svc.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found") from None
    except users_svc.UserAdminError as exc:
        context = _users_context(db, principal, error=str(exc))
        return templates.TemplateResponse(request, "_admin_users.html", context)
    db.commit()
    context = _users_context(db, principal, notice=notice)
    return templates.TemplateResponse(request, "_admin_users.html", context)


@router.post("/admin/users", response_class=HTMLResponse)
def add_user(
    request: Request,
    email: str = Form(""),
    display_name: str = Form(""),
    role: Role = Form(Role.VIEWER),
    password: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    def action(ip: str | None) -> str:
        user = users_svc.add_user(
            db,
            principal,
            email=email,
            display_name=display_name,
            role=role,
            password=password,
            ip_address=ip,
        )
        return f"Added {user.email} as {user.role.value.title()}."

    return _users_action(request, db, principal, action)


@router.post("/admin/users/{user_id}/role", response_class=HTMLResponse)
def change_role(
    user_id: uuid.UUID,
    request: Request,
    role: Role = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    def action(ip: str | None) -> str:
        user = users_svc.change_role(db, principal, user_id, role, ip_address=ip)
        return f"{user.display_name} is now {user.role.value.title()}."

    return _users_action(request, db, principal, action)


@router.post("/admin/users/{user_id}/active", response_class=HTMLResponse)
def set_active(
    user_id: uuid.UUID,
    request: Request,
    active: bool = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    def action(ip: str | None) -> str:
        user = users_svc.set_active(db, principal, user_id, active, ip_address=ip)
        if active:
            return f"Reactivated {user.display_name}."
        return f"Deactivated {user.display_name} and signed them out."

    return _users_action(request, db, principal, action)


@router.post("/admin/users/{user_id}/password", response_class=HTMLResponse)
def reset_password(
    user_id: uuid.UUID,
    request: Request,
    password: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    def action(ip: str | None) -> str:
        user = users_svc.reset_password(db, principal, user_id, password, ip_address=ip)
        return f"Password reset for {user.display_name}."

    return _users_action(request, db, principal, action)
