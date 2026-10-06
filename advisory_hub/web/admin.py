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
from ..core.models.enums import API_KEY_KINDS, Role, SystemIntegrationKind
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
        "entra_cards": [_entra_context(db, kind) for kind in svc.ENTRA_KINDS],
        **_ivanti_context(db),
        **_sources_context(db),
        **_users_context(db, principal),
    }
    return templates.TemplateResponse(request, "admin_index.html", context)


def _require_api_key_kind(kind: SystemIntegrationKind) -> None:
    """The key/toggle routes are for NVD and VirusTotal only; the Entra apps
    have their own settings routes and rules."""
    if kind not in API_KEY_KINDS:
        raise HTTPException(status_code=404, detail="Not an API-key integration")


def _integration_rows(db: DbSession) -> list[dict[str, object]]:
    rows = svc.list_integrations(db)
    out: list[dict[str, object]] = []
    for kind in API_KEY_KINDS:
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
    _require_api_key_kind(kind)
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
    _require_api_key_kind(kind)
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
        "sso_enabled": users_svc.sso_enabled(db),
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


@router.post("/admin/users/{user_id}/unlink-entra", response_class=HTMLResponse)
def unlink_entra(
    user_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    def action(ip: str | None) -> str:
        user = users_svc.unlink_entra(db, principal, user_id, ip_address=ip)
        return f"Unlinked {user.display_name}'s Microsoft account."

    return _users_action(request, db, principal, action)


# ─── Microsoft Entra apps: sign-in and mailbox sync (D-049) ──────────────────


def _entra_kind(slug: str) -> SystemIntegrationKind:
    try:
        kind = SystemIntegrationKind(slug.upper())
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown integration") from None
    if kind not in svc.ENTRA_KINDS:
        raise HTTPException(status_code=404, detail="Unknown integration")
    return kind


def _entra_context(
    db: DbSession,
    kind: SystemIntegrationKind,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> dict[str, object]:
    from ..config import settings
    from ..core.services import entra_auth, mailbox_sync

    return {
        "kind": kind,
        "app": svc.entra_app(db, kind),
        "redirect_uri": entra_auth.redirect_uri() if settings.public_base_url else None,
        "sync_state": mailbox_sync.state(db)
        if kind is SystemIntegrationKind.MAILBOX_SYNC
        else None,
        "poll_default": svc.MAILBOX_POLL_DEFAULT,
        "entra_error": error,
        "entra_notice": notice,
    }


def _entra_action(
    request: Request,
    db: DbSession,
    principal: Principal,
    kind: SystemIntegrationKind,
    action: Callable[[], str],
) -> HTMLResponse:
    """ADMIN only; run ``action`` in a savepoint, commit, re-render the card."""
    try:
        principal.require_role(Role.ADMIN)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    try:
        with db.begin_nested():
            notice = action()
    except svc.EntraSettingsError as exc:
        context = _entra_context(db, kind, error=str(exc))
        return templates.TemplateResponse(request, "_admin_entra_card.html", context)
    db.commit()
    context = _entra_context(db, kind, notice=notice)
    return templates.TemplateResponse(request, "_admin_entra_card.html", context)


@router.post("/admin/entra/{slug}/settings", response_class=HTMLResponse)
def save_entra_settings(
    slug: str,
    request: Request,
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    mailbox: str = Form(""),
    folder: str = Form(""),
    poll_seconds: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    kind = _entra_kind(slug)

    def action() -> str:
        svc.save_entra_settings(
            db,
            kind,
            config={
                "tenant_id": tenant_id,
                "client_id": client_id,
                "mailbox": mailbox,
                "folder": folder,
                "poll_seconds": poll_seconds,
            },
            client_secret=client_secret,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        return "Saved."

    return _entra_action(request, db, principal, kind, action)


@router.post("/admin/entra/{slug}/enabled", response_class=HTMLResponse)
def set_entra_enabled(
    slug: str,
    request: Request,
    enabled: bool = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    kind = _entra_kind(slug)

    def action() -> str:
        svc.set_entra_enabled(
            db,
            kind,
            enabled=enabled,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        return "Enabled." if enabled else "Disabled."

    return _entra_action(request, db, principal, kind, action)


@router.post("/admin/entra/{slug}/test", response_class=HTMLResponse)
def test_entra(
    slug: str,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import entra_auth, mailbox_sync

    kind = _entra_kind(slug)

    def action() -> str:
        if kind is SystemIntegrationKind.MAILBOX_SYNC:
            ok, message = mailbox_sync.check_connection(db)
        else:
            app = svc.entra_app(db, kind)
            if not app.tenant_id:
                raise svc.EntraSettingsError("Set the tenant ID first.")
            ok, message = entra_auth.check_configuration(app)
        if not ok:
            raise svc.EntraSettingsError(message)
        return message

    return _entra_action(request, db, principal, kind, action)


@router.post("/admin/entra/mailbox_sync/sync-now", response_class=HTMLResponse)
def mailbox_sync_now(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    """Sync now, then ingest what arrived — like "Scan inbox now"."""
    from ..core.services import mailbox_sync
    from ..ingest.pipeline import process_inbox

    try:
        principal.require_role(Role.ADMIN)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    report = mailbox_sync.run_sync(db)
    db.commit()  # the state row records the outcome either way
    kind = SystemIntegrationKind.MAILBOX_SYNC
    if report.status != "ok":
        context = _entra_context(db, kind, error=report.message)
        return templates.TemplateResponse(request, "_admin_entra_card.html", context)
    notice = report.message + "."
    if report.fetched:
        outcomes = process_inbox()
        n = {s: sum(o.status == s for o in outcomes) for s in ("INGESTED", "DUPLICATE", "FAILED")}
        notice += (
            f" Processed: {n['INGESTED']} ingested, {n['DUPLICATE']} duplicate(s), "
            f"{n['FAILED']} failed."
        )
    context = _entra_context(db, kind, notice=notice)
    return templates.TemplateResponse(request, "_admin_entra_card.html", context)


# ─── Ivanti ITSM (D-050) ─────────────────────────────────────────────────────


def _ivanti_context(
    db: DbSession,
    *,
    error: str | None = None,
    notice: str | None = None,
    report: object | None = None,
) -> dict[str, object]:
    from ..core.services import tickets

    return {
        "ivanti": tickets.get_settings(db),
        "ivanti_levels": [(lvl, tickets.LEVEL_LABELS[lvl]) for lvl in tickets.LEVELS],
        "ivanti_placeholders": tickets.PLACEHOLDERS,
        "ivanti_error": error,
        "ivanti_notice": notice,
        "ivanti_report": report,
    }


def _ivanti_response(
    request: Request, db: DbSession, principal: Principal, action: Callable[[], object]
) -> HTMLResponse:
    """ADMIN only; run ``action`` in a savepoint, commit, re-render the card.
    ``action`` returns a notice string or a Test report."""
    from ..core.services import tickets

    try:
        principal.require_role(Role.ADMIN)
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    try:
        with db.begin_nested():
            outcome = action()
    except tickets.TicketError as exc:
        context = _ivanti_context(db, error=str(exc))
        return templates.TemplateResponse(request, "_admin_ivanti_card.html", context)
    db.commit()
    if isinstance(outcome, tickets.TestReport):
        context = _ivanti_context(db, report=outcome)
    else:
        context = _ivanti_context(db, notice=str(outcome))
    return templates.TemplateResponse(request, "_admin_ivanti_card.html", context)


@router.post("/admin/ivanti/settings", response_class=HTMLResponse)
async def save_ivanti_settings(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import tickets

    form = await request.form()

    def field(name: str) -> str:
        value = form.get(name)
        return value if isinstance(value, str) else ""

    # Only what the form actually sent: an absent field keeps its current
    # value; a blank one in Advanced falls back to the default.
    def sent(name: str) -> str | None:
        value = form.get(name)
        return value if isinstance(value, str) else None

    advanced: dict[str, object] = {}
    for key in (
        "tenant_id", "object_type", "number_field", "subject_field", "description_field",
        "subject_template", "description_template", "extra_fields", "link_template",
    ):  # fmt: skip
        value = sent(key)
        if value is not None and (value.strip() or key in ("tenant_id", "extra_fields")):
            advanced[key] = value
    if sent("base_url") is not None and "level_service_field" in form:
        advanced["attach_pdfs"] = field("attach_pdfs") == "on"
    levels = {
        lvl: {
            key: value
            for key in ("field", "bo", "display", "parent")
            if (value := sent(f"level_{lvl}_{key}")) is not None
        }
        for lvl in tickets.LEVELS
    }
    if any(levels.values()):
        advanced["levels"] = levels

    def action() -> str:
        result = tickets.save_settings(
            db,
            base_url=field("base_url"),
            api_key=field("api_key"),
            advanced=advanced,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        return "Saved." + (" Run Test before enabling." if not result.tested_at else "")

    return _ivanti_response(request, db, principal, action)


@router.post("/admin/ivanti/test", response_class=HTMLResponse)
def test_ivanti(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import tickets

    return _ivanti_response(
        request,
        db,
        principal,
        lambda: tickets.run_test(
            db, actor=principal.to_actor(request.client.host if request.client else None)
        ),
    )


@router.post("/admin/ivanti/enabled", response_class=HTMLResponse)
def set_ivanti_enabled(
    request: Request,
    enabled: bool = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import tickets

    def action() -> str:
        tickets.set_ivanti_enabled(
            db,
            enabled=enabled,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        return "Enabled — analysts now see Create ticket on advisories." if enabled else "Disabled."

    return _ivanti_response(request, db, principal, action)


@router.post("/admin/ivanti/refresh-lists", response_class=HTMLResponse)
def refresh_ivanti_lists(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import tickets

    def action() -> str:
        tickets.clear_cache()
        return "Lists will be re-read from Ivanti the next time they're needed."

    return _ivanti_response(request, db, principal, action)


# ─── Sources ─────────────────────────────────────────────────────────────────


def _sources_context(
    db: DbSession, *, error: str | None = None, notice: str | None = None
) -> dict[str, object]:
    from ..core.services import sources

    return {
        "source_rows": sources.sources_with_counts(db),
        "sources_error": error,
        "sources_notice": notice,
    }


def _sources_action(
    request: Request, db: DbSession, principal: Principal, action: Callable[[], str]
) -> HTMLResponse:
    from ..core.services import sources

    try:
        with db.begin_nested():
            notice = action()
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except LookupError:
        raise HTTPException(status_code=404, detail="Source not found") from None
    except sources.SourceAdminError as exc:
        context = _sources_context(db, error=str(exc))
        return templates.TemplateResponse(request, "_admin_sources.html", context)
    db.commit()
    context = _sources_context(db, notice=notice)
    return templates.TemplateResponse(request, "_admin_sources.html", context)


@router.post("/admin/sources", response_class=HTMLResponse)
def add_source(
    request: Request,
    name: str = Form(""),
    short_code: str = Form(""),
    sender_patterns: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import sources

    def action() -> str:
        source = sources.create_source(
            db, principal, name=name, short_code=short_code, sender_patterns=sender_patterns
        )
        return f"Added {source.short_code} — {source.name}."

    return _sources_action(request, db, principal, action)


@router.post("/admin/sources/{source_id}", response_class=HTMLResponse)
def edit_source(
    source_id: uuid.UUID,
    request: Request,
    name: str = Form(""),
    short_code: str = Form(""),
    sender_patterns: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import sources

    def action() -> str:
        source = sources.update_source(
            db,
            principal,
            source_id,
            name=name,
            short_code=short_code,
            sender_patterns=sender_patterns,
        )
        return f"Saved {source.short_code}."

    return _sources_action(request, db, principal, action)


@router.post("/admin/sources/{source_id}/active", response_class=HTMLResponse)
def set_source_active(
    source_id: uuid.UUID,
    request: Request,
    active: bool = Form(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    from ..core.services import sources

    def action() -> str:
        source = sources.set_source_active(db, principal, source_id, active)
        return f"{'Reactivated' if active else 'Deactivated'} {source.short_code}."

    return _sources_action(request, db, principal, action)
