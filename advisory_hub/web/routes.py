"""Web UI routes: authentication. The tracker itself lives in ``tracker.py``."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import SESSION_COOKIE, current_principal, db_session, sign
from ..config import settings
from ..core.services.auth import AuthError, LocalAuthProvider, Principal, end_session, start_session

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
auth_provider = LocalAuthProvider()


@router.get("/login", response_class=HTMLResponse)
def login_form(
    request: Request, principal: Principal | None = Depends(current_principal)
) -> object:
    if principal is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"title": "Sign in"})


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: DbSession = Depends(db_session),
) -> object:
    ip = request.client.host if request.client else None
    try:
        user = auth_provider.authenticate(db, identifier=email, secret=password)
    except AuthError:
        db.rollback()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"title": "Sign in", "error": "Invalid email or password.", "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    session = start_session(db, user, ip_address=ip, user_agent=request.headers.get("user-agent"))
    db.commit()

    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE,
        sign(str(session.id)),
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
    )
    return response


@router.post("/logout")
def logout(request: Request, db: DbSession = Depends(db_session)) -> RedirectResponse:
    from ..api.deps import _unsign

    signed = request.cookies.get(SESSION_COOKIE)
    if signed and (sid := _unsign(signed)):
        end_session(db, sid)
        db.commit()
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response
