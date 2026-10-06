"""Web UI routes: authentication. The tracker itself lives in ``tracker.py``."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as DbSession

from ..api.deps import SESSION_COOKIE, current_principal, db_session, sign
from ..config import settings
from ..core.models.user import User
from ..core.services import entra_auth as entra
from ..core.services.auth import AuthError, LocalAuthProvider, Principal, end_session, start_session
from ..logging import get_logger

log = get_logger(__name__)
router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
auth_provider = LocalAuthProvider()


def _sso_button(db: DbSession) -> bool:
    """Whether to offer Microsoft sign-in. The login page is the way in for
    the break-glass admin too, so a failure reading the setting hides the
    button instead of failing the page."""
    try:
        return entra.enabled_app(db) is not None
    except SQLAlchemyError:
        db.rollback()
        log.warning("login.sso_setting_unreadable", exc_info=True)
        return False


def _login_page(
    request: Request,
    db: DbSession,
    *,
    error: str | None = None,
    email: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    context = {
        "title": "Sign in",
        "error": error,
        "email": email,
        "sso_enabled": _sso_button(db),
    }
    return templates.TemplateResponse(request, "login.html", context, status_code=status_code)


def _signed_in(request: Request, db: DbSession, user: User) -> RedirectResponse:
    """Start a session and set its cookie — the same for password and Microsoft."""
    ip = request.client.host if request.client else None
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


@router.get("/login", response_class=HTMLResponse)
def login_form(
    request: Request,
    principal: Principal | None = Depends(current_principal),
    db: DbSession = Depends(db_session),
) -> object:
    if principal is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return _login_page(request, db)


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: DbSession = Depends(db_session),
) -> object:
    try:
        user = auth_provider.authenticate(db, identifier=email, secret=password)
    except AuthError:
        db.rollback()
        return _login_page(
            request,
            db,
            error="Invalid email or password.",
            email=email,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return _signed_in(request, db, user)


# ─── Microsoft Entra ID (D-049) ──────────────────────────────────────────────

#: Carries state/nonce/PKCE verifier from /auth/entra/login to the callback.
FLOW_COOKIE = "advisory_hub_entra_flow"
FLOW_MAX_AGE_SECONDS = 600


def _flow_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt="advisory-hub-entra-flow")


@router.get("/auth/entra/login")
def entra_login(db: DbSession = Depends(db_session)) -> RedirectResponse:
    app = entra.enabled_app(db)
    if app is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    url, flow = entra.start_login(app)
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        FLOW_COOKIE,
        _flow_serializer().dumps(flow.to_dict()),
        max_age=FLOW_MAX_AGE_SECONDS,
        path="/auth/entra",
        httponly=True,
        secure=settings.session_cookie_secure,
        # Lax, not Strict: the callback is a top-level redirect from Microsoft.
        samesite="lax",
    )
    return response


@router.get("/auth/entra/callback", response_class=HTMLResponse)
def entra_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    db: DbSession = Depends(db_session),
) -> object:
    flow = None
    raw = request.cookies.get(FLOW_COOKIE)
    if raw:
        try:
            flow = entra.LoginFlow.from_dict(
                _flow_serializer().loads(raw, max_age=FLOW_MAX_AGE_SECONDS)
            )
        except BadSignature:  # includes SignatureExpired
            flow = None

    response: Response
    if error:
        # The person cancelled, or Entra refused (e.g. Conditional Access).
        # Only the error code is shown; the description can be long and odd.
        response = _login_page(
            request,
            db,
            error=f"Microsoft sign-in didn't complete ({error}).",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    else:
        try:
            user = entra.complete_login(
                db,
                code=code,
                state=state,
                flow=flow,
                ip_address=request.client.host if request.client else None,
            )
        except entra.EntraLoginError as exc:
            db.rollback()
            response = _login_page(
                request, db, error=exc.user_message, status_code=status.HTTP_403_FORBIDDEN
            )
        else:
            response = _signed_in(request, db, user)
    response.delete_cookie(FLOW_COOKIE, path="/auth/entra")
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
