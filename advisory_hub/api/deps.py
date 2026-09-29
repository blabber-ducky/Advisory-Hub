"""FastAPI dependencies: session, principal resolution, authorisation guards."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy.orm import Session as DbSession

from ..config import settings
from ..core.models.enums import Role
from ..core.services.auth import (
    PermissionDeniedError,
    Principal,
    resolve_api_token,
    resolve_session,
)
from ..db import get_session

SESSION_COOKIE = "advisory_hub_session"


def db_session() -> Iterator[DbSession]:
    yield from get_session()


def current_principal(request: Request, db: DbSession = Depends(db_session)) -> Principal | None:
    """Resolve a caller from either a bearer token or a session cookie."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return resolve_api_token(db, auth[7:].strip())

    signed = request.cookies.get(SESSION_COOKIE)
    if signed:
        session_id = _unsign(signed)
        if session_id:
            return resolve_session(db, session_id)
    return None


def require_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_role(required: Role) -> Callable[[Principal], Principal]:
    def _guard(principal: Principal = Depends(require_principal)) -> Principal:
        if principal.user is None or not principal.user.role.satisfies(required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return _guard


def require_scope(scope: str) -> Callable[[Principal], Principal]:
    def _guard(principal: Principal = Depends(require_principal)) -> Principal:
        try:
            principal.require_scope(scope)
        except PermissionDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires scope {scope}"
            ) from exc
        return principal

    return _guard


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ─── Cookie signing ──────────────────────────────────────────────────────────


def _serializer() -> URLSafeSerializer:
    # Read the key at call time, not import time, so a rotated SECRET_KEY takes
    # effect without a code reload.
    return URLSafeSerializer(settings.secret_key, salt="advisory-hub-session")


def sign(session_id: str) -> str:
    return str(_serializer().dumps(session_id))


def _unsign(signed: str) -> str | None:
    try:
        value = _serializer().loads(signed)
    except BadSignature:
        return None
    return value if isinstance(value, str) else None
