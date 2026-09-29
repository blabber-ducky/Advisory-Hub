"""Authentication and authorisation.

All authz decisions happen here, never in templates or route handlers
(CLAUDE.md §2.3). ``AuthProvider`` exists so Entra ID OIDC can be dropped in at
Phase 4 without touching call sites — see D-003.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ..models.base import utcnow
from ..models.enums import ActorKind, Role
from ..models.user import ApiToken, Session, User
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.tokens import SCOPE_MIN_ROLE, split_token, verify_token
from .audit import Actor, record


class AuthError(Exception):
    """Authentication failed. Deliberately carries no detail about *why* —
    the caller must not be able to distinguish a bad password from a missing
    account."""


class PermissionDeniedError(Exception):
    def __init__(self, required: str) -> None:
        super().__init__(f"Requires {required}")
        self.required = required


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller, however they authenticated."""

    kind: ActorKind
    user: User | None = None
    token: ApiToken | None = None
    scopes: tuple[str, ...] = ()

    @property
    def role(self) -> Role | None:
        return self.user.role if self.user else None

    @property
    def display(self) -> str:
        if self.user:
            return self.user.display_name
        if self.token:
            return f"token:{self.token.name}"
        return "anonymous"

    def to_actor(self, ip_address: str | None = None) -> Actor:
        return Actor(
            kind=self.kind,
            user_id=self.user.id if self.user else None,
            label=self.display,
            ip_address=ip_address,
        )

    def require_role(self, required: Role) -> None:
        if self.user is None or not self.user.role.satisfies(required):
            raise PermissionDeniedError(required.value)

    def require_scope(self, required: str) -> None:
        # A logged-in user's role implies scopes, translated via
        # SCOPE_MIN_ROLE — a VIEWER must not pass an `advisories:write` check
        # just because they're authenticated. Tokens carry scopes explicitly.
        if self.kind is ActorKind.USER:
            min_role = SCOPE_MIN_ROLE.get(required)
            if min_role is not None and (
                self.user is None or not self.user.role.satisfies(min_role)
            ):
                raise PermissionDeniedError(required)
            return
        if required not in self.scopes:
            raise PermissionDeniedError(required)


class AuthProvider(Protocol):
    """Swap point for SSO. Implementations must not leak *why* auth failed."""

    def authenticate(self, session: DbSession, *, identifier: str, secret: str) -> User: ...


class LocalAuthProvider:
    """Username/password against ``user_account``. Phase 0 default."""

    def authenticate(self, session: DbSession, *, identifier: str, secret: str) -> User:
        user = session.scalar(select(User).where(User.email == identifier.strip().lower()))
        stored = user.password_hash if user else None

        # Always verify, even when the user is absent, so timing doesn't leak
        # account existence.
        if not verify_password(secret, stored):
            raise AuthError("Invalid credentials")
        assert user is not None  # verify_password(_, None) is always False

        if not user.is_active:
            raise AuthError("Invalid credentials")

        if user.password_hash and needs_rehash(user.password_hash):
            user.password_hash = hash_password(secret)

        user.last_login_at = utcnow()
        return user


def create_user(
    session: DbSession,
    *,
    email: str,
    display_name: str,
    password: str | None,
    role: Role = Role.VIEWER,
    actor: Actor | None = None,
) -> User:
    email = email.strip().lower()
    if session.scalar(select(User).where(User.email == email)):
        raise ValueError(f"A user with email {email} already exists")
    user = User(
        email=email,
        display_name=display_name.strip(),
        password_hash=hash_password(password) if password else None,
        role=role,
        is_active=True,
    )
    session.add(user)
    session.flush()
    record(
        session,
        actor=actor or Actor.system("cli"),
        action="user.created",
        entity_type="user",
        entity_id=user.id,
        detail={"email": email, "role": role.value},
    )
    return user


# ─── Sessions ────────────────────────────────────────────────────────────────


def start_session(
    db: DbSession, user: User, *, ip_address: str | None = None, user_agent: str | None = None
) -> Session:
    sess = Session(
        user_id=user.id,
        expires_at=utcnow() + timedelta(seconds=settings.session_max_age_seconds),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:500] or None,
    )
    db.add(sess)
    db.flush()
    record(
        db,
        actor=Actor(ActorKind.USER, user.id, user.display_name, ip_address),
        action="auth.login",
        entity_type="user",
        entity_id=user.id,
    )
    return sess


def resolve_session(db: DbSession, session_id: str) -> Principal | None:
    try:
        sid = uuid.UUID(session_id)
    except (ValueError, AttributeError):
        return None
    sess = db.get(Session, sid)
    if sess is None or not sess.is_valid:
        return None
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        return None
    return Principal(kind=ActorKind.USER, user=user)


def end_session(db: DbSession, session_id: str) -> None:
    try:
        sid = uuid.UUID(session_id)
    except (ValueError, AttributeError):
        return
    sess = db.get(Session, sid)
    if sess is not None and sess.revoked_at is None:
        sess.revoked_at = utcnow()
        record(
            db,
            actor=Actor(ActorKind.USER, sess.user_id, None, None),
            action="auth.logout",
            entity_type="user",
            entity_id=sess.user_id,
        )


# ─── API tokens ──────────────────────────────────────────────────────────────


def resolve_api_token(db: DbSession, plaintext: str) -> Principal | None:
    parts = split_token(plaintext)
    if parts is None:
        return None
    prefix, full = parts

    # The prefix narrows the candidate set; the Argon2 verify is what decides.
    candidates = db.scalars(select(ApiToken).where(ApiToken.token_prefix == prefix)).all()
    for token in candidates:
        if not token.is_valid:
            continue
        if verify_token(full, token.token_hash):
            token.last_used_at = utcnow()
            return Principal(
                kind=ActorKind.API_TOKEN, token=token, scopes=tuple(token.scopes or ())
            )
    return None
