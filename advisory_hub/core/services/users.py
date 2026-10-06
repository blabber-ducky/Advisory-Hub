"""User administration: list, create, change role, (de)activate, reset password.

Every function takes the acting ``Principal`` and enforces ADMIN itself — the
web adapter only translates errors (CLAUDE.md §2.3). Two rules protect
against lock-out:

- an admin cannot change their own role or deactivate themselves;
- the last active admin can never be demoted or deactivated. The check locks
  the active-admin rows, so two admins demoting each other concurrently
  cannot both succeed.

A role change takes effect on the user's next request (``resolve_session``
reads the role from the database every time). Deactivating a user or
resetting their password ends all of their sessions.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from ..models.base import utcnow
from ..models.enums import Role
from ..models.user import Session, User
from ..security.passwords import hash_password
from .audit import record
from .auth import Principal, create_user

MIN_PASSWORD_LENGTH = 12


class UserAdminError(ValueError):
    """A request that breaks a rule; the message is safe to show the admin."""


class UserNotFoundError(LookupError):
    pass


def list_users(db: DbSession, principal: Principal) -> list[User]:
    principal.require_role(Role.ADMIN)
    return list(
        db.scalars(select(User).order_by(User.is_active.desc(), func.lower(User.display_name)))
    )


def add_user(
    db: DbSession,
    principal: Principal,
    *,
    email: str,
    display_name: str,
    role: Role,
    password: str,
    ip_address: str | None = None,
) -> User:
    """``password`` may be blank when Microsoft sign-in is enabled: the user
    then signs in with Microsoft only, and their first sign-in links the
    account by email (use their Entra sign-in name / UPN as the email)."""
    principal.require_role(Role.ADMIN)
    email = email.strip()
    if "@" not in email or len(email) > 320:
        raise UserAdminError("Enter a valid email address.")
    if not display_name.strip():
        raise UserAdminError("Enter a display name.")
    if password:
        _check_password(password)
    elif not _sso_enabled(db):
        raise UserAdminError(
            "Set an initial password — Microsoft sign-in isn't enabled, so it's the only way in."
        )
    try:
        return create_user(
            db,
            email=email,
            display_name=display_name,
            password=password or None,
            role=role,
            actor=principal.to_actor(ip_address),
        )
    except ValueError as exc:  # duplicate email
        raise UserAdminError(str(exc)) from None


def change_role(
    db: DbSession,
    principal: Principal,
    user_id: uuid.UUID,
    role: Role,
    *,
    ip_address: str | None = None,
) -> User:
    principal.require_role(Role.ADMIN)
    user = _get(db, user_id)
    if user.role is role:
        return user
    if _is_self(principal, user):
        raise UserAdminError("You can't change your own role — ask another admin.")
    if user.role is Role.ADMIN and user.is_active:
        _ensure_another_active_admin(db, user)
    previous = user.role
    user.role = role
    record(
        db,
        actor=principal.to_actor(ip_address),
        action="user.role_changed",
        entity_type="user",
        entity_id=user.id,
        detail={"email": user.email, "from": previous.value, "to": role.value},
    )
    return user


def set_active(
    db: DbSession,
    principal: Principal,
    user_id: uuid.UUID,
    active: bool,
    *,
    ip_address: str | None = None,
) -> User:
    principal.require_role(Role.ADMIN)
    user = _get(db, user_id)
    if user.is_active is active:
        return user
    if not active:
        if _is_self(principal, user):
            raise UserAdminError("You can't deactivate your own account.")
        if user.role is Role.ADMIN:
            _ensure_another_active_admin(db, user)
        _end_sessions(db, user)
    user.is_active = active
    record(
        db,
        actor=principal.to_actor(ip_address),
        action="user.activated" if active else "user.deactivated",
        entity_type="user",
        entity_id=user.id,
        detail={"email": user.email},
    )
    return user


def reset_password(
    db: DbSession,
    principal: Principal,
    user_id: uuid.UUID,
    password: str,
    *,
    ip_address: str | None = None,
) -> User:
    principal.require_role(Role.ADMIN)
    user = _get(db, user_id)
    if user.external_subject is not None:
        raise UserAdminError(
            f"{user.display_name} signs in with Microsoft, so a password can't be used. "
            "Unlink their Microsoft account first if they need a local password."
        )
    _check_password(password)
    user.password_hash = hash_password(password)
    if not _is_self(principal, user):
        # Signs them out everywhere. An admin resetting their own password
        # keeps the session they're using.
        _end_sessions(db, user)
    record(
        db,
        actor=principal.to_actor(ip_address),
        action="user.password_reset",
        entity_type="user",
        entity_id=user.id,
        detail={"email": user.email},
    )
    return user


def unlink_entra(
    db: DbSession,
    principal: Principal,
    user_id: uuid.UUID,
    *,
    ip_address: str | None = None,
) -> User:
    """Detach the user from their Microsoft account — for a mis-link or an
    Entra account that was deleted and re-created. Their next Microsoft
    sign-in links again by email; without one they need a password reset to
    sign in. Ends their sessions."""
    principal.require_role(Role.ADMIN)
    user = _get(db, user_id)
    if user.external_subject is None:
        return user
    previous = user.external_subject
    user.external_subject = None
    if not _is_self(principal, user):
        _end_sessions(db, user)
    record(
        db,
        actor=principal.to_actor(ip_address),
        action="user.entra_unlinked",
        entity_type="user",
        entity_id=user.id,
        detail={"email": user.email, "was": previous},
    )
    return user


def sso_enabled(db: DbSession) -> bool:
    return _sso_enabled(db)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _sso_enabled(db: DbSession) -> bool:
    from .entra_auth import enabled_app

    return enabled_app(db) is not None


def _get(db: DbSession, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise UserNotFoundError(str(user_id))
    return user


def _is_self(principal: Principal, user: User) -> bool:
    return principal.user is not None and principal.user.id == user.id


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserAdminError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")


def _ensure_another_active_admin(db: DbSession, user: User) -> None:
    """Raise unless an active admin other than ``user`` would remain."""
    admins = db.scalars(
        select(User.id).where(User.role == Role.ADMIN, User.is_active.is_(True)).with_for_update()
    ).all()
    if not any(admin_id != user.id for admin_id in admins):
        raise UserAdminError("This is the last active admin — make someone else an admin first.")


def _end_sessions(db: DbSession, user: User) -> None:
    db.execute(
        update(Session)
        .where(Session.user_id == user.id, Session.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
