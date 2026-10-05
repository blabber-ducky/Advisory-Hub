"""User administration: core.services.users rules and the /admin users section."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from advisory_hub.core.models.enums import ActorKind, Role
from advisory_hub.core.models.user import AuditLog, User
from advisory_hub.core.services import users as svc
from advisory_hub.core.services.auth import (
    PermissionDeniedError,
    Principal,
    resolve_session,
    start_session,
)

PASSWORD = "a-long-enough-password"


def _user(db, role: Role = Role.VIEWER, *, active: bool = True) -> User:
    user = User(
        email=f"{role.value.lower()}-{uuid.uuid4().hex[:6]}@example.invalid",
        display_name=f"{role.value.title()} {uuid.uuid4().hex[:4]}",
        role=role,
        is_active=active,
    )
    db.add(user)
    db.flush()
    return user


def _as(user: User) -> Principal:
    return Principal(kind=ActorKind.USER, user=user)


def _audit(db, user: User) -> list[str]:
    return list(db.scalars(select(AuditLog.action).where(AuditLog.entity_id == user.id)))


@pytest.mark.integration
class TestUserService:
    def test_only_admins(self, db) -> None:
        analyst = _user(db, Role.ANALYST)
        target = _user(db)
        with pytest.raises(PermissionDeniedError):
            svc.list_users(db, _as(analyst))
        with pytest.raises(PermissionDeniedError):
            svc.change_role(db, _as(analyst), target.id, Role.ADMIN)
        with pytest.raises(PermissionDeniedError):
            svc.add_user(
                db, _as(analyst), email="x@example.invalid", display_name="X",
                role=Role.VIEWER, password=PASSWORD,
            )  # fmt: skip

    def test_add_user_validates_and_audits(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        with pytest.raises(svc.UserAdminError, match="at least 12"):
            svc.add_user(
                db, _as(admin), email="n@example.invalid", display_name="N",
                role=Role.ANALYST, password="short",
            )  # fmt: skip
        user = svc.add_user(
            db, _as(admin), email=" New@Example.invalid ", display_name="New",
            role=Role.ANALYST, password=PASSWORD,
        )  # fmt: skip
        assert user.email == "new@example.invalid"
        assert (user.role, user.is_active) == (Role.ANALYST, True)
        assert _audit(db, user) == ["user.created"]
        with pytest.raises(svc.UserAdminError, match="already exists"):
            svc.add_user(
                db, _as(admin), email="new@example.invalid", display_name="Dup",
                role=Role.VIEWER, password=PASSWORD,
            )  # fmt: skip

    def test_change_role_is_audited_with_from_and_to(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        target = _user(db, Role.VIEWER)
        svc.change_role(db, _as(admin), target.id, Role.ANALYST)
        assert target.role is Role.ANALYST
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "user.role_changed"))
        assert entry is not None and entry.actor_id == admin.id
        assert entry.detail == {"email": target.email, "from": "VIEWER", "to": "ANALYST"}

    def test_unchanged_role_writes_nothing(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        target = _user(db, Role.ANALYST)
        svc.change_role(db, _as(admin), target.id, Role.ANALYST)
        assert _audit(db, target) == []

    def test_cannot_change_own_role_or_deactivate_self(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        _user(db, Role.ADMIN)  # another admin exists — still refused
        with pytest.raises(svc.UserAdminError, match="your own role"):
            svc.change_role(db, _as(admin), admin.id, Role.VIEWER)
        with pytest.raises(svc.UserAdminError, match="your own account"):
            svc.set_active(db, _as(admin), admin.id, False)

    def test_last_active_admin_is_protected(self, db) -> None:
        # Existing admins in the shared test DB would mask the rule.
        for other in db.scalars(select(User).where(User.role == Role.ADMIN)):
            other.is_active = False
        acting = _user(db, Role.ADMIN)
        other = _user(db, Role.ADMIN)
        _user(db, Role.ADMIN, active=False)  # inactive admins don't count

        svc.change_role(db, _as(acting), other.id, Role.ANALYST)  # acting remains
        assert other.role is Role.ANALYST

        # `acting` is now the only active admin; the API-token-free way to
        # reach this is another admin acting on them, so simulate one that's
        # been deactivated meanwhile.
        ghost = _user(db, Role.ADMIN, active=False)
        with pytest.raises(svc.UserAdminError, match="last active admin"):
            svc.change_role(db, _as(ghost), acting.id, Role.VIEWER)
        with pytest.raises(svc.UserAdminError, match="last active admin"):
            svc.set_active(db, _as(ghost), acting.id, False)
        assert acting.role is Role.ADMIN and acting.is_active

    def test_deactivating_ends_sessions_and_blocks_sign_in(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        target = _user(db, Role.ANALYST)
        session = start_session(db, target)
        assert resolve_session(db, str(session.id)) is not None

        svc.set_active(db, _as(admin), target.id, False)
        db.flush()
        db.refresh(session)
        assert session.revoked_at is not None
        assert resolve_session(db, str(session.id)) is None

        svc.set_active(db, _as(admin), target.id, True)
        assert target.is_active
        assert _audit(db, target)[-2:] == ["user.deactivated", "user.activated"]

    def test_reset_password_signs_the_user_out(self, db) -> None:
        from advisory_hub.core.security.passwords import verify_password

        admin = _user(db, Role.ADMIN)
        target = _user(db, Role.VIEWER)
        session = start_session(db, target)
        with pytest.raises(svc.UserAdminError):
            svc.reset_password(db, _as(admin), target.id, "short")
        svc.reset_password(db, _as(admin), target.id, PASSWORD)
        db.flush()
        db.refresh(session)
        assert verify_password(PASSWORD, target.password_hash)
        assert session.revoked_at is not None

    def test_own_password_reset_keeps_own_session(self, db) -> None:
        admin = _user(db, Role.ADMIN)
        session = start_session(db, admin)
        svc.reset_password(db, _as(admin), admin.id, PASSWORD)
        db.flush()
        db.refresh(session)
        assert session.revoked_at is None

    def test_unknown_user(self, db) -> None:
        with pytest.raises(svc.UserNotFoundError):
            svc.change_role(db, _as(_user(db, Role.ADMIN)), uuid.uuid4(), Role.VIEWER)


# ─── Web ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def web(db, tmp_path, monkeypatch):
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    from fastapi.testclient import TestClient

    from advisory_hub.api.deps import SESSION_COOKIE, db_session, sign
    from advisory_hub.config import get_settings
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override

    def client_for(user: User) -> TestClient:
        session = start_session(db, user, ip_address="127.0.0.1", user_agent="test")
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    def test_analyst_cannot_manage_users(self, db, web) -> None:
        client = web(_user(db, Role.ANALYST))
        target = _user(db)
        assert client.get("/admin").status_code == 403
        r = client.post(f"/admin/users/{target.id}/role", data={"role": "ADMIN"})
        assert r.status_code == 403
        assert target.role is Role.VIEWER

    def test_admin_page_lists_users_with_role_controls(self, db, web) -> None:
        admin = _user(db, Role.ADMIN)
        other = _user(db, Role.ANALYST)
        page = web(admin).get("/admin").text
        assert 'id="admin-users"' in page
        assert other.email in page and f'hx-post="/admin/users/{other.id}/role"' in page
        # No role picker or deactivate button for yourself.
        assert f'hx-post="/admin/users/{admin.id}/role"' not in page
        assert f'hx-post="/admin/users/{admin.id}/active"' not in page

    def test_change_role_then_rule_error_in_place(self, db, web) -> None:
        admin = _user(db, Role.ADMIN)
        target = _user(db, Role.VIEWER)
        client = web(admin)

        r = client.post(f"/admin/users/{target.id}/role", data={"role": "ANALYST"})
        assert r.status_code == 200 and "is now Analyst" in r.text
        db.refresh(target)
        assert target.role is Role.ANALYST

        r = client.post(f"/admin/users/{admin.id}/role", data={"role": "VIEWER"})
        assert r.status_code == 200 and 'class="error"' in r.text
        assert "your own role" in r.text
        db.refresh(admin)
        assert admin.role is Role.ADMIN

    def test_add_deactivate_reactivate_and_reset(self, db, web) -> None:
        client = web(_user(db, Role.ADMIN))
        r = client.post(
            "/admin/users",
            data={"email": "added@example.invalid", "display_name": "Added",
                  "role": "ANALYST", "password": PASSWORD},
        )  # fmt: skip
        assert "Added added@example.invalid as Analyst." in r.text
        user = db.scalar(select(User).where(User.email == "added@example.invalid"))
        assert user is not None and user.role is Role.ANALYST

        r = client.post(f"/admin/users/{user.id}/active", data={"active": "false"})
        assert "Deactivated Added" in r.text
        db.refresh(user)
        assert not user.is_active
        r = client.post(f"/admin/users/{user.id}/active", data={"active": "true"})
        db.refresh(user)
        assert user.is_active

        r = client.post(f"/admin/users/{user.id}/password", data={"password": "short"})
        assert "at least 12" in r.text
        r = client.post(f"/admin/users/{user.id}/password", data={"password": PASSWORD})
        assert "Password reset for Added." in r.text

    def test_deactivated_user_is_signed_out(self, db, web) -> None:
        admin_client = web(_user(db, Role.ADMIN))
        target = _user(db, Role.ANALYST)
        target_client = web(target)
        assert target_client.get("/").status_code == 200

        admin_client.post(f"/admin/users/{target.id}/active", data={"active": "false"})
        r = target_client.get("/")
        assert r.status_code == 303 and r.headers["location"] == "/login"
