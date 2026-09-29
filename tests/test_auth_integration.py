"""Database-backed auth: users, sessions, tokens, and the append-only audit log.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError, IntegrityError

from advisory_hub.core.models.enums import ActorKind, Role
from advisory_hub.core.models.user import ApiToken, AuditLog, User
from advisory_hub.core.security.tokens import Scope, mint_token
from advisory_hub.core.services.audit import Actor, record
from advisory_hub.core.services.auth import (
    AuthError,
    LocalAuthProvider,
    PermissionDeniedError,
    create_user,
    end_session,
    resolve_api_token,
    resolve_session,
    start_session,
)

pytestmark = pytest.mark.integration

PASSWORD = "a-sufficiently-long-test-password"


@pytest.fixture
def user(db) -> User:
    u = create_user(
        db,
        email="Analyst@Example.Com",
        display_name="Test Analyst",
        password=PASSWORD,
        role=Role.ANALYST,
    )
    db.flush()
    return u


class TestUserCreation:
    def test_email_is_normalised(self, user: User) -> None:
        assert user.email == "analyst@example.com"

    def test_duplicate_email_rejected(self, db, user: User) -> None:
        with pytest.raises(ValueError, match="already exists"):
            create_user(db, email="ANALYST@example.com", display_name="Dup", password=PASSWORD)

    def test_creation_is_audited(self, db, user: User) -> None:
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "user.created"))
        assert entry is not None
        assert entry.entity_id == user.id


class TestAuthentication:
    def test_correct_password_authenticates(self, db, user: User) -> None:
        assert (
            LocalAuthProvider()
            .authenticate(db, identifier="analyst@example.com", secret=PASSWORD)
            .id
            == user.id
        )

    def test_login_is_case_insensitive(self, db, user: User) -> None:
        assert (
            LocalAuthProvider()
            .authenticate(db, identifier="  ANALYST@EXAMPLE.COM  ", secret=PASSWORD)
            .id
            == user.id
        )

    def test_wrong_password_rejected(self, db, user: User) -> None:
        with pytest.raises(AuthError):
            LocalAuthProvider().authenticate(db, identifier=user.email, secret="wrong")

    def test_unknown_user_raises_the_same_error(self, db) -> None:
        """Callers must not be able to distinguish these two cases."""
        with pytest.raises(AuthError):
            LocalAuthProvider().authenticate(db, identifier="nobody@example.com", secret="x")

    def test_deactivated_user_cannot_log_in(self, db, user: User) -> None:
        user.is_active = False
        db.flush()
        with pytest.raises(AuthError):
            LocalAuthProvider().authenticate(db, identifier=user.email, secret=PASSWORD)


class TestSessions:
    def test_session_resolves_to_its_user(self, db, user: User) -> None:
        s = start_session(db, user, ip_address="192.0.2.10")
        db.flush()
        principal = resolve_session(db, str(s.id))
        assert principal is not None
        assert principal.user is not None and principal.user.id == user.id
        assert principal.kind is ActorKind.USER

    def test_revoked_session_stops_resolving(self, db, user: User) -> None:
        s = start_session(db, user)
        db.flush()
        end_session(db, str(s.id))
        db.flush()
        assert resolve_session(db, str(s.id)) is None

    @pytest.mark.parametrize("junk", ["", "not-a-uuid", "../../etc/passwd"])
    def test_malformed_session_ids_are_rejected(self, db, junk: str) -> None:
        assert resolve_session(db, junk) is None

    def test_deactivating_a_user_invalidates_their_session(self, db, user: User) -> None:
        s = start_session(db, user)
        db.flush()
        user.is_active = False
        db.flush()
        assert resolve_session(db, str(s.id)) is None


class TestApiTokenResolution:
    def test_valid_token_resolves_with_scopes(self, db, user: User) -> None:
        minted = mint_token()
        db.add(
            ApiToken(
                name="dashboard",
                token_prefix=minted.prefix,
                token_hash=minted.token_hash,
                scopes=[Scope.ADVISORIES_READ, Scope.STATS_READ],
                created_by_id=user.id,
            )
        )
        db.flush()

        principal = resolve_api_token(db, minted.plaintext)
        assert principal is not None
        assert principal.kind is ActorKind.API_TOKEN
        assert Scope.ADVISORIES_READ in principal.scopes

        principal.require_scope(Scope.ADVISORIES_READ)
        with pytest.raises(PermissionDeniedError):
            principal.require_scope(Scope.ADVISORIES_WRITE)

    def test_revoked_token_is_rejected(self, db) -> None:
        from advisory_hub.core.models.base import utcnow

        minted = mint_token()
        db.add(
            ApiToken(
                name="revoked",
                token_prefix=minted.prefix,
                token_hash=minted.token_hash,
                scopes=[Scope.ADVISORIES_READ],
                revoked_at=utcnow(),
            )
        )
        db.flush()
        assert resolve_api_token(db, minted.plaintext) is None

    def test_unknown_token_is_rejected(self, db) -> None:
        assert resolve_api_token(db, mint_token().plaintext) is None


class TestSessionUserScopeChecks:
    """Regression: a logged-in USER used to pass every `require_scope()` check
    unconditionally, regardless of role — a VIEWER could pass an
    `advisories:write` check just by being authenticated. See D-021 follow-up
    and docs/architecture.md §6's role table."""

    def test_viewer_fails_a_write_scope_check(self, db) -> None:
        from advisory_hub.core.models.enums import ActorKind
        from advisory_hub.core.services.auth import Principal, create_user

        viewer = create_user(
            db, email="viewer@example.invalid", display_name="V", password="x", role=Role.VIEWER
        )
        principal = Principal(kind=ActorKind.USER, user=viewer)
        principal.require_scope(Scope.ADVISORIES_READ)
        with pytest.raises(PermissionDeniedError):
            principal.require_scope(Scope.ADVISORIES_WRITE)

    def test_analyst_passes_a_write_scope_check(self, db) -> None:
        from advisory_hub.core.models.enums import ActorKind
        from advisory_hub.core.services.auth import Principal, create_user

        analyst = create_user(
            db, email="analyst2@example.invalid", display_name="A", password="x", role=Role.ANALYST
        )
        principal = Principal(kind=ActorKind.USER, user=analyst)
        principal.require_scope(Scope.ADVISORIES_WRITE)


class TestAuditLogIsAppendOnly:
    """The schema itself enforces this — see migration 4f03b42cc69d."""

    def test_insert_is_permitted(self, db) -> None:
        record(db, actor=Actor.system("test"), action="probe.insert")
        db.flush()
        assert db.scalar(select(AuditLog).where(AuditLog.action == "probe.insert"))

    def test_update_is_refused_by_the_database(self, db) -> None:
        record(db, actor=Actor.system("test"), action="probe.update")
        db.flush()
        with pytest.raises(DatabaseError, match="append-only"):
            db.execute(text("UPDATE audit_log SET action = 'tampered'"))

    def test_delete_is_refused_by_the_database(self, db) -> None:
        record(db, actor=Actor.system("test"), action="probe.delete")
        db.flush()
        with pytest.raises(DatabaseError, match="append-only"):
            db.execute(text("DELETE FROM audit_log"))


class TestCommentConstraint:
    """Layer 1 of the mandatory-comment rule — see D-006."""

    def test_blank_comment_body_is_refused_by_the_database(self, db, user: User) -> None:
        from advisory_hub.core.models.advisory import Advisory, Comment, Source
        from advisory_hub.core.models.base import utcnow
        from advisory_hub.core.models.enums import AdvisoryType

        source = Source(name="Test Regulator", short_code="TEST", sender_patterns=["t@example.com"])
        db.add(source)
        db.flush()
        advisory = Advisory(
            source_id=source.id,
            type=AdvisoryType.CVE_ADVISORY,
            title="Test",
            received_at=utcnow(),
            dedupe_hash="0" * 64,
            parser_version="0",
        )
        db.add(advisory)
        db.flush()

        db.add(Comment(advisory_id=advisory.id, author_id=user.id, body="   "))
        with pytest.raises(IntegrityError):
            db.flush()
