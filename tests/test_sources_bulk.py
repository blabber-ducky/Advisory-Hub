"""Custom sources managed on /admin, and bulk edit of source/status."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from advisory_hub.core.models.enums import (
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    Role,
    SourceMethod,
)


def _user(db, role: Role):
    from advisory_hub.core.models.user import User

    user = User(
        email=f"{uuid.uuid4().hex[:8]}@x.example", display_name=role.value.title(), role=role
    )
    db.add(user)
    db.flush()
    return user


def _principal(db, role: Role = Role.ADMIN):
    from advisory_hub.core.services.auth import Principal

    return Principal(kind=ActorKind.USER, user=_user(db, role))


def _advisory(db, ref: str, status: AdvisoryStatus = AdvisoryStatus.NEW):
    from advisory_hub.core.models.advisory import Advisory
    from advisory_hub.core.models.base import utcnow
    from advisory_hub.core.services.sources import get_or_create_unknown

    a = Advisory(
        source_id=get_or_create_unknown(db).id,
        source_method=SourceMethod.NONE,
        external_ref=ref,
        type=AdvisoryType.CVE_ADVISORY,
        title=f"Advisory {ref}",
        status=status,
        received_at=utcnow(),
        ingested_at=utcnow(),
        dedupe_hash=uuid.uuid4().hex,
        parser_version="3",
    )
    db.add(a)
    db.flush()
    return a


@pytest.mark.integration
class TestSourceAdmin:
    def test_create_edit_deactivate(self, db) -> None:
        from advisory_hub.core.models.user import AuditLog
        from advisory_hub.core.services import sources

        admin = _principal(db)
        src = sources.create_source(
            db, admin, name="  National   CERT ", short_code="ncert",
            sender_patterns="alerts@ncert.example\n@ncert.example, NCERT.example",
        )  # fmt: skip
        assert (src.name, src.short_code) == ("National CERT", "NCERT")
        assert src.sender_patterns == ["alerts@ncert.example", "ncert.example"]
        assert src in sources.assignable_sources(db)

        sources.update_source(
            db,
            admin,
            src.id,
            name="National CERT",
            short_code="NCERT",
            sender_patterns="ncert.example",
        )
        assert src.sender_patterns == ["ncert.example"]
        sources.set_source_active(db, admin, src.id, False)
        assert src not in sources.assignable_sources(db)
        actions = list(db.scalars(select(AuditLog.action).where(AuditLog.entity_id == src.id)))
        assert actions == ["source.created", "source.updated", "source.deactivated"]

    def test_new_source_is_used_for_detection(self, db) -> None:
        from advisory_hub.core.services import sources

        sources.create_source(
            db,
            _principal(db),
            name="National CERT",
            short_code="NCERT",
            sender_patterns="ncert.example",
        )
        by_sender = sources.resolve_source(db, "alerts@ncert.example", None)
        by_ref = sources.resolve_source(db, "someone@else.example", "NCERT-123456")
        assert by_sender.source.short_code == by_ref.source.short_code == "NCERT"
        assert by_ref.method is SourceMethod.REFERENCE

    @pytest.mark.parametrize(
        ("name", "code", "patterns", "message"),
        [
            ("X", "1AB", "", "Short code"),
            ("X", "UNKNOWN", "", "reserved"),
            ("", "ABC", "", "Enter a name"),
            ("X", "ABC", "not a domain", "isn't an email address or a domain"),
        ],
    )
    def test_validation(self, db, name, code, patterns, message) -> None:
        from advisory_hub.core.services import sources

        with pytest.raises(sources.SourceAdminError, match=message):
            sources.create_source(
                db, _principal(db), name=name, short_code=code, sender_patterns=patterns
            )

    def test_duplicates_and_unknown_are_protected(self, db) -> None:
        from advisory_hub.core.services import sources

        admin = _principal(db)
        sources.create_source(db, admin, name="Alpha", short_code="ALPHA", sender_patterns="")
        with pytest.raises(sources.SourceAdminError, match="short code"):
            sources.create_source(db, admin, name="Beta", short_code="alpha", sender_patterns="")
        with pytest.raises(sources.SourceAdminError, match="name"):
            sources.create_source(db, admin, name="alpha", short_code="BETA", sender_patterns="")
        unknown = sources.get_or_create_unknown(db)
        with pytest.raises(sources.SourceAdminError, match="built in"):
            sources.set_source_active(db, admin, unknown.id, False)

    def test_admin_only(self, db) -> None:
        from advisory_hub.core.services import sources
        from advisory_hub.core.services.auth import PermissionDeniedError

        with pytest.raises(PermissionDeniedError):
            sources.create_source(
                db, _principal(db, Role.ANALYST), name="X", short_code="XY", sender_patterns=""
            )


@pytest.mark.integration
class TestBulk:
    def test_status_applies_where_allowed_and_explains_the_rest(self, db) -> None:
        from advisory_hub.core.models.advisory import Comment
        from advisory_hub.core.services import advisories as svc
        from advisory_hub.core.services.audit import Actor

        user = _user(db, Role.ANALYST)
        actor = Actor(ActorKind.USER, user.id, "A")
        a = _advisory(db, "DOH-1", AdvisoryStatus.ACKNOWLEDGED)
        b = _advisory(db, "DOH-2", AdvisoryStatus.ACKNOWLEDGED)
        c = _advisory(db, "DOH-3", AdvisoryStatus.IN_PROGRESS)
        d = _advisory(db, "DOH-4", AdvisoryStatus.TRIAGED)
        allowed_from_ack = svc.next_statuses(AdvisoryStatus.ACKNOWLEDGED)
        target = AdvisoryStatus.TRIAGED
        assert target in allowed_from_ack

        result = svc.bulk_change_status(
            db,
            [a.id, b.id, c.id, d.id, a.id],
            to_status=target,
            comment_body="Bulk triage",
            actor=actor,
        )
        assert result.updated == ["DOH-1", "DOH-2"]
        assert dict(result.skipped) == {
            "DOH-3": "can't go from In Progress to Triaged",
            "DOH-4": "already Triaged",
        }
        assert (a.status, b.status, c.status) == (target, target, AdvisoryStatus.IN_PROGRESS)
        comments = db.scalars(select(Comment).where(Comment.advisory_id.in_([a.id, b.id])))
        assert {cm.body for cm in comments} == {"Bulk triage"}

    def test_status_needs_a_comment_and_ack_channel(self, db) -> None:
        from advisory_hub.core.services import advisories as svc
        from advisory_hub.core.services.audit import Actor

        a = _advisory(db, "DOH-1")
        actor = Actor.system("t")
        with pytest.raises(svc.MissingCommentError):
            svc.bulk_change_status(
                db, [a.id], to_status=AdvisoryStatus.ACKNOWLEDGED, comment_body=" ", actor=actor
            )
        with pytest.raises(svc.MissingAckChannelError):
            svc.bulk_change_status(
                db, [a.id], to_status=AdvisoryStatus.ACKNOWLEDGED, comment_body="x", actor=actor
            )
        assert a.status is AdvisoryStatus.NEW

    def test_source(self, db) -> None:
        from advisory_hub.core.services import advisories as svc
        from advisory_hub.core.services import sources
        from advisory_hub.core.services.audit import Actor

        src = sources.create_source(
            db, _principal(db), name="Alpha", short_code="ALPHA", sender_patterns=""
        )
        a, b = _advisory(db, "X-1"), _advisory(db, "X-2")
        result = svc.bulk_change_source(db, [a.id, b.id], source_id=src.id, actor=Actor.system("t"))
        assert result.updated == ["X-1", "X-2"]
        assert {a.source_method, b.source_method} == {SourceMethod.MANUAL}
        again = svc.bulk_change_source(db, [a.id], source_id=src.id, actor=Actor.system("t"))
        assert again.skipped == [("X-1", "already ALPHA")]


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
    from advisory_hub.core.services.auth import start_session
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override

    def client_for(role: Role) -> TestClient:
        session = start_session(db, _user(db, role))
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    def test_admin_page_groups_and_sources(self, db, web) -> None:
        admin = web(Role.ADMIN)
        page = admin.get("/admin").text
        for group in ("group-people", "group-intake", "group-ticketing", "group-enrichment"):
            assert f'id="{group}"' in page
        r = admin.post(
            "/admin/sources",
            data={
                "short_code": "ncert",
                "name": "National CERT",
                "sender_patterns": "ncert.example",
            },
        )
        assert "Added NCERT — National CERT." in r.text and "<code>NCERT</code>" in r.text
        r = admin.post(
            "/admin/sources", data={"short_code": "NCERT", "name": "Other", "sender_patterns": ""}
        )
        assert "already has that short code" in r.text
        assert (
            web(Role.ANALYST)
            .post("/admin/sources", data={"short_code": "AB", "name": "x"})
            .status_code
            == 403
        )

    def test_new_source_is_offered_to_analysts(self, db, web) -> None:
        from advisory_hub.core.services import sources

        sources.create_source(
            db, _principal(db), name="National CERT", short_code="NCERT", sender_patterns=""
        )
        a = _advisory(db, "NCERT-1")
        detail = web(Role.ANALYST).get(f"/advisories/{a.id}").text
        assert "NCERT — National CERT" in detail  # in the source picker
        assert "NCERT — National CERT" in web(Role.ANALYST).get("/").text  # in the bulk bar

    def test_bulk_bar_for_analysts_only(self, db, web) -> None:
        _advisory(db, "DOH-1")
        assert 'id="bulk-form"' in web(Role.ANALYST).get("/").text
        viewer = web(Role.VIEWER).get("/").text
        assert 'id="bulk-form"' not in viewer and 'name="ids"' not in viewer
        assert (
            web(Role.VIEWER).post("/advisories/bulk", data={"action": "status"}).status_code == 403
        )

    def test_bulk_status_over_http(self, db, web) -> None:
        a = _advisory(db, "DOH-1", AdvisoryStatus.ACKNOWLEDGED)
        c = _advisory(db, "DOH-3", AdvisoryStatus.IN_PROGRESS)
        client = web(Role.ANALYST)
        r = client.post(
            "/advisories/bulk",
            data={
                "ids": [str(a.id), str(c.id)],
                "action": "status",
                "to_status": "TRIAGED",
                "comment": "Triaged in bulk",
            },
        )
        assert r.headers.get("HX-Trigger") == "tracker-refresh"
        assert (
            "Status changed for 1 advisory." in r.text
            and "can&#39;t go from In Progress to Triaged" in r.text
        )
        db.refresh(a)
        assert a.status is AdvisoryStatus.TRIAGED

        r = client.post(
            "/advisories/bulk",
            data={"ids": [str(a.id)], "action": "status", "to_status": "IN_PROGRESS"},
        )
        assert "A comment is required" in r.text and "HX-Trigger" not in r.headers
        r = client.post("/advisories/bulk", data={"action": "status"})
        assert "Select at least one advisory." in r.text
