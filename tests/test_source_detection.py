"""Source detection (sender → reference number → unknown), the manual
override, and re-parse keeping both honest."""

from __future__ import annotations

import uuid
from email.message import EmailMessage
from pathlib import Path

import pytest
from sqlalchemy import select

from advisory_hub.core.models.enums import ActorKind, FlagKind, Role, SourceMethod
from advisory_hub.ingest.message import subject_parts

DOH_SENDER = "DoH Cyber Advisory <cyber.advisory@doh.gov.ae>"
COLLEAGUE = "A Colleague <colleague@hospital.example>"


class TestSubjectParts:
    @pytest.mark.parametrize(
        ("subject", "ref", "title"),
        [
            # The corpus shape is unchanged.
            (
                "[EXTERNAL] Security Advisory :: DOH- 2026550 - Flaw in Doris",
                "DOH-2026550",
                "Flaw in Doris",
            ),
            ("Security Advisory _ DOH-2026607 Title", "DOH-2026607", "Title"),
            # Forwarded / replied, in any order with [EXTERNAL].
            (
                "FW: [EXTERNAL] Security Advisory :: DOH-2026551 - SharePoint RCE",
                "DOH-2026551",
                "SharePoint RCE",
            ),
            ("[EXTERNAL] RE: Fwd: Security Advisory :: DOH-2026552 - X", "DOH-2026552", "X"),
            # Reference anywhere; the title is the cleaned subject.
            (
                "FW: Urgent - DOH-2026700 patch today",
                "DOH-2026700",
                "Urgent - DOH-2026700 patch today",
            ),
            # Never a CVE / CWE.
            ("Patch CVE-2026-12345 now", None, "Patch CVE-2026-12345 now"),
            ("CWE-79 in portal", None, "CWE-79 in portal"),
            ("DOH 2026 meeting", None, "DOH 2026 meeting"),
            ("", None, "(untitled)"),
        ],
    )
    def test_reference_and_title(self, subject: str, ref: str | None, title: str) -> None:
        assert subject_parts(subject) == (ref, title)


def _eml(tmp_path: Path, *, sender: str, subject: str) -> Path:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "soc@example.invalid"
    msg["Subject"] = subject
    msg["Date"] = "Thu, 23 Jul 2026 12:00:00 +0000"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@example.invalid>"
    msg.set_content(
        "Dear IS Stakeholder,\n\nType:\n\nVulnerability\n\nRisk level:\n\nHigh\n\n"
        "Description:\n\nCVE-2026-58319 affects Apache Doris.\n"
    )
    path = tmp_path / f"{uuid.uuid4().hex}.eml"
    path.write_bytes(msg.as_bytes())
    return path


@pytest.fixture
def ingest(db, tmp_path: Path):
    from advisory_hub.core.services.ingestion import ingest_parsed_advisory
    from advisory_hub.core.services.sources import seed_default_sources
    from advisory_hub.core.storage.blobs import FilesystemBlobStore
    from advisory_hub.ingest.message import parse_message
    from advisory_hub.ingest.parser import parse_advisory

    seed_default_sources(db)
    blobs = FilesystemBlobStore(tmp_path / "blobs")

    def _ingest(*, sender: str, subject: str):
        message = parse_message(_eml(tmp_path, sender=sender, subject=subject))
        result = ingest_parsed_advisory(db, parse_advisory(message, extract_pdfs=False), blobs)
        db.flush()
        return result.advisory

    _ingest.blobs = blobs  # type: ignore[attr-defined]
    return _ingest


def _flags(advisory, kind: FlagKind):
    return [f for f in advisory.flags if f.kind is kind]


def _actor(db, role: Role = Role.ANALYST):
    from advisory_hub.core.models.user import User
    from advisory_hub.core.services.audit import Actor

    user = User(email=f"{uuid.uuid4().hex[:8]}@example.invalid", display_name="Ana", role=role)
    db.add(user)
    db.flush()
    return user, Actor(kind=ActorKind.USER, user_id=user.id, label="Ana")


@pytest.mark.integration
class TestDetection:
    def test_known_sender(self, db, ingest) -> None:
        a = ingest(sender=DOH_SENDER, subject="Security Advisory :: DOH-2026001 - A")
        assert (a.source.short_code, a.source_method) == ("DOH", SourceMethod.SENDER)
        assert _flags(a, FlagKind.UNKNOWN_SENDER) == []

    def test_forwarded_doh_advisory_is_filed_under_doh_and_still_flagged(self, db, ingest) -> None:
        a = ingest(sender=COLLEAGUE, subject="FW: [EXTERNAL] Security Advisory :: DOH-2026002 - B")
        assert a.external_ref == "DOH-2026002" and a.title == "B"
        assert (a.source.short_code, a.source_method) == ("DOH", SourceMethod.REFERENCE)
        [flag] = _flags(a, FlagKind.UNKNOWN_SENDER)
        assert flag.detail == {"sender": COLLEAGUE, "source_from_reference": "DOH"}

    def test_nothing_to_go_on(self, db, ingest) -> None:
        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        assert (a.source.short_code, a.source_method) == ("UNKNOWN", SourceMethod.NONE)
        [flag] = _flags(a, FlagKind.UNKNOWN_SENDER)
        assert "source_from_reference" not in flag.detail

    def test_reference_to_an_inactive_source_is_not_used(self, db, ingest) -> None:
        from advisory_hub.core.models.advisory import Source

        doh = db.scalar(select(Source).where(Source.short_code == "DOH"))
        doh.is_active = False
        a = ingest(sender=COLLEAGUE, subject="Security Advisory :: DOH-2026003 - C")
        assert a.source_method is SourceMethod.NONE


@pytest.mark.integration
class TestManualSource:
    def test_sets_manual_resolves_the_flag_and_audits(self, db, ingest) -> None:
        from advisory_hub.core.models.advisory import Source
        from advisory_hub.core.models.user import AuditLog
        from advisory_hub.core.services import advisories as svc

        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        user, actor = _actor(db)
        doh = db.scalar(select(Source).where(Source.short_code == "DOH"))

        svc.change_source(db, a.id, source_id=doh.id, actor=actor)
        db.flush()
        assert (a.source_id, a.source_method) == (doh.id, SourceMethod.MANUAL)
        [flag] = _flags(a, FlagKind.UNKNOWN_SENDER)
        assert flag.resolved_at is not None and flag.resolved_by_id == user.id
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "advisory.source_changed"))
        assert entry.detail["from"] == "UNKNOWN" and entry.detail["to"] == "DOH"
        assert entry.detail["from_method"] == "NONE"

    def test_unknown_and_missing_sources_are_refused(self, db, ingest) -> None:
        from advisory_hub.core.services import advisories as svc
        from advisory_hub.core.services.sources import get_or_create_unknown

        a = ingest(sender=COLLEAGUE, subject="x")
        _, actor = _actor(db)
        for source_id in (get_or_create_unknown(db).id, uuid.uuid4()):
            with pytest.raises(svc.InvalidSourceError):
                svc.change_source(db, a.id, source_id=source_id, actor=actor)
        with pytest.raises(svc.AdvisoryNotFoundError):
            svc.change_source(db, uuid.uuid4(), source_id=a.source_id, actor=actor)


@pytest.mark.integration
class TestReparse:
    def _reparse(self, db, ingest) -> None:
        from advisory_hub.core.services.reparse import reparse_advisories

        report = reparse_advisories(db, dry_run=False, blobs=ingest.blobs)
        assert report.failed == 0, report.lines
        db.flush()
        db.expire_all()

    def test_fixes_an_advisory_parsed_before_reference_detection(self, db, ingest) -> None:
        a = ingest(sender=COLLEAGUE, subject="FW: Security Advisory :: DOH-2026010 - D")
        # As parser v2 left it: no reference from a forwarded subject → UNKNOWN.
        from advisory_hub.core.services.sources import get_or_create_unknown

        a.external_ref, a.parser_version = None, "2"
        a.source_id, a.source_method = get_or_create_unknown(db).id, SourceMethod.NONE
        db.flush()

        self._reparse(db, ingest)
        assert a.external_ref == "DOH-2026010"
        assert (a.source.short_code, a.source_method) == ("DOH", SourceMethod.REFERENCE)
        [flag] = _flags(a, FlagKind.UNKNOWN_SENDER)
        assert flag.detail["source_from_reference"] == "DOH"

    def test_keeps_a_manual_source_and_its_resolved_flag(self, db, ingest) -> None:
        from advisory_hub.core.models.advisory import Source
        from advisory_hub.core.services import advisories as svc

        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        _, actor = _actor(db)
        doh = db.scalar(select(Source).where(Source.short_code == "DOH"))
        svc.change_source(db, a.id, source_id=doh.id, actor=actor)
        a.parser_version = "2"  # force a diff so the re-parse writes
        db.flush()

        self._reparse(db, ingest)
        assert (a.source_id, a.source_method) == (doh.id, SourceMethod.MANUAL)
        [flag] = _flags(a, FlagKind.UNKNOWN_SENDER)
        assert flag.resolved_at is not None

    def test_keeps_ingest_time_flags(self, db, ingest) -> None:
        """Regression: re-parse used to delete UNKNOWN_SENDER and POSSIBLE_REISSUE."""
        from advisory_hub.core.models.advisory import AdvisoryFlag

        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        db.add(AdvisoryFlag(advisory_id=a.id, kind=FlagKind.POSSIBLE_REISSUE, detail={}))
        a.parser_version = "2"
        db.flush()

        self._reparse(db, ingest)
        kinds = sorted(f.kind.value for f in a.flags)
        assert kinds.count("UNKNOWN_SENDER") == 1 and kinds.count("POSSIBLE_REISSUE") == 1


# ─── Web ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def web(db, tmp_path, monkeypatch):
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    from contextlib import contextmanager

    from fastapi.testclient import TestClient

    from advisory_hub.api.deps import SESSION_COOKIE, db_session, sign
    from advisory_hub.config import get_settings
    from advisory_hub.core.services.auth import start_session
    from advisory_hub.ingest import pipeline
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override

    @contextmanager
    def _scope():
        yield db
        db.flush()

    monkeypatch.setattr(pipeline, "session_scope", _scope)

    def client_for(role: Role) -> TestClient:
        user, _ = _actor(db, role)
        session = start_session(db, user, ip_address="127.0.0.1", user_agent="test")
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    def test_detail_view_picker_for_analysts_only(self, db, web, ingest) -> None:
        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        analyst = web(Role.ANALYST).get(f"/advisories/{a.id}").text
        viewer = web(Role.VIEWER).get(f"/advisories/{a.id}").text
        assert "Not detected" in analyst and "Not detected" in viewer
        assert f'hx-post="/advisories/{a.id}/source"' in analyst
        assert f'hx-post="/advisories/{a.id}/source"' not in viewer

    def test_set_source_from_the_detail_view(self, db, web, ingest) -> None:
        from advisory_hub.core.models.advisory import Source

        a = ingest(sender=COLLEAGUE, subject="Please look at this")
        doh = db.scalar(select(Source).where(Source.short_code == "DOH"))
        assert web(Role.VIEWER).post(
            f"/advisories/{a.id}/source", data={"source_id": str(doh.id)}
        ).status_code == 403  # fmt: skip

        r = web(Role.ANALYST).post(f"/advisories/{a.id}/source", data={"source_id": str(doh.id)})
        assert r.status_code == 200
        assert "set manually" in r.text and doh.name in r.text
        db.refresh(a)
        assert a.source_method is SourceMethod.MANUAL

    def test_upload_offers_a_picker_only_when_not_detected(self, db, web, tmp_path) -> None:
        from advisory_hub.core.services.sources import seed_default_sources

        seed_default_sources(db)
        db.flush()
        undetected = _eml(tmp_path, sender=COLLEAGUE, subject="Please look at this").read_bytes()
        by_ref = _eml(tmp_path, sender=COLLEAGUE, subject="FW: DOH-2026020 notice").read_bytes()
        r = web(Role.ANALYST).post(
            "/inbox/upload",
            files=[
                ("files", ("undetected.eml", undetected, "message/rfc822")),
                ("files", ("byref.eml", by_ref, "message/rfc822")),
            ],
        )
        assert r.status_code == 200
        assert r.text.count("Source not detected") == 1
        assert "DOH (from reference)" in r.text
        assert r.text.count('name="source_id"') == 1
