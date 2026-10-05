"""Uploading .eml/.msg files from the tracker page, and the page header
regression on the IOCs / Affected Software pages."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path

import pytest

from advisory_hub.core.services.audit import Actor
from advisory_hub.ingest import pipeline
from advisory_hub.ingest.pipeline import IngestOutcome, UploadRejectedError, ingest_uploads
from advisory_hub.ingest.watcher import Inbox, safe_message_name


@pytest.fixture
def inbox(tmp_path: Path) -> Inbox:
    return Inbox(
        inbox=tmp_path / "inbox",
        processing=tmp_path / "processing",
        archive=tmp_path / "archive",
        failed=tmp_path / "failed",
        worker_id="test",
    )


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


class TestSafeMessageName:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("advisory.eml", "advisory.eml"),
            ("Advisory.MSG", "Advisory.msg"),
            ("../../etc/passwd.eml", "passwd.eml"),
            ("C:\\Users\\me\\Desktop\\a b.msg", "a b.msg"),
            ("DOH: 2026/55 <x>.eml", "55 _x_.eml"),
        ],
    )
    def test_keeps_a_safe_basename(self, given: str, expected: str) -> None:
        assert safe_message_name(given) == expected

    @pytest.mark.parametrize("given", ["report.pdf", "a.eml.exe", "noextension", "", "eml"])
    def test_rejects_non_messages(self, given: str) -> None:
        assert safe_message_name(given) is None


class TestDeposit:
    def test_lands_complete_with_no_tmp_left(self, inbox: Inbox) -> None:
        path = inbox.deposit("a.eml", b"data")
        assert path.read_bytes() == b"data"
        assert [p.name for p in inbox.inbox.iterdir()] == ["a.eml"]

    def test_never_overwrites(self, inbox: Inbox) -> None:
        first = inbox.deposit("a.eml", b"one")
        second = inbox.deposit("a.eml", b"two")
        assert first != second
        assert (first.read_bytes(), second.read_bytes()) == (b"one", b"two")

    def test_stays_inside_the_inbox(self, inbox: Inbox) -> None:
        path = inbox.deposit("../../escape.eml", b"x")
        assert path.parent == inbox.inbox


class TestIngestUploads:
    @pytest.mark.parametrize(
        ("uploads", "message"),
        [
            ([], "at least one"),
            ([("a.eml", b"x"), ("b.pdf", b"x")], "not an email file"),
            ([("a.eml", b"")], "is empty"),
        ],
    )
    def test_rejects_before_writing_anything(
        self, inbox: Inbox, uploads: list[tuple[str, bytes]], message: str
    ) -> None:
        with pytest.raises(UploadRejectedError, match=message):
            ingest_uploads(uploads, inbox=inbox)
        assert _files(inbox.inbox.parent) == []

    def test_size_and_count_limits(self, inbox: Inbox, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("UPLOAD_MAX_BYTES", str(2 * 1024 * 1024))
        monkeypatch.setenv("UPLOAD_MAX_FILES", "2")
        get_settings.cache_clear()
        try:
            with pytest.raises(UploadRejectedError, match="larger than 2 MB"):
                ingest_uploads([("a.eml", b"x" * (2 * 1024 * 1024 + 1))], inbox=inbox)
            with pytest.raises(UploadRejectedError, match="Too many"):
                ingest_uploads([("a.eml", b"1")] * 3, inbox=inbox)
        finally:
            get_settings.cache_clear()
        assert _files(inbox.inbox.parent) == []

    def test_same_dispositions_as_an_inbox_drop(self, inbox: Inbox, monkeypatch) -> None:
        """Ingested → archive/, failed → failed/ with a sidecar, actor passed."""
        seen_actors: list[Actor | None] = []

        def fake_ingest(path: Path, *, blobs: object, actor: Actor | None) -> IngestOutcome:
            seen_actors.append(actor)
            if path.name.startswith("bad"):
                return IngestOutcome(path, "FAILED", error="MESSAGE_PARSE: nope")
            return IngestOutcome(path, "INGESTED", advisory_id="x", external_ref="DOH-1")

        monkeypatch.setattr(pipeline, "ingest_file", fake_ingest)
        actor = Actor.system("uploader")
        outcomes = ingest_uploads([("good.eml", b"1"), ("bad.msg", b"2")], actor=actor, inbox=inbox)

        assert [o.status for o in outcomes] == ["INGESTED", "FAILED"]
        assert seen_actors == [actor, actor]
        assert [p.name for p in inbox.archive.rglob("*.eml")] == ["good.eml"]
        assert {p.name for p in inbox.failed.iterdir()} == {"bad.msg", "bad.msg.error.json"}
        assert list(inbox.inbox.iterdir()) == []

    def test_a_file_the_poller_won_is_reported_queued(self, inbox: Inbox, monkeypatch) -> None:
        monkeypatch.setattr(Inbox, "claim", lambda self, path: None)
        outcomes = ingest_uploads([("a.eml", b"1")], inbox=inbox)
        assert [o.status for o in outcomes] == ["QUEUED"]
        assert [p.name for p in inbox.inbox.iterdir()] == ["a.eml"]


# ─── Web ──────────────────────────────────────────────────────────────────────


def _advisory_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "DoH Cyber Advisory <cyber.advisory@doh.gov.ae>"
    msg["To"] = "soc@example.invalid"
    msg["Subject"] = "[EXTERNAL] Security Advisory :: DOH- 2026551 - Flaw in Apache Doris"
    msg["Date"] = "Thu, 23 Jul 2026 12:00:00 +0000"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@example.invalid>"
    msg.set_content(
        "Dear IS Stakeholder,\n\n"
        "Affected Product:\n\nApache Doris\n\n"
        "Type:\n\nVulnerability\n\n"
        "Risk level:\n\nCritical\n\n"
        "Description:\n\nCVE-2026-58319 affects Apache Doris.\n"
    )
    return msg.as_bytes()


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
    from advisory_hub.core.models.user import User
    from advisory_hub.core.services.auth import start_session
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override

    # The pipeline opens its own session; point it at the test transaction.
    @contextmanager
    def _scope() -> Iterator[object]:
        yield db
        db.flush()

    monkeypatch.setattr(pipeline, "session_scope", _scope)

    def client_for(role: str) -> TestClient:
        user = User(
            email=f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.invalid",
            display_name=role,
            role=role,
        )
        db.add(user)
        db.flush()
        session = start_session(db, user, ip_address="127.0.0.1", user_agent="test")
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    @pytest.mark.parametrize("path", ["/", "/inventory", "/affected-software", "/iocs"])
    def test_every_page_shows_the_header_nav(self, web, path: str) -> None:
        r = web("VIEWER").get(path)
        assert r.status_code == 200
        assert '<nav class="tabs">' in r.text and "Sign out" in r.text

    def test_viewer_cannot_upload(self, web) -> None:
        r = web("VIEWER").post(
            "/inbox/upload", files=[("files", ("a.eml", _advisory_eml(), "message/rfc822"))]
        )
        assert r.status_code == 403

    def test_analyst_sees_the_button(self, web) -> None:
        assert 'hx-post="/inbox/upload"' in web("ANALYST").get("/").text
        assert 'hx-post="/inbox/upload"' not in web("VIEWER").get("/").text

    def test_upload_ingests_and_links_the_advisory(self, db, web) -> None:
        from advisory_hub.core.models.advisory import Advisory
        from advisory_hub.core.services.sources import seed_default_sources

        seed_default_sources(db)
        db.flush()
        data = _advisory_eml()
        client = web("ANALYST")

        r = client.post("/inbox/upload", files=[("files", ("doh.eml", data, "message/rfc822"))])
        assert r.status_code == 200
        assert "Ingested" in r.text and "doh.eml" in r.text
        advisory_id = r.text.split('href="/advisories/')[1].split('"')[0]
        assert db.get(Advisory, uuid.UUID(advisory_id)) is not None

        again = client.post("/inbox/upload", files=[("files", ("doh.eml", data, "message/rfc822"))])
        assert "Already ingested" in again.text

    def test_rejected_upload_shows_an_error(self, web) -> None:
        r = web("ANALYST").post(
            "/inbox/upload", files=[("files", ("report.pdf", b"%PDF", "application/pdf"))]
        )
        assert r.status_code == 200
        assert 'class="error"' in r.text and "not an email file" in r.text
