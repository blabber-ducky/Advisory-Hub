"""Mailbox-folder sync via Microsoft Graph (D-049). No network: a fake Graph."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path

import httpx
import pytest

from advisory_hub.core.models.enums import SystemIntegrationKind
from advisory_hub.core.services import mailbox_sync
from advisory_hub.core.services.audit import Actor
from advisory_hub.ingest import graph_mailbox
from advisory_hub.ingest.watcher import Inbox
from advisory_hub.inventory import api_client

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MAILBOX = "advisories@contoso.example"
BASE = f"https://graph.microsoft.com/v1.0/users/{MAILBOX}"
DELTA = f"{BASE}/mailFolders/SEC/messages/delta"


def _eml(ref: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = "DoH Cyber Advisory <cyber.advisory@doh.gov.ae>"
    msg["To"] = MAILBOX
    msg["Subject"] = f"[EXTERNAL] Security Advisory :: {ref} - Something critical"
    msg["Date"] = "Mon, 05 Oct 2026 09:00:00 +0400"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@doh.example>"
    msg.set_content("Type:\n\nVulnerability\n\nRisk level:\n\nHigh\n\nDescription:\n\nx\n")
    return msg.as_bytes()


class FakeGraph:
    def __init__(self) -> None:
        self.messages = {"m1": _eml("DOH-2026801"), "m2": _eml("DOH-2026802")}
        self.pages = {
            "start": (["m1"], f"{DELTA}?$skiptoken=p2", None),
            "p2": (["m2", "@removed:gone"], None, f"{DELTA}?$deltatoken=D1"),
            "D1": ([], None, f"{DELTA}?$deltatoken=D2"),
            "D2": ([], None, f"{DELTA}?$deltatoken=D2"),
        }  # fmt: skip
        self.folder_status = 200
        self.expired_tokens: set[str] = set()
        self.methods: list[tuple[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.methods.append((request.method, request.url.host))
        url = str(request.url)
        path = request.url.path
        if path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "graph-token"})
        assert request.headers["authorization"] == "Bearer graph-token"
        if path.endswith("/mailFolders/inbox"):
            if self.folder_status != 200:
                return httpx.Response(self.folder_status, json={"error": {"code": "x"}})
            return httpx.Response(200, json={"id": "INBOX", "displayName": "Inbox"})
        if path.endswith("/mailFolders/INBOX/childFolders"):
            return httpx.Response(
                200,
                json={"value": [
                    {"id": "OTHER", "displayName": "Other"},
                    {"id": "SEC", "displayName": "Security Advisories", "totalItemCount": 2},
                ]},
            )  # fmt: skip
        if path.endswith("/messages/delta"):
            q = request.url.params
            key = q.get("$deltatoken") or q.get("$skiptoken") or "start"
            if key in self.expired_tokens:
                return httpx.Response(410, json={"error": {"code": "SyncStateNotFound"}})
            ids, next_link, delta_link = self.pages[key]
            value = [
                {"id": i.split(":")[1], "@removed": {"reason": "deleted"}}
                if i.startswith("@removed")
                else {"id": i}
                for i in ids
            ]
            body: dict = {"value": value}
            if next_link:
                body["@odata.nextLink"] = next_link
            if delta_link:
                body["@odata.deltaLink"] = delta_link
            return httpx.Response(200, json=body)
        if path.endswith("/$value"):
            message_id = path.split("/messages/")[1].split("/")[0]
            return httpx.Response(200, content=self.messages[message_id])
        raise AssertionError(f"unexpected request {request.method} {url}")

    def client(self, *_, **__) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def graph(monkeypatch) -> FakeGraph:
    from cryptography.fernet import Fernet

    from advisory_hub.config import get_settings

    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    for module in (graph_mailbox, api_client):
        monkeypatch.setattr(module, "validate_outbound_url", lambda url: None)
    fake = FakeGraph()
    monkeypatch.setattr(mailbox_sync, "_http_client", fake.client)
    yield fake
    get_settings.cache_clear()


@pytest.fixture
def configured(db, graph):
    from advisory_hub.core.services.system_integrations import (
        save_entra_settings,
        set_entra_enabled,
    )

    actor = Actor.system("test")
    save_entra_settings(
        db,
        SystemIntegrationKind.MAILBOX_SYNC,
        config={
            "tenant_id": TENANT,
            "client_id": CLIENT,
            "mailbox": MAILBOX,
            "folder": " Inbox / Security Advisories ",
            "poll_seconds": "",
        },
        client_secret="mail-secret",
        actor=actor,
    )
    set_entra_enabled(db, SystemIntegrationKind.MAILBOX_SYNC, enabled=True, actor=actor)
    db.flush()
    return graph


@pytest.fixture
def inbox(tmp_path: Path) -> Inbox:
    return Inbox(
        inbox=tmp_path / "inbox",
        processing=tmp_path / "processing",
        archive=tmp_path / "archive",
        failed=tmp_path / "failed",
        worker_id="test",
    )


@pytest.mark.integration
class TestSync:
    def test_first_sync_deposits_every_message_and_saves_the_position(
        self, db, configured, inbox
    ) -> None:
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert (report.status, report.fetched) == ("ok", 2)
        files = sorted(p.read_bytes() for p in inbox.pending())
        assert files == sorted(configured.messages.values())
        state = mailbox_sync.state(db)
        assert state.folder_id == "SEC" and state.delta_link.endswith("$deltatoken=D1")
        assert state.last_status == "ok" and state.fetched_total == 2

    def test_next_cycle_fetches_only_new_messages(self, db, configured, inbox) -> None:
        mailbox_sync.run_sync(db, inbox=inbox)
        configured.messages["m3"] = _eml("DOH-2026803")
        configured.pages["D1"] = (
            ["m3"],
            None,
            f"{DELTA}?$deltatoken=D2",
        )
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert report.fetched == 1
        assert len(inbox.pending()) == 3
        assert mailbox_sync.run_sync(db, inbox=inbox).fetched == 0

    def test_never_writes_to_the_mailbox(self, db, configured, inbox) -> None:
        mailbox_sync.run_sync(db, inbox=inbox)
        graph_calls = [m for m, host in configured.methods if host == "graph.microsoft.com"]
        assert graph_calls and set(graph_calls) == {"GET"}

    def test_imported_mail_goes_through_the_normal_pipeline_once(
        self, db, configured, inbox, monkeypatch, tmp_path
    ) -> None:
        from advisory_hub.core.services.sources import seed_default_sources
        from advisory_hub.ingest import pipeline

        seed_default_sources(db)

        @contextmanager
        def _scope():
            yield db
            db.flush()

        monkeypatch.setattr(pipeline, "session_scope", _scope)
        monkeypatch.setenv("BLOB_ROOT", str(tmp_path / "blobs"))
        from advisory_hub.config import get_settings

        get_settings.cache_clear()
        mailbox_sync.run_sync(db, inbox=inbox)
        outcomes = pipeline.process_inbox(inbox=inbox)
        assert sorted((o.status, o.external_ref) for o in outcomes) == [
            ("INGESTED", "DOH-2026801"),
            ("INGESTED", "DOH-2026802"),
        ]
        # The sync position is lost (e.g. expired): everything comes again, and
        # the duplicate gates stop it.
        mailbox_sync.state(db).delta_link = None
        mailbox_sync.run_sync(db, inbox=inbox)
        assert {o.status for o in pipeline.process_inbox(inbox=inbox)} == {"DUPLICATE"}

    def test_too_large_is_skipped_and_counted(self, db, configured, inbox, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        configured.messages["m2"] = b"x" * 5000
        monkeypatch.setenv("UPLOAD_MAX_BYTES", "4000")
        get_settings.cache_clear()
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert (report.fetched, report.skipped_too_large) == (1, 1)
        assert mailbox_sync.state(db).skipped_too_large_total == 1

    def test_expired_position_starts_over(self, db, configured, inbox) -> None:
        mailbox_sync.run_sync(db, inbox=inbox)
        configured.expired_tokens.add("D1")
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert report.status == "ok" and report.fetched == 2  # re-listed from the start

    def test_access_denied_is_recorded_not_raised(self, db, configured, inbox) -> None:
        configured.folder_status = 403
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert report.status == "error" and "Application Mail.Read" in report.message
        state = mailbox_sync.state(db)
        assert state.last_status == "error" and "Access denied" in state.last_error

    def test_token_is_never_sent_to_another_host(self, db, configured, inbox) -> None:
        configured.pages["start"] = (["m1"], "https://evil.example/steal", None)
        report = mailbox_sync.run_sync(db, inbox=inbox)
        assert report.status == "error" and "evil.example" in report.message
        assert all(host != "evil.example" for _, host in configured.methods)

    def test_changing_the_folder_starts_over(self, db, configured, inbox) -> None:
        from advisory_hub.core.services.system_integrations import entra_app, save_entra_settings

        mailbox_sync.run_sync(db, inbox=inbox)
        app = entra_app(db, SystemIntegrationKind.MAILBOX_SYNC)
        save_entra_settings(
            db,
            SystemIntegrationKind.MAILBOX_SYNC,
            config={**app.config, "folder": "Inbox/Other"},
            client_secret=None,
            actor=Actor.system("test"),
        )
        mailbox_sync.run_sync(db, inbox=inbox)
        state = mailbox_sync.state(db)
        assert state.target.endswith("|Inbox/Other") and state.folder_id == "OTHER"

    def test_disabled_does_nothing(self, db, graph, inbox) -> None:
        assert mailbox_sync.run_sync(db, inbox=inbox).status == "disabled"
        assert graph.methods == []

    def test_check_connection(self, db, configured) -> None:
        ok, message = mailbox_sync.check_connection(db)
        assert ok and "2 message(s)" in message


@pytest.mark.integration
class TestSettings:
    def test_validation(self, db, graph) -> None:
        from advisory_hub.core.services.system_integrations import (
            EntraSettingsError,
            save_entra_settings,
            set_entra_enabled,
        )

        kind, actor = SystemIntegrationKind.MAILBOX_SYNC, Actor.system("t")
        base = {"tenant_id": TENANT, "client_id": CLIENT, "mailbox": MAILBOX, "folder": "Inbox"}
        for bad, msg in [
            ({"tenant_id": "contoso.onmicrosoft.com"}, "must be a GUID"),
            ({"mailbox": "not-an-address"}, "email address"),
            ({"poll_seconds": "5"}, "at least 60"),
        ]:
            with pytest.raises(EntraSettingsError, match=msg):
                save_entra_settings(
                    db, kind, config={**base, **bad}, client_secret="s", actor=actor
                )
        save_entra_settings(db, kind, config=base, client_secret=None, actor=actor)
        with pytest.raises(EntraSettingsError, match="client_secret"):
            set_entra_enabled(db, kind, enabled=True, actor=actor)

    def test_secret_is_never_in_the_audit_log(self, db, graph) -> None:
        from sqlalchemy import select

        from advisory_hub.core.models.user import AuditLog
        from advisory_hub.core.services.system_integrations import save_entra_settings

        save_entra_settings(
            db,
            SystemIntegrationKind.MAILBOX_SYNC,
            config={
                "tenant_id": TENANT,
                "client_id": CLIENT,
                "mailbox": MAILBOX,
                "folder": "Inbox",
            },
            client_secret="top-secret-value",
            actor=Actor.system("t"),
        )
        entry = db.scalar(
            select(AuditLog).where(AuditLog.action == "system_integration.config_set")
        )
        assert "top-secret-value" not in str(entry.detail)
        assert entry.detail["client_secret"] == "rotated"


# ─── Admin web ────────────────────────────────────────────────────────────────


@pytest.fixture
def admin_web(db, graph, tmp_path, monkeypatch):
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    from fastapi.testclient import TestClient

    from advisory_hub.api.deps import SESSION_COOKIE, db_session, sign
    from advisory_hub.config import get_settings
    from advisory_hub.core.models.enums import Role
    from advisory_hub.core.models.user import User
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
        user = User(email=f"{uuid.uuid4().hex[:8]}@x.example", display_name="Adm", role=role)
        db.add(user)
        db.flush()
        session = start_session(db, user)
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


_FORM = {
    "tenant_id": TENANT,
    "client_id": CLIENT,
    "client_secret": "never-shown-secret",
    "mailbox": MAILBOX,
    "folder": "Inbox/Security Advisories",
    "poll_seconds": "120",
}


@pytest.mark.integration
class TestAdminWeb:
    def test_analyst_cannot_configure(self, admin_web) -> None:
        from advisory_hub.core.models.enums import Role

        r = admin_web(Role.ANALYST).post("/admin/entra/mailbox_sync/settings", data=_FORM)
        assert r.status_code == 403

    def test_save_enable_sync_and_secret_never_rendered(self, db, admin_web) -> None:
        from advisory_hub.core.models.enums import Role
        from advisory_hub.core.services.sources import seed_default_sources

        seed_default_sources(db)
        client = admin_web(Role.ADMIN)
        r = client.post("/admin/entra/mailbox_sync/settings", data=_FORM)
        assert r.status_code == 200 and "Saved." in r.text
        assert "never-shown-secret" not in r.text and "(set — blank keeps it)" in r.text
        assert "never-shown-secret" not in client.get("/admin").text

        assert "Connected" in client.post("/admin/entra/mailbox_sync/test").text
        assert (
            "Enabled"
            in client.post("/admin/entra/mailbox_sync/enabled", data={"enabled": "true"}).text
        )
        r = client.post("/admin/entra/mailbox_sync/sync-now")
        assert "2 new message(s) imported" in r.text and "2 ingested" in r.text

    def test_enable_refused_until_complete(self, admin_web) -> None:
        from advisory_hub.core.models.enums import Role

        r = admin_web(Role.ADMIN).post("/admin/entra/entra_sso/enabled", data={"enabled": "true"})
        assert 'class="error"' in r.text and "client_secret" in r.text

    def test_unknown_and_api_key_routes_are_separate(self, admin_web) -> None:
        from advisory_hub.core.models.enums import Role

        client = admin_web(Role.ADMIN)
        assert client.post("/admin/entra/nvd/settings", data=_FORM).status_code == 404
        r = client.post("/admin/integrations/ENTRA_SSO/key", data={"api_key": "x"})
        assert r.status_code == 404
