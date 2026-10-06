"""Ivanti ITSM ticket integration (D-050). No network: a fake Ivanti answers
SOAP shaped exactly like the tenant's WSDL (namespace SaaS.Services)."""

from __future__ import annotations

import base64
import uuid
from xml.sax.saxutils import escape

import httpx
import pytest
from defusedxml import ElementTree as SafeET
from sqlalchemy import select

from advisory_hub.core.models.enums import Role
from advisory_hub.core.services import tickets
from advisory_hub.core.services.audit import Actor
from advisory_hub.integrations import ivanti

BASE = "https://tenant.ivanticloud.example"
NS = "SaaS.Services"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"

SERVICES = ["Endpoint Security", "Network", "Email"]
CATEGORIES = {"Endpoint Security": ["Patching", "Malware"], "Network": ["Firewall"]}
SUBCATEGORIES = {"Patching": ["Operating System", "Third-party"], "Firewall": ["Rules"]}
TEAMS = ["SOC", "Desktop Support", "Network Team"]
SCHEMA = (
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="ServiceReq">'
    "<xs:complexType><xs:sequence>"
    + "".join(
        f'<xs:element name="{n}" type="xs:string" minOccurs="{m}" />'
        for n, m in [
            ("Service", "0"), ("Category", "0"), ("Subcategory", "0"), ("OwnerTeam", "0"),
            ("Subject", "0"), ("Symptom", "0"), ("ServiceReqNumber", "0"), ("ProfileLink", "1"),
        ]
    )
    + "</xs:sequence></xs:complexType></xs:element></xs:schema>"
)  # fmt: skip


def _bo(fields: dict[str, str], rec_id: str = "") -> str:
    values = "".join(
        f"<WebServiceFieldValue><Name>{escape(k)}</Name><Value>{escape(v)}</Value></WebServiceFieldValue>"
        for k, v in fields.items()
    )
    return f"<RecID>{rec_id}</RecID><FieldValues>{values}</FieldValues>"


def _wrap(tag: str, inner: str) -> str:
    return f"<{tag}>{inner}</{tag}>"


def _soap(op: str, inner: str) -> str:
    return (
        f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="{SOAP}"><soap:Body>'
        f'<{op}Response xmlns="{NS}"><{op}Result>{inner}</{op}Result></{op}Response>'
        "</soap:Body></soap:Envelope>"
    )


class FakeIvanti:
    def __init__(self) -> None:
        self.api_key = "good-key"
        self.calls: list[tuple[str, str]] = []  # (operation, host)
        self.created: list[dict[str, str]] = []
        self.attachments: list[tuple[str, bytes]] = []
        self.create_status = "Success"
        self.attach_status = "Success"
        self.lists = {
            "CI#Service": lambda where: SERVICES,
            "Category#": lambda where: CATEGORIES.get(where.get("Service", ""), []),
            "Subcategory#": lambda where: SUBCATEGORIES.get(where.get("Category", ""), []),
            "StandardUserTeam#": lambda where: TEAMS,
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        op = request.headers["SOAPAction"].strip('"').split("/")[-1]
        self.calls.append((op, request.url.host))
        assert request.url.path == "/ServiceAPI/FRSHEATIntegration.asmx"
        body = SafeET.fromstring(request.content).find(f"{{{SOAP}}}Body")[0]

        def text(tag: str) -> str:
            el = body.find(f"{{{NS}}}{tag}")
            return el.text or "" if el is not None else ""

        if op == "AuthenticateTenantAPIKey":
            if text("apiKey") != self.api_key:
                return httpx.Response(
                    500,
                    text=f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body><soap:Fault>'
                    "<faultcode>soap:Server</faultcode><faultstring>Invalid API key</faultstring>"
                    "</soap:Fault></soap:Body></soap:Envelope>",
                )
            return httpx.Response(200, text=_soap(op, "SESSION-1"))
        assert text("sessionKey") == "SESSION-1"
        if op == "GetSchemaForObject":
            return httpx.Response(200, text=_soap(op, escape(SCHEMA)))
        if op == "PaginationSearch":
            query = body.find(f"{{{NS}}}ObjectQuery")
            bo = query.find(f"{{{NS}}}From").get("Object")
            display = query.find(f".//{{{NS}}}Field").get("Name")
            where = {r.get("Field"): r.get("Value") for r in query.iter(f"{{{NS}}}Rule")}
            values = self.lists[bo](where) if text("skip") == "0" else []
            objs = "".join(
                _wrap("WebServiceBusinessObject", _bo({display: v}, f"R-{v}")) for v in values
            )
            inner = "<status>Success</status>" + _wrap(
                "objList", _wrap("ArrayOfWebServiceBusinessObject", objs)
            )
            return httpx.Response(200, text=_soap(op, inner))
        if op == "CreateObject":
            fields = {
                f.findtext(f"{{{NS}}}Name"): f.findtext(f"{{{NS}}}Value") or ""
                for f in body.iter(f"{{{NS}}}ObjectCommandDataFieldValue")
            }
            if self.create_status != "Success":
                inner = _wrap("status", self.create_status) + _wrap(
                    "exceptionReason", "Subcategory is required by business rule"
                )
                return httpx.Response(200, text=_soap(op, inner))
            self.created.append(fields)
            number = {**fields, "ServiceReqNumber": "10452"}
            inner = _wrap("status", "Success") + _wrap("recId", "REC-1")
            inner += _wrap("obj", _bo(number, "REC-1"))
            return httpx.Response(200, text=_soap(op, inner))
        if op == "AddAttachment":
            data = base64.b64decode(body.find(f".//{{{NS}}}fileData").text)
            self.attachments.append((body.findtext(f".//{{{NS}}}fileName"), data))
            inner = (
                f"<status>{self.attach_status}</status><exceptionReason>too big</exceptionReason>"
            )
            return httpx.Response(200, text=_soap(op, inner))
        raise AssertionError(f"unexpected operation {op}")

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def fake(monkeypatch) -> FakeIvanti:
    from cryptography.fernet import Fernet

    from advisory_hub.config import get_settings

    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://hub.example")
    get_settings.cache_clear()
    monkeypatch.setattr(ivanti, "validate_outbound_url", lambda url: None)
    f = FakeIvanti()
    monkeypatch.setattr(tickets, "_http_client", f.client)
    tickets.clear_cache()
    yield f
    get_settings.cache_clear()


ACTOR = Actor.system("test")


@pytest.fixture
def configured(db, fake):
    tickets.save_settings(db, base_url=BASE, api_key="good-key", advanced=None, actor=ACTOR)
    report = tickets.run_test(db, actor=ACTOR)
    assert report.ok, report.steps
    tickets.set_ivanti_enabled(db, enabled=True, actor=ACTOR)
    db.flush()
    return fake


@pytest.fixture
def advisory(db, tmp_path, monkeypatch):
    from advisory_hub.core.models.advisory import Advisory, AdvisoryAttachment, Blob
    from advisory_hub.core.models.enums import AdvisoryStatus, AdvisoryType, Severity
    from advisory_hub.core.services.sources import seed_default_sources
    from advisory_hub.core.storage.blobs import FilesystemBlobStore

    monkeypatch.setenv("BLOB_ROOT", str(tmp_path / "blobs"))
    from advisory_hub.config import get_settings

    get_settings.cache_clear()
    seed_default_sources(db)
    from advisory_hub.core.models.advisory import Source

    source = db.scalar(select(Source).where(Source.short_code == "DOH"))
    pdf = b"%PDF-1.4 advisory body"
    stored = FilesystemBlobStore(tmp_path / "blobs").put_bytes(pdf)
    blob = Blob(sha256=stored.sha256, size_bytes=stored.size_bytes, content_type="application/pdf")
    db.add(blob)
    db.flush()
    from advisory_hub.core.models.base import utcnow

    adv = Advisory(
        source_id=source.id,
        external_ref="DOH-2026901",
        type=AdvisoryType.CVE_ADVISORY,
        title='FortiOS <heap> overflow & "RCE"',
        description="Critical flaw.",
        severity=Severity.CRITICAL,
        status=AdvisoryStatus.NEW,
        received_at=utcnow(),
        ingested_at=utcnow(),
        dedupe_hash=uuid.uuid4().hex,
        parser_version="3",
    )
    db.add(adv)
    db.flush()
    db.add(AdvisoryAttachment(advisory_id=adv.id, blob_id=blob.id, filename="DOH-2026901.pdf"))
    db.flush()
    db.refresh(adv)
    return adv


CHOICES = {
    "service": "Endpoint Security",
    "category": "Patching",
    "subcategory": "Third-party",
    "team": "SOC",
}


@pytest.mark.integration
class TestSettingsAndTest:
    def test_test_walks_every_list_and_reports_uncovered_required_fields(self, db, fake) -> None:
        tickets.save_settings(db, base_url=BASE, api_key="good-key", advanced=None, actor=ACTOR)
        report = tickets.run_test(db, actor=ACTOR)
        steps = {s.label.split(" (")[0]: s for s in report.steps}
        assert report.ok
        assert "3 value(s)" in steps["Service list"].detail
        # "Email" (first) has no categories: Test moves on to the next service.
        assert "for 'Endpoint Security'" in steps["Category list"].detail
        assert "for 'Patching'" in steps["Sub-category list"].detail
        assert "ProfileLink" in steps["Ticket fields"].detail  # required, not set here

    def test_bad_key(self, db, fake) -> None:
        tickets.save_settings(db, base_url=BASE, api_key="wrong", advanced=None, actor=ACTOR)
        report = tickets.run_test(db, actor=ACTOR)
        assert not report.ok and "Invalid API key" in report.steps[0].detail
        with pytest.raises(tickets.TicketError, match="successful Test"):
            tickets.set_ivanti_enabled(db, enabled=True, actor=ACTOR)

    def test_a_failing_list_is_pinpointed(self, db, fake) -> None:
        tickets.save_settings(
            db, base_url=BASE, api_key="good-key",
            advanced={"levels": {"subcategory": {"bo": "CI#Service", "parent": "Nope"}}},
            actor=ACTOR,
        )  # fmt: skip
        fake.lists["CI#Service"] = lambda where: [] if "Nope" in where else SERVICES
        report = tickets.run_test(db, actor=ACTOR)
        failing = [(s.label, s.detail) for s in report.steps if not s.ok]
        assert failing == [
            ("Sub-category list (CI#Service)", "No values (tried under 2 value(s) above).")
        ]

    def test_changing_where_lists_come_from_requires_a_new_test(self, db, configured) -> None:
        assert tickets.is_enabled(db)
        tickets.save_settings(
            db, base_url=BASE, api_key=None,
            advanced={"levels": {"team": {"bo": "Team#"}}}, actor=ACTOR,
        )  # fmt: skip
        assert not tickets.is_enabled(db)
        assert "a successful Test" in tickets.get_settings(db).missing()

    @pytest.mark.parametrize(
        ("base_url", "advanced", "message"),
        [
            ("http://tenant.example", None, "https://"),
            (f"{BASE}/ServiceAPI", None, "address only"),
            (BASE, {"subject_template": "{ref} {secret}"}, "Unknown placeholder"),
            (BASE, {"extra_fields": "NoEquals"}, "isn't Name=Value"),
        ],
    )
    def test_validation(self, db, fake, base_url, advanced, message) -> None:
        with pytest.raises(tickets.TicketError, match=message):
            tickets.save_settings(
                db, base_url=base_url, api_key="k", advanced=advanced, actor=ACTOR
            )

    def test_key_is_never_in_the_audit_log(self, db, fake) -> None:
        from advisory_hub.core.models.user import AuditLog

        tickets.save_settings(
            db, base_url=BASE, api_key="super-secret-key", advanced=None, actor=ACTOR
        )
        entries = db.scalars(
            select(AuditLog).where(AuditLog.action == "system_integration.config_set")
        )
        assert all("super-secret-key" not in str(e.detail) for e in entries)


@pytest.mark.integration
class TestOptions:
    def test_cascade(self, db, configured) -> None:
        assert tickets.options(db, "service") == sorted(SERVICES)
        assert tickets.options(db, "category", "Endpoint Security") == ["Malware", "Patching"]
        assert tickets.options(db, "category", "Email") == []
        assert tickets.options(db, "subcategory", "Patching") == ["Operating System", "Third-party"]
        assert tickets.options(db, "subcategory", None) == []  # needs a parent
        assert tickets.options(db, "team") == sorted(TEAMS)

    def test_cached(self, db, configured) -> None:
        tickets.options(db, "service")
        before = len(configured.calls)
        tickets.options(db, "service")
        assert len(configured.calls) == before


@pytest.mark.integration
class TestCreate:
    def test_creates_links_attaches_and_audits(self, db, configured, advisory) -> None:
        from advisory_hub.core.models.user import AuditLog

        subject, description = tickets.draft(db, advisory, "Ana")
        assert subject == 'DOH-2026901 - FortiOS <heap> overflow & "RCE"'
        assert "https://hub.example/advisories/" in description
        result = tickets.create_ticket(
            db, advisory.id, choices=CHOICES, subject=subject, description=description, actor=ACTOR
        )
        t = result.ticket
        assert (t.number, t.rec_id, t.attachment_count, t.warning) == ("10452", "REC-1", 1, None)
        assert t.url == (
            f"{BASE}/HEAT/Default.aspx?Scope=ObjectWorkspace&CommandId=Search"
            "&ObjectType=ServiceReq%23&CommandData=RecId,%3D,0,REC-1,string,AND|"
        )
        sent = configured.created[0]
        assert sent["Service"] == "Endpoint Security" and sent["OwnerTeam"] == "SOC"
        assert sent["Subcategory"] == "Third-party"
        assert sent["Subject"] == subject  # special characters survive the round trip
        assert configured.attachments == [("DOH-2026901.pdf", b"%PDF-1.4 advisory body")]
        assert db.scalar(select(AuditLog).where(AuditLog.action == "advisory.ticket_created"))

    def test_all_four_are_required(self, db, configured, advisory) -> None:
        with pytest.raises(tickets.TicketError, match="Sub-category"):
            tickets.create_ticket(
                db, advisory.id, choices={**CHOICES, "subcategory": ""},
                subject="s", description="d", actor=ACTOR,
            )  # fmt: skip
        assert configured.created == []

    def test_a_value_outside_its_parents_list_is_refused(self, db, configured, advisory) -> None:
        with pytest.raises(tickets.TicketError, match="isn't a Category"):
            tickets.create_ticket(
                db, advisory.id, choices={**CHOICES, "service": "Email"},
                subject="s", description="d", actor=ACTOR,
            )  # fmt: skip
        with pytest.raises(tickets.TicketError, match="isn't a Team"):
            tickets.create_ticket(
                db, advisory.id, choices={**CHOICES, "team": "Made-up team"},
                subject="s", description="d", actor=ACTOR,
            )  # fmt: skip
        assert configured.created == []

    def test_double_click_creates_one(self, db, configured, advisory) -> None:
        first = tickets.create_ticket(
            db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
        )
        again = tickets.create_ticket(
            db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
        )
        assert again.reused and again.ticket.id == first.ticket.id
        assert len(configured.created) == 1

    def test_ivanti_refusal_is_shown_and_nothing_stored(self, db, configured, advisory) -> None:
        configured.create_status = "Error"
        with pytest.raises(tickets.TicketError, match="business rule"):
            tickets.create_ticket(
                db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
            )
        assert tickets.tickets_for(db, advisory.id) == []

    def test_attachment_failure_keeps_the_ticket(self, db, configured, advisory) -> None:
        configured.attach_status = "Error"
        t = tickets.create_ticket(
            db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
        ).ticket
        assert t.number == "10452" and t.attachment_count == 0
        assert "not attached" in t.warning

    def test_disabled(self, db, fake, advisory) -> None:
        with pytest.raises(tickets.TicketError, match="isn't enabled"):
            tickets.create_ticket(
                db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
            )

    def test_api_key_only_goes_to_the_tenant(self, db, configured, advisory) -> None:
        tickets.create_ticket(
            db, advisory.id, choices=CHOICES, subject="s", description="d", actor=ACTOR
        )
        assert {host for _, host in configured.calls} == {"tenant.ivanticloud.example"}


def test_client_refuses_xml_entities() -> None:
    evil = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]>'
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body>&e;</soap:Body></soap:Envelope>'
    )
    client = ivanti.IvantiClient(
        BASE,
        "t",
        "k",
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=evil))),
    )
    ivanti_validate = ivanti.validate_outbound_url
    ivanti.validate_outbound_url = lambda url: None
    try:
        with pytest.raises(ivanti.IvantiError, match="isn't SOAP"):
            client.authenticate()
    finally:
        ivanti.validate_outbound_url = ivanti_validate


# ─── Web ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def web(db, fake, tmp_path, monkeypatch):
    for var in ("INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
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

    def client_for(role: Role) -> TestClient:
        user = User(
            email=f"{uuid.uuid4().hex[:8]}@x.example",
            display_name=f"{role.value.title()} User",
            role=role,
        )
        db.add(user)
        db.flush()
        session = start_session(db, user)
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    def test_panel_and_button_for_analysts_only(self, db, configured, advisory, web) -> None:
        analyst = web(Role.ANALYST).get(f"/advisories/{advisory.id}").text
        viewer = web(Role.VIEWER).get(f"/advisories/{advisory.id}").text
        assert 'id="tickets-panel"' in analyst and "Create ticket" in analyst
        assert 'id="ticket-dialog"' in analyst
        assert 'id="tickets-panel"' in viewer and "Create ticket" not in viewer
        assert web(Role.VIEWER).get(f"/advisories/{advisory.id}/tickets/new").status_code == 403

    def test_no_panel_while_disabled(self, db, fake, advisory, web) -> None:
        assert 'id="tickets-panel"' not in web(Role.ANALYST).get(f"/advisories/{advisory.id}").text

    def test_dialog_and_cascade(self, db, configured, advisory, web) -> None:
        client = web(Role.ANALYST)
        dialog = client.get(f"/advisories/{advisory.id}/tickets/new").text
        assert '<option value="Endpoint Security"' in dialog and '<option value="SOC"' in dialog
        assert "Choose a Service first" in dialog  # category waits for a service
        assert 'value="DOH-2026901 - FortiOS &lt;heap&gt; overflow &amp; &#34;RCE&#34;"' in dialog

        r = client.get(
            f"/advisories/{advisory.id}/tickets/options",
            params={"level": "category", "service": "Endpoint Security"},
        )
        assert '<option value="Patching"' in r.text and '<option value="Malware"' in r.text
        # Sub-category is reset out-of-band; Team (not narrowed) isn't touched.
        assert 'id="ticket-level-subcategory" class="ticket-field" hx-swap-oob="true"' in r.text
        assert "ticket-level-team" not in r.text

        r = client.get(
            f"/advisories/{advisory.id}/tickets/options",
            params={"level": "subcategory", "category": "Patching"},
        )
        assert '<option value="Third-party"' in r.text

    def test_create_and_link(self, db, configured, advisory, web) -> None:
        client = web(Role.ANALYST)
        r = client.post(
            f"/advisories/{advisory.id}/tickets",
            data={**CHOICES, "subject": "DOH-2026901 - FortiOS", "description": "d"},
        )
        assert r.status_code == 200
        assert (
            r.headers["HX-Retarget"] == "#tickets-panel"
            and r.headers["HX-Trigger"] == "ticket-created"
        )
        assert "SR 10452" in r.text and "CommandData=RecId,%3D,0,REC-1" in r.text
        assert "Create another ticket" in r.text
        assert configured.created[0]["Subject"] == "DOH-2026901 - FortiOS"

    def test_missing_choice_reshows_the_dialog(self, db, configured, advisory, web) -> None:
        r = web(Role.ANALYST).post(
            f"/advisories/{advisory.id}/tickets",
            data={**CHOICES, "team": "", "subject": "s", "description": "d"},
        )
        assert "HX-Retarget" not in r.headers
        assert 'class="error"' in r.text and "Choose a Team" in r.text
        assert '<option value="Endpoint Security" selected' in r.text  # choices kept
        assert configured.created == []

    def test_admin_card(self, db, fake, web) -> None:
        admin = web(Role.ADMIN)
        r = admin.post(
            "/admin/ivanti/settings",
            data={"base_url": BASE, "api_key": "good-key", "attach_pdfs": "on"},
        )
        assert "Saved. Run Test before enabling." in r.text and "good-key" not in r.text
        assert "(set — blank keeps it)" in r.text
        r = admin.post("/admin/ivanti/enabled", data={"enabled": "true"})
        assert "successful Test" in r.text
        r = admin.post("/admin/ivanti/test")
        assert "Test passed." in r.text and "3 value(s)" in r.text
        r = admin.post("/admin/ivanti/enabled", data={"enabled": "true"})
        assert "Enabled — analysts now see Create ticket" in r.text
        assert web(Role.ANALYST).post("/admin/ivanti/test").status_code == 403
        assert "good-key" not in admin.get("/admin").text
