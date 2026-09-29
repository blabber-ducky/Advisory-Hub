"""Integration tests for `/api/v1/advisories` and `/api/v1/sources`.

Exercises the real FastAPI app and routing/auth/exception-handling stack,
with `db_session` overridden to the transactional `db` fixture so no real
database commit happens. Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from advisory_hub.core.models.advisory import Advisory, Source
from advisory_hub.core.models.enums import (
    SLA_HOURS,
    AdvisoryStatus,
    AdvisoryType,
    Priority,
    Severity,
)
from advisory_hub.core.models.user import ApiToken
from advisory_hub.core.security.tokens import Scope, mint_token

pytestmark = pytest.mark.integration


@pytest.fixture
def client(db, tmp_path, monkeypatch) -> TestClient:
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")

    from advisory_hub.config import get_settings

    get_settings.cache_clear()

    from advisory_hub.api.deps import db_session
    from advisory_hub.main import create_app

    def _override_db_session():
        yield db

    app = create_app()
    app.dependency_overrides[db_session] = _override_db_session
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 51000))


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TR", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


def _make_advisory(db: Any, source: Source, *, ref: str, status: AdvisoryStatus) -> Advisory:
    received = datetime(2020, 1, 1, tzinfo=UTC)
    ack_hours, resolve_hours = SLA_HOURS[Priority.P2]
    advisory = Advisory(
        source_id=source.id,
        external_ref=ref,
        type=AdvisoryType.CVE_ADVISORY,
        title=f"Test advisory {ref}",
        received_at=received,
        dedupe_hash=ref.ljust(64, "0").lower(),
        parser_version="1",
        severity=Severity.HIGH,
        priority=Priority.P2,
        status=status,
        ack_due_at=received + timedelta(hours=ack_hours),
        resolution_due_at=received + timedelta(hours=resolve_hours),
    )
    db.add(advisory)
    db.flush()
    return advisory


def _token(db, *scopes: str) -> str:
    minted = mint_token()
    db.add(
        ApiToken(
            name="test",
            token_prefix=minted.prefix,
            token_hash=minted.token_hash,
            scopes=list(scopes),
        )
    )
    db.flush()
    return minted.plaintext


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestAuth:
    def test_no_token_is_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/advisories")
        assert r.status_code == 401
        assert r.json()["type"].endswith("unauthenticated")

    def test_bad_token_is_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/advisories", headers=_auth("ah_deadbeef_notreal"))
        assert r.status_code == 401

    def test_read_token_cannot_write(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_READ)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/status",
            json={"to_status": "TRIAGED", "comment": "x"},
            headers=_auth(token),
        )
        assert r.status_code == 403


class TestListAdvisories:
    def test_lists_with_pagination(self, db, client: TestClient, source: Source) -> None:
        for i in range(3):
            _make_advisory(db, source, ref=f"A-{i}", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_READ)

        r = client.get("/api/v1/advisories", params={"limit": 2}, headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

        r2 = client.get(
            "/api/v1/advisories",
            params={"limit": 2, "cursor": body["next_cursor"]},
            headers=_auth(token),
        )
        assert r2.status_code == 200
        assert len(r2.json()["items"]) == 1

    def test_bad_cursor_is_400(self, db, client: TestClient) -> None:
        token = _token(db, Scope.ADVISORIES_READ)
        r = client.get("/api/v1/advisories", params={"cursor": "not-valid"}, headers=_auth(token))
        assert r.status_code == 400
        assert r.json()["type"].endswith("invalid-cursor")


class TestGetAdvisory:
    def test_unknown_id_is_404_problem_detail(self, db, client: TestClient) -> None:
        import uuid

        token = _token(db, Scope.ADVISORIES_READ)
        r = client.get(f"/api/v1/advisories/{uuid.uuid4()}", headers=_auth(token))
        assert r.status_code == 404
        body = r.json()
        assert body["type"].endswith("advisory-not-found")
        assert body["status"] == 404

    def test_iocs_never_carry_the_raw_value(self, db, client: TestClient, source: Source) -> None:
        """CLAUDE.md §2.3: every surface renders IOCs defanged."""
        from advisory_hub.core.models.advisory import AdvisoryIoc
        from advisory_hub.core.models.enums import IocType

        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        db.add(
            AdvisoryIoc(
                advisory_id=advisory.id,
                ioc_type=IocType.IPV4,
                value="192.0.2.1",
                defanged_value="192[.]0[.]2[.]1",
            )
        )
        db.flush()
        token = _token(db, Scope.ADVISORIES_READ)

        r = client.get(f"/api/v1/advisories/{advisory.id}", headers=_auth(token))
        assert r.status_code == 200
        ioc = r.json()["iocs"][0]
        assert "value" not in ioc
        assert ioc["defanged_value"] == "192[.]0[.]2[.]1"


class TestStatusChange:
    def test_missing_comment_is_422(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/status",
            json={"to_status": "TRIAGED", "comment": "   "},
            headers=_auth(token),
        )
        assert r.status_code == 422
        assert r.json()["type"].endswith("comment-required")

    def test_illegal_transition_is_409_with_allowed_list(
        self, db, client: TestClient, source: Source
    ) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/status",
            json={"to_status": "CLOSED", "comment": "skip ahead"},
            headers=_auth(token),
        )
        assert r.status_code == 409
        body = r.json()
        assert body["type"].endswith("invalid-transition")
        assert "TRIAGED" in body["allowed"]

    def test_valid_transition_updates_status(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/status",
            json={"to_status": "TRIAGED", "comment": "Confirmed relevant."},
            headers=_auth(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["to_status"] == "TRIAGED"
        assert body["from_status"] == "NEW"
        assert body["comment"]["body"] == "Confirmed relevant."


class TestComments:
    def test_add_and_list(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_READ, Scope.ADVISORIES_WRITE)

        r = client.post(
            f"/api/v1/advisories/{advisory.id}/comments",
            json={"body": "a free comment"},
            headers=_auth(token),
        )
        assert r.status_code == 201

        r2 = client.get(f"/api/v1/advisories/{advisory.id}/comments", headers=_auth(token))
        assert r2.status_code == 200
        assert len(r2.json()) == 1

    def test_blank_comment_is_rejected(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/comments",
            json={"body": ""},
            headers=_auth(token),
        )
        assert r.status_code == 422


class TestPatch:
    def test_only_provided_fields_change(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)

        r = client.patch(
            f"/api/v1/advisories/{advisory.id}",
            json={"severity": "CRITICAL"},
            headers=_auth(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["severity"] == "CRITICAL"
        assert body["type"] == "CVE_ADVISORY"  # untouched

    def test_status_is_not_settable_via_patch(self, db, client: TestClient, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        token = _token(db, Scope.ADVISORIES_WRITE)
        r = client.patch(
            f"/api/v1/advisories/{advisory.id}",
            json={"status": "CLOSED"},
            headers=_auth(token),
        )
        assert r.status_code == 200
        assert r.json()["status"] == "NEW"


class TestSources:
    def test_list_and_get(self, db, client: TestClient, source: Source) -> None:
        token = _token(db, Scope.ADVISORIES_READ)
        r = client.get("/api/v1/sources", headers=_auth(token))
        assert r.status_code == 200
        assert any(s["id"] == str(source.id) for s in r.json())

        r2 = client.get(f"/api/v1/sources/{source.id}", headers=_auth(token))
        assert r2.status_code == 200
        assert r2.json()["short_code"] == "TR"

    def test_unknown_source_is_404(self, db, client: TestClient) -> None:
        import uuid

        token = _token(db, Scope.ADVISORIES_READ)
        r = client.get(f"/api/v1/sources/{uuid.uuid4()}", headers=_auth(token))
        assert r.status_code == 404
