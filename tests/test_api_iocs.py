"""Integration tests for `/api/v1/iocs` — VirusTotal check endpoint.

Exercises the real FastAPI app and routing/auth/exception-handling stack,
with `db_session` overridden to the transactional `db` fixture and
`VtClient` monkeypatched to a fake (no live HTTP calls). Requires
TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from advisory_hub.core.models.advisory import Advisory, AdvisoryIoc, Source
from advisory_hub.core.models.enums import AdvisoryStatus, AdvisoryType, IocType
from advisory_hub.core.models.user import ApiToken
from advisory_hub.core.security.tokens import Scope, mint_token
from advisory_hub.enrich.virustotal import VtResult, VtUnauthorizedError

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
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 51003))


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


class _FakeVtClient:
    def __init__(self, result=None, error=None) -> None:
        self._result = result
        self._error = error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def lookup(self, ioc_type, value):
        if self._error is not None:
            raise self._error
        return self._result


def _patch_client(monkeypatch, fake: _FakeVtClient) -> None:
    import advisory_hub.core.services.vt_lookup as vt_lookup_module

    monkeypatch.setattr(vt_lookup_module, "VtClient", lambda **kwargs: fake)


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TRAI", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def advisory(db, source) -> Advisory:
    adv = Advisory(
        source_id=source.id,
        external_ref="TEST-API-IOC-1",
        type=AdvisoryType.THREAT_LANDSCAPE,
        title="Test advisory",
        received_at=datetime(2026, 8, 1, tzinfo=UTC),
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        status=AdvisoryStatus.NEW,
    )
    db.add(adv)
    db.flush()
    return adv


@pytest.fixture
def domain_ioc(db, advisory) -> AdvisoryIoc:
    ioc = AdvisoryIoc(
        advisory_id=advisory.id,
        ioc_type=IocType.DOMAIN,
        value="evil.example.invalid",
        defanged_value="evil[.]example[.]invalid",
    )
    db.add(ioc)
    db.flush()
    return ioc


@pytest.fixture
def email_ioc(db, advisory) -> AdvisoryIoc:
    ioc = AdvisoryIoc(
        advisory_id=advisory.id,
        ioc_type=IocType.EMAIL,
        value="attacker@example.invalid",
        defanged_value="attacker[at]example[.]invalid",
    )
    db.add(ioc)
    db.flush()
    return ioc


class TestAuth:
    def test_no_token_is_401(self, client: TestClient, domain_ioc: AdvisoryIoc) -> None:
        r = client.post(f"/api/v1/iocs/{domain_ioc.id}/check-vt", json={})
        assert r.status_code == 401

    def test_read_scope_cannot_check(self, db, client: TestClient, domain_ioc: AdvisoryIoc) -> None:
        token = _token(db, Scope.ADVISORIES_READ)
        r = client.post(f"/api/v1/iocs/{domain_ioc.id}/check-vt", json={}, headers=_auth(token))
        assert r.status_code == 403


class TestCheckVt:
    def test_successful_check(
        self, db, client: TestClient, domain_ioc: AdvisoryIoc, monkeypatch
    ) -> None:
        result = VtResult(
            malicious_count=10,
            suspicious_count=0,
            harmless_count=60,
            undetected_count=5,
            reputation=-20,
            last_analysis_at=datetime(2026, 8, 1, tzinfo=UTC),
            permalink="https://www.virustotal.com/gui/domain/evil.example.invalid",
        )
        _patch_client(monkeypatch, _FakeVtClient(result=result))
        token = _token(db, Scope.VT_CHECK)
        r = client.post(f"/api/v1/iocs/{domain_ioc.id}/check-vt", json={}, headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "OK"
        assert body["malicious_count"] == 10
        # `permalink` legitimately embeds the value inside VT's own safe
        # report URL — that's fine. What must never happen is the raw
        # value coming back as a standalone field.
        assert body["permalink"] == result.permalink
        assert "value" not in body

    def test_unsupported_ioc_type_is_422_problem_detail(
        self, db, client: TestClient, email_ioc: AdvisoryIoc, monkeypatch
    ) -> None:
        _patch_client(monkeypatch, _FakeVtClient(result=None))
        token = _token(db, Scope.VT_CHECK)
        r = client.post(f"/api/v1/iocs/{email_ioc.id}/check-vt", json={}, headers=_auth(token))
        assert r.status_code == 422
        assert r.headers["content-type"] == "application/problem+json"

    def test_unauthorized_vt_key_is_502_problem_detail(
        self, db, client: TestClient, domain_ioc: AdvisoryIoc, monkeypatch
    ) -> None:
        _patch_client(monkeypatch, _FakeVtClient(error=VtUnauthorizedError("bad key")))
        token = _token(db, Scope.VT_CHECK)
        r = client.post(f"/api/v1/iocs/{domain_ioc.id}/check-vt", json={}, headers=_auth(token))
        assert r.status_code == 502

    def test_unknown_ioc_is_404_problem_detail(self, db, client: TestClient) -> None:
        token = _token(db, Scope.VT_CHECK)
        r = client.post(f"/api/v1/iocs/{uuid.uuid4()}/check-vt", json={}, headers=_auth(token))
        assert r.status_code == 404

    def test_force_flag_is_honoured(
        self, db, client: TestClient, domain_ioc: AdvisoryIoc, monkeypatch
    ) -> None:
        calls = {"n": 0}
        result = VtResult(
            malicious_count=0,
            suspicious_count=0,
            harmless_count=1,
            undetected_count=0,
            reputation=0,
            last_analysis_at=None,
            permalink="https://www.virustotal.com/gui/domain/evil.example.invalid",
        )

        class _CountingFake(_FakeVtClient):
            def lookup(self, ioc_type, value):
                calls["n"] += 1
                return result

        _patch_client(monkeypatch, _CountingFake())
        token = _token(db, Scope.VT_CHECK)
        client.post(f"/api/v1/iocs/{domain_ioc.id}/check-vt", json={}, headers=_auth(token))
        client.post(
            f"/api/v1/iocs/{domain_ioc.id}/check-vt",
            json={"force": True},
            headers=_auth(token),
        )
        assert calls["n"] == 2
