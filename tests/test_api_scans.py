"""Integration tests for `/api/v1` scan endpoints — Phase 2e.

Exercises the real FastAPI app and routing/auth/exception-handling stack,
with `db_session` overridden to the transactional `db` fixture. Requires
TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from advisory_hub.core.models.advisory import Advisory, AdvisoryCve, CveCpe, Source
from advisory_hub.core.models.enums import (
    AdvisoryStatus,
    AdvisoryType,
    EnrichmentStatus,
    InventoryItemKind,
    InventoryMode,
    InventorySourceKind,
)
from advisory_hub.core.models.inventory import InventorySnapshot, InventorySoftware, InventorySource
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
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 51002))


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


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TRSC", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def advisory(db, source) -> Advisory:
    received = datetime(2026, 8, 1, tzinfo=UTC)
    adv = Advisory(
        source_id=source.id,
        external_ref="TEST-API-SCAN-1",
        type=AdvisoryType.CVE_ADVISORY,
        title="Test Log4j advisory",
        received_at=received,
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        status=AdvisoryStatus.NEW,
    )
    db.add(adv)
    db.flush()
    db.add(
        AdvisoryCve(
            advisory_id=adv.id,
            cve_id="CVE-2021-44228",
            found_in=["PDF"],
            enrichment_status=EnrichmentStatus.OK,
        )
    )
    db.add(
        CveCpe(
            cve_id="CVE-2021-44228",
            cpe_uri="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            vendor="apache",
            product="log4j",
            version_start="2.0",
            version_start_inclusive=True,
            version_end="2.15.0",
            version_end_inclusive=False,
            vulnerable=True,
        )
    )
    db.flush()
    return adv


@pytest.fixture
def snapshot(db) -> InventorySnapshot:
    inv_source = InventorySource(
        name="Test API Scan Source",
        kind=InventorySourceKind.CSV_LANSWEEPER,
        mode=InventoryMode.AGGREGATE,
        config={},
        is_active=True,
    )
    db.add(inv_source)
    db.flush()

    snap = InventorySnapshot(
        source_id=inv_source.id,
        taken_at=datetime.now(UTC),
        mode=InventoryMode.AGGREGATE,
        software_row_count=1,
        is_latest=True,
    )
    db.add(snap)
    db.flush()
    db.add(
        InventorySoftware(
            snapshot_id=snap.id,
            vendor_raw="Apache",
            product_raw="Log4j",
            vendor="apache",
            product="log4j",
            version_raw="2.14.1",
            device_count=6,
            kind=InventoryItemKind.SOFTWARE,
        )
    )
    db.flush()
    return snap


class TestAuth:
    def test_no_token_is_401(self, client: TestClient, advisory: Advisory) -> None:
        r = client.post(f"/api/v1/advisories/{advisory.id}/scan", json={})
        assert r.status_code == 401

    def test_read_scope_cannot_run(self, db, client: TestClient, advisory: Advisory) -> None:
        token = _token(db, Scope.ADVISORIES_READ)
        r = client.post(f"/api/v1/advisories/{advisory.id}/scan", json={}, headers=_auth(token))
        assert r.status_code == 403


class TestTriggerScan:
    def test_default_snapshot_ids_scans_all_active_latest(
        self, db, client: TestClient, advisory: Advisory, snapshot: InventorySnapshot
    ) -> None:
        token = _token(db, Scope.SCAN_RUN)
        r = client.post(f"/api/v1/advisories/{advisory.id}/scan", json={}, headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "COMPLETE"
        assert body["match_count"] == 1
        assert body["matches"][0]["confidence"] == "CONFIRMED"
        assert body["matches"][0]["cve_id"] == "CVE-2021-44228"
        assert body["coverage_gaps"] == []

    def test_explicit_snapshot_ids_are_honoured(
        self, db, client: TestClient, advisory: Advisory, snapshot: InventorySnapshot
    ) -> None:
        token = _token(db, Scope.SCAN_RUN)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/scan",
            json={"snapshot_ids": [str(snapshot.id)]},
            headers=_auth(token),
        )
        assert r.status_code == 200
        assert r.json()["snapshot_ids"] == [str(snapshot.id)]

    def test_unknown_advisory_is_404_problem_detail(self, db, client: TestClient) -> None:
        token = _token(db, Scope.SCAN_RUN)
        r = client.post(f"/api/v1/advisories/{uuid.uuid4()}/scan", json={}, headers=_auth(token))
        assert r.status_code == 404
        assert r.headers["content-type"] == "application/problem+json"

    def test_unknown_snapshot_is_404_problem_detail(
        self, db, client: TestClient, advisory: Advisory
    ) -> None:
        token = _token(db, Scope.SCAN_RUN)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/scan",
            json={"snapshot_ids": [str(uuid.uuid4())]},
            headers=_auth(token),
        )
        assert r.status_code == 404

    def test_no_inventory_match_yields_coverage_gap(
        self, db, client: TestClient, advisory: Advisory
    ) -> None:
        # No snapshot fixture used — nothing scanned reports log4j at all.
        inv_source = InventorySource(
            name="Empty Source",
            kind=InventorySourceKind.CSV_LANSWEEPER,
            mode=InventoryMode.AGGREGATE,
            config={},
            is_active=True,
        )
        db.add(inv_source)
        db.flush()
        snap = InventorySnapshot(
            source_id=inv_source.id,
            taken_at=datetime.now(UTC),
            mode=InventoryMode.AGGREGATE,
            software_row_count=0,
            is_latest=True,
        )
        db.add(snap)
        db.flush()

        token = _token(db, Scope.SCAN_RUN)
        r = client.post(
            f"/api/v1/advisories/{advisory.id}/scan",
            json={"snapshot_ids": [str(snap.id)]},
            headers=_auth(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["match_count"] == 0
        assert body["coverage_gaps"] == [{"vendor": "apache", "product": "log4j"}]


class TestGetAndHistory:
    def test_get_scan_run(
        self, db, client: TestClient, advisory: Advisory, snapshot: InventorySnapshot
    ) -> None:
        token = _token(db, Scope.SCAN_RUN)
        created = client.post(
            f"/api/v1/advisories/{advisory.id}/scan", json={}, headers=_auth(token)
        ).json()

        r = client.get(f"/api/v1/scans/{created['id']}", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["id"] == created["id"]

    def test_get_unknown_scan_run_is_404(self, db, client: TestClient) -> None:
        token = _token(db, Scope.SCAN_RUN)
        r = client.get(f"/api/v1/scans/{uuid.uuid4()}", headers=_auth(token))
        assert r.status_code == 404

    def test_history_lists_newest_first(
        self, db, client: TestClient, advisory: Advisory, snapshot: InventorySnapshot
    ) -> None:
        token = _token(db, Scope.SCAN_RUN)
        first = client.post(
            f"/api/v1/advisories/{advisory.id}/scan", json={}, headers=_auth(token)
        ).json()
        second = client.post(
            f"/api/v1/advisories/{advisory.id}/scan", json={}, headers=_auth(token)
        ).json()

        r = client.get(f"/api/v1/advisories/{advisory.id}/scans", headers=_auth(token))
        assert r.status_code == 200
        ids = [row["id"] for row in r.json()]
        assert ids == [second["id"], first["id"]]
