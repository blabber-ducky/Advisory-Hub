"""Integration tests for `/api/v1/inventory/sources`.

Exercises the real FastAPI app and routing/auth/exception-handling stack,
with `db_session` overridden to the transactional `db` fixture. Requires
TEST_DATABASE_URL.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from advisory_hub.core.models.user import ApiToken
from advisory_hub.core.security.tokens import Scope, mint_token

pytestmark = pytest.mark.integration


@pytest.fixture
def client(db, tmp_path, monkeypatch) -> TestClient:
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "dc.internal.example")

    from advisory_hub.config import get_settings

    get_settings.cache_clear()

    from advisory_hub.api.deps import db_session
    from advisory_hub.main import create_app

    def _override_db_session():
        yield db

    app = create_app()
    app.dependency_overrides[db_session] = _override_db_session
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 51001))


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


def _resolves_to(*ips: str):
    return patch(
        "advisory_hub.core.security.ssrf.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443)) for ip in ips],
    )


class TestAuth:
    def test_no_token_is_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/inventory/sources")
        assert r.status_code == 401

    def test_read_token_cannot_create(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_READ)
        r = client.post(
            "/api/v1/inventory/sources",
            json={"name": "X", "kind": "CSV_LANSWEEPER"},
            headers=_auth(token),
        )
        assert r.status_code == 403


class TestCreateAndList:
    def test_create_csv_source(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_READ, Scope.INVENTORY_WRITE)
        r = client.post(
            "/api/v1/inventory/sources",
            json={"name": "DC CSV", "kind": "CSV_DESKTOP_CENTRAL", "config": {}},
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["mode"] == "AGGREGATE"
        assert body["has_credential"] is False

        r2 = client.get("/api/v1/inventory/sources", headers=_auth(token))
        assert r2.status_code == 200
        assert len(r2.json()) == 1

    def test_duplicate_name_is_409(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        payload = {"name": "Dup", "kind": "CSV_LANSWEEPER", "config": {}}
        client.post("/api/v1/inventory/sources", json=payload, headers=_auth(token))
        r = client.post("/api/v1/inventory/sources", json=payload, headers=_auth(token))
        assert r.status_code == 409
        assert r.json()["type"].endswith("duplicate-source-name")

    def test_api_source_missing_base_url_is_422(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        r = client.post(
            "/api/v1/inventory/sources",
            json={"name": "DC API", "kind": "API_DESKTOP_CENTRAL", "config": {}},
            headers=_auth(token),
        )
        assert r.status_code == 422
        assert r.json()["type"].endswith("invalid-source-config")

    def test_credential_never_appears_in_the_response(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        with _resolves_to("1.1.1.1"):
            r = client.post(
                "/api/v1/inventory/sources",
                json={
                    "name": "DC API",
                    "kind": "API_DESKTOP_CENTRAL",
                    "config": {"base_url": "https://dc.internal.example"},
                    "credential": {"api_key": "super-secret"},
                    "credential_auth_type": "API_KEY",
                },
                headers=_auth(token),
            )
        assert r.status_code == 201
        assert "super-secret" not in r.text
        assert "credential" not in r.json()
        assert r.json()["has_credential"] is True


class TestGetPatchTest:
    def test_unknown_source_is_404(self, db, client: TestClient) -> None:
        import uuid

        token = _token(db, Scope.INVENTORY_READ)
        r = client.get(f"/api/v1/inventory/sources/{uuid.uuid4()}", headers=_auth(token))
        assert r.status_code == 404
        assert r.json()["type"].endswith("source-not-found")

    def test_patch_deactivates(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_READ, Scope.INVENTORY_WRITE)
        created = client.post(
            "/api/v1/inventory/sources",
            json={"name": "DC CSV", "kind": "CSV_DESKTOP_CENTRAL", "config": {}},
            headers=_auth(token),
        ).json()

        r = client.patch(
            f"/api/v1/inventory/sources/{created['id']}",
            json={"is_active": False},
            headers=_auth(token),
        )
        assert r.status_code == 200
        assert r.json()["is_active"] is False

    def test_test_connection_on_csv_source(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_READ, Scope.INVENTORY_WRITE)
        created = client.post(
            "/api/v1/inventory/sources",
            json={"name": "DC CSV", "kind": "CSV_DESKTOP_CENTRAL", "config": {}},
            headers=_auth(token),
        ).json()

        r = client.post(f"/api/v1/inventory/sources/{created['id']}/test", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["ok"] is False
        assert "upload a file" in r.json()["message"]

    def test_history_lists_events(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_READ, Scope.INVENTORY_WRITE)
        created = client.post(
            "/api/v1/inventory/sources",
            json={"name": "DC CSV", "kind": "CSV_DESKTOP_CENTRAL", "config": {}},
            headers=_auth(token),
        ).json()

        r = client.get(f"/api/v1/inventory/sources/{created['id']}/history", headers=_auth(token))
        assert r.status_code == 200
        assert any(h["action"] == "inventory_source.created" for h in r.json())


LANSWEEPER_CSV = (
    b"SoftwareName,SoftwareVersion,Publisher,Count\n"
    b"Google Chrome,120.0.6099.109,Google LLC,41\n"
    b"Apache Log4j,2.14.1,Apache Software Foundation,6\n"
    b",1.0,Unknown,2\n"
)


class TestCsvPreviewAndCommit:
    def _create_csv_source(self, client: TestClient, token: str) -> str:
        r = client.post(
            "/api/v1/inventory/sources",
            json={"name": "CSV Src", "kind": "CSV_LANSWEEPER", "config": {}},
            headers=_auth(token),
        )
        return str(r.json()["id"])

    def test_preview_auto_maps_and_reports_errors(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_csv_source(client, token)

        r = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/preview",
            files={"file": ("export.csv", LANSWEEPER_CSV, "text/csv")},
            headers=_auth(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["mapping"]["product"] == "SoftwareName"
        assert body["total_rows"] == 3
        assert body["matched_row_count"] == 2
        assert len(body["errors"]) == 1
        assert body["errors"][0]["message"] == "product is blank"

    def test_read_token_cannot_preview(self, db, client: TestClient) -> None:
        write_token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_csv_source(client, write_token)
        read_token = _token(db, Scope.INVENTORY_READ)

        r = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/preview",
            files={"file": ("export.csv", LANSWEEPER_CSV, "text/csv")},
            headers=_auth(read_token),
        )
        assert r.status_code == 403

    def test_preview_then_commit_creates_a_latest_snapshot(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_csv_source(client, token)

        preview = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/preview",
            files={"file": ("export.csv", LANSWEEPER_CSV, "text/csv")},
            headers=_auth(token),
        ).json()

        r = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/commit",
            json={"blob_id": preview["blob_id"], "mapping": preview["mapping"]},
            headers=_auth(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["is_latest"] is True
        assert body["software_row_count"] == 2
        assert body["source_id"] == source_id

    def test_commit_with_unknown_blob_is_404(self, db, client: TestClient) -> None:
        import uuid

        token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_csv_source(client, token)

        r = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/commit",
            json={"blob_id": str(uuid.uuid4()), "mapping": {"product": "SoftwareName"}},
            headers=_auth(token),
        )
        assert r.status_code == 404
        assert r.json()["type"].endswith("csv-blob-not-found")

    def test_commit_with_unmapped_product_is_422(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_csv_source(client, token)

        preview = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/preview",
            files={"file": ("export.csv", LANSWEEPER_CSV, "text/csv")},
            headers=_auth(token),
        ).json()

        r = client.post(
            f"/api/v1/inventory/sources/{source_id}/csv/commit",
            json={"blob_id": preview["blob_id"], "mapping": {"product": None}},
            headers=_auth(token),
        )
        assert r.status_code == 422
        assert r.json()["type"].endswith("invalid-source-config")


class TestApiSync:
    def _create_api_source(self, client: TestClient, token: str) -> str:
        with _resolves_to("1.1.1.1"):
            r = client.post(
                "/api/v1/inventory/sources",
                json={
                    "name": "API Sync Test",
                    "kind": "API_DESKTOP_CENTRAL",
                    "config": {"base_url": "https://dc.internal.example"},
                    "credential": {"api_key": "x"},
                    "credential_auth_type": "API_KEY",
                },
                headers=_auth(token),
            )
        return str(r.json()["id"])

    def test_successful_sync_returns_the_new_snapshot(self, db, client: TestClient) -> None:
        from advisory_hub.inventory.adapters.base import DeviceRecord, FetchResult

        token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_api_source(client, token)

        result = FetchResult(devices=[DeviceRecord("dev-1", "WKS-1", "Windows", "11")])
        with (
            _resolves_to("1.1.1.1"),
            patch("advisory_hub.inventory.adapters.desktop_central.fetch", return_value=result),
        ):
            r = client.post(f"/api/v1/inventory/sources/{source_id}/sync", headers=_auth(token))

        assert r.status_code == 201
        body = r.json()
        assert body["is_latest"] is True
        assert body["device_count"] == 1
        assert body["mode"] == "DETAILED"

    def test_failed_sync_is_502_and_still_records_the_error(self, db, client: TestClient) -> None:
        from advisory_hub.inventory.api_client import ApiAdapterError

        token = _token(db, Scope.INVENTORY_READ, Scope.INVENTORY_WRITE)
        source_id = self._create_api_source(client, token)

        with (
            _resolves_to("1.1.1.1"),
            patch(
                "advisory_hub.inventory.adapters.desktop_central.fetch",
                side_effect=ApiAdapterError("unreachable"),
            ),
        ):
            r = client.post(f"/api/v1/inventory/sources/{source_id}/sync", headers=_auth(token))

        assert r.status_code == 502
        assert r.json()["type"].endswith("upstream-sync-failed")

        r2 = client.get(f"/api/v1/inventory/sources/{source_id}", headers=_auth(token))
        assert r2.json()["last_sync_status"] == "ERROR"
        assert "unreachable" in r2.json()["last_sync_error"]

    def test_read_token_cannot_sync(self, db, client: TestClient) -> None:
        write_token = _token(db, Scope.INVENTORY_WRITE)
        source_id = self._create_api_source(client, write_token)
        read_token = _token(db, Scope.INVENTORY_READ)

        r = client.post(f"/api/v1/inventory/sources/{source_id}/sync", headers=_auth(read_token))
        assert r.status_code == 403

    def test_csv_source_cannot_be_synced(self, db, client: TestClient) -> None:
        token = _token(db, Scope.INVENTORY_WRITE)
        created = client.post(
            "/api/v1/inventory/sources",
            json={"name": "CSV Src", "kind": "CSV_LANSWEEPER", "config": {}},
            headers=_auth(token),
        ).json()

        r = client.post(f"/api/v1/inventory/sources/{created['id']}/sync", headers=_auth(token))
        assert r.status_code == 422
        assert r.json()["type"].endswith("invalid-source-config")
