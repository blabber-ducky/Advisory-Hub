"""Unit tests for `core.services.inventory` — source CRUD and test-connection.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from advisory_hub.core.models.enums import ActorKind, CredentialAuthType, InventorySourceKind
from advisory_hub.core.models.inventory import IntegrationCredential
from advisory_hub.core.security.crypto import decrypt_credential
from advisory_hub.core.services import inventory as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")


@pytest.fixture(autouse=True)
def _fernet_key(monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "dc.internal.example")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _resolves_to(*ips: str):
    return patch(
        "advisory_hub.core.security.ssrf.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443)) for ip in ips],
    )


class TestCreateSource:
    def test_csv_source_needs_no_config(self, db) -> None:
        source = svc.create_source(
            db, name="DC CSV", kind=InventorySourceKind.CSV_DESKTOP_CENTRAL, actor=ACTOR
        )
        assert source.mode.value == "AGGREGATE"
        assert source.credential_id is None

    def test_duplicate_name_is_rejected(self, db) -> None:
        svc.create_source(db, name="Dup", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR)
        with pytest.raises(svc.DuplicateSourceNameError):
            svc.create_source(db, name="Dup", kind=InventorySourceKind.CSV_AZURE, actor=ACTOR)

    def test_blank_name_is_rejected(self, db) -> None:
        with pytest.raises(svc.InvalidSourceConfigError):
            svc.create_source(db, name="   ", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR)

    def test_api_source_without_base_url_is_rejected(self, db) -> None:
        with pytest.raises(svc.InvalidSourceConfigError, match="base_url"):
            svc.create_source(
                db, name="DC API", kind=InventorySourceKind.API_DESKTOP_CENTRAL, actor=ACTOR
            )

    def test_api_source_with_non_allowlisted_url_is_rejected(self, db) -> None:
        with pytest.raises(svc.InvalidSourceConfigError, match="OUTBOUND_ALLOWLIST"):
            svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://evil.example.com"},
                actor=ACTOR,
            )

    def test_api_source_with_credential_encrypts_it(self, db) -> None:
        with _resolves_to("1.1.1.1"):
            source = svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                credential={"api_key": "s3cr3t-token"},
                credential_auth_type=CredentialAuthType.API_KEY,
                actor=ACTOR,
            )
        assert source.mode.value == "DETAILED"
        assert source.credential_id is not None
        cred = db.get(IntegrationCredential, source.credential_id)
        assert b"s3cr3t-token" not in cred.ciphertext
        assert decrypt_credential(cred.ciphertext) == {"api_key": "s3cr3t-token"}

    def test_credential_without_auth_type_is_rejected(self, db) -> None:
        with _resolves_to("1.1.1.1"), pytest.raises(svc.InvalidSourceConfigError):
            svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                credential={"api_key": "x"},
                actor=ACTOR,
            )


class TestUpdateSource:
    def test_only_provided_fields_change(self, db) -> None:
        source = svc.create_source(
            db, name="CSV Src", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR
        )
        updated = svc.update_source(db, source.id, is_active=False, actor=ACTOR)
        assert updated.is_active is False
        assert updated.name == "CSV Src"

    def test_unknown_source_raises(self, db) -> None:
        with pytest.raises(svc.SourceNotFoundError):
            svc.update_source(db, uuid.uuid4(), is_active=False, actor=ACTOR)

    def test_clearing_credential(self, db) -> None:
        with _resolves_to("1.1.1.1"):
            source = svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                credential={"api_key": "x"},
                credential_auth_type=CredentialAuthType.API_KEY,
                actor=ACTOR,
            )
        assert source.credential_id is not None
        updated = svc.update_source(db, source.id, credential=None, actor=ACTOR)
        assert updated.credential_id is None


class TestListAndGet:
    def test_active_only_filters(self, db) -> None:
        a = svc.create_source(db, name="A", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR)
        svc.create_source(db, name="B", kind=InventorySourceKind.CSV_AZURE, actor=ACTOR)
        svc.update_source(db, a.id, is_active=False, actor=ACTOR)

        all_sources = svc.list_sources(db)
        active_sources = svc.list_sources(db, active_only=True)
        assert len(all_sources) == 2
        assert len(active_sources) == 1
        assert active_sources[0].name == "B"

    def test_get_unknown_returns_none(self, db) -> None:
        assert svc.get_source(db, uuid.uuid4()) is None


class TestConnection:
    def test_csv_source_reports_no_live_connection(self, db) -> None:
        source = svc.create_source(
            db, name="CSV Src", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR
        )
        result = svc.test_connection(db, source.id, actor=ACTOR)
        assert result.ok is False
        assert "upload a file" in result.message

    def test_api_source_without_a_credential_fails_cleanly(self, db) -> None:
        with _resolves_to("1.1.1.1"):
            source = svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                actor=ACTOR,
            )
            result = svc.test_connection(db, source.id, actor=ACTOR)
        assert result.ok is False
        assert "no credential" in result.message.lower()

    def test_api_source_calls_the_real_adapter(self, db) -> None:
        """The adapter is actually invoked now (2c) — not just SSRF-checked."""
        from unittest.mock import patch

        with _resolves_to("1.1.1.1"):
            source = svc.create_source(
                db,
                name="DC API",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                credential={"api_key": "x"},
                credential_auth_type=CredentialAuthType.API_KEY,
                actor=ACTOR,
            )
            with patch(
                "advisory_hub.inventory.adapters.desktop_central.test_connection",
                return_value=(True, "Connected — 3 computer(s) found."),
            ) as mock_test:
                result = svc.test_connection(db, source.id, actor=ACTOR)

        assert result.ok is True
        assert "3 computer" in result.message
        mock_test.assert_called_once()

    def test_unknown_source_raises(self, db) -> None:
        with pytest.raises(svc.SourceNotFoundError):
            svc.test_connection(db, uuid.uuid4(), actor=ACTOR)


class TestSyncHistory:
    def test_history_reflects_create_and_update(self, db) -> None:
        source = svc.create_source(
            db, name="CSV Src", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR
        )
        svc.update_source(db, source.id, is_active=False, actor=ACTOR)
        history = svc.sync_history(db, source.id)
        actions = {h.action for h in history}
        # Order isn't asserted here: both writes land in the same
        # transaction, so `created_at` (postgres `now()` = transaction start)
        # ties — ordering within a tie isn't this function's contract.
        assert actions == {"inventory_source.created", "inventory_source.updated"}


def _api_source(db, *, kind=InventorySourceKind.API_DESKTOP_CENTRAL):
    with _resolves_to("1.1.1.1"):
        return svc.create_source(
            db,
            name=f"API Src {uuid.uuid4()}",
            kind=kind,
            config={"base_url": "https://dc.internal.example"},
            credential={"api_key": "x"},
            credential_auth_type=CredentialAuthType.API_KEY,
            actor=ACTOR,
        )


class TestSyncSource:
    def test_successful_sync_creates_a_detailed_snapshot(self, db) -> None:
        from unittest.mock import patch

        from advisory_hub.inventory.adapters.base import (
            DeviceRecord,
            DeviceSoftwareRecord,
            FetchResult,
        )

        source = _api_source(db)
        fetch_result = FetchResult(
            devices=[
                DeviceRecord(
                    device_identifier="dev-1",
                    hostname="WKS-1",
                    os_name="Windows",
                    os_version="11",
                    software=[
                        DeviceSoftwareRecord(vendor="Google LLC", product="Chrome", version="120.0")
                    ],
                )
            ]
        )
        with (
            _resolves_to("1.1.1.1"),
            patch(
                "advisory_hub.inventory.adapters.desktop_central.fetch", return_value=fetch_result
            ),
        ):
            snapshot = svc.sync_source(db, source.id, actor=ACTOR)

        assert snapshot.is_latest is True
        assert snapshot.mode.value == "DETAILED"
        assert snapshot.device_count == 1
        assert snapshot.software_row_count == 2  # Chrome + the Windows OS row

        db.refresh(source)
        assert source.last_sync_status.value == "OK"
        assert source.last_sync_error is None

    def test_failed_fetch_leaves_the_previous_snapshot_latest(self, db) -> None:
        from unittest.mock import patch

        from advisory_hub.core.models.inventory import InventorySnapshot
        from advisory_hub.inventory.adapters.base import DeviceRecord, FetchResult
        from advisory_hub.inventory.api_client import ApiAdapterError

        source = _api_source(db)
        ok_result = FetchResult(devices=[DeviceRecord("dev-1", "WKS-1", None, None)])
        with (
            _resolves_to("1.1.1.1"),
            patch("advisory_hub.inventory.adapters.desktop_central.fetch", return_value=ok_result),
        ):
            first = svc.sync_source(db, source.id, actor=ACTOR)

        with (
            _resolves_to("1.1.1.1"),
            patch(
                "advisory_hub.inventory.adapters.desktop_central.fetch",
                side_effect=ApiAdapterError("connection refused"),
            ),
            pytest.raises(ApiAdapterError),
        ):
            svc.sync_source(db, source.id, actor=ACTOR)

        db.refresh(first)
        assert first.is_latest is True

        db.refresh(source)
        assert source.last_sync_status.value == "ERROR"
        assert "connection refused" in source.last_sync_error

        latest_count = (
            db.query(InventorySnapshot).filter_by(source_id=source.id, is_latest=True).count()
        )
        assert latest_count == 1

    def test_truncated_fetch_marks_partial_not_ok(self, db) -> None:
        from unittest.mock import patch

        from advisory_hub.inventory.adapters.base import DeviceRecord, FetchResult

        source = _api_source(db)
        result = FetchResult(
            devices=[DeviceRecord("dev-1", "WKS-1", None, None)],
            truncated=True,
            truncated_reason="stopped after 20 pages",
        )
        with (
            _resolves_to("1.1.1.1"),
            patch("advisory_hub.inventory.adapters.desktop_central.fetch", return_value=result),
        ):
            svc.sync_source(db, source.id, actor=ACTOR)

        db.refresh(source)
        assert source.last_sync_status.value == "PARTIAL"
        assert source.last_sync_error == "stopped after 20 pages"

    def test_csv_source_is_rejected(self, db) -> None:
        source = svc.create_source(
            db, name="CSV Src", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR
        )
        with pytest.raises(svc.InvalidSourceConfigError):
            svc.sync_source(db, source.id, actor=ACTOR)

    def test_unknown_source_raises(self, db) -> None:
        with pytest.raises(svc.SourceNotFoundError):
            svc.sync_source(db, uuid.uuid4(), actor=ACTOR)
