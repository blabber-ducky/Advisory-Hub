"""Unit tests for CSV preview/commit orchestration in `core.services.inventory`.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid

import pytest

from advisory_hub.core.models.enums import (
    ActorKind,
    InventoryItemKind,
    InventorySourceKind,
    SyncStatus,
)
from advisory_hub.core.models.inventory import InventorySnapshot, InventorySoftware
from advisory_hub.core.services import inventory as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")

LANSWEEPER_CSV = (
    b"SoftwareName,SoftwareVersion,Publisher,Count\n"
    b"Google Chrome,120.0.6099.109,Google LLC,41\n"
    b"Apache Log4j,2.14.1,Apache Software Foundation,6\n"
    b"Google Chrome,120.0.6099.109,Google LLC,9\n"  # duplicate key — must aggregate
    b",1.0,Unknown,2\n"  # blank product — row error
)


@pytest.fixture(autouse=True)
def _blob_root(tmp_path, monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("BLOB_ROOT", str(tmp_path / "blobs"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def csv_source(db):
    return svc.create_source(
        db, name="CSV Src", kind=InventorySourceKind.CSV_LANSWEEPER, actor=ACTOR
    )


class TestPreviewCsv:
    def test_auto_maps_and_parses(self, db, csv_source) -> None:
        preview = svc.preview_csv(
            db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="export.csv"
        )
        assert preview.mapping["product"] == "SoftwareName"
        assert preview.total_rows == 4
        assert preview.matched_row_count == 3
        assert len(preview.errors) == 1
        assert preview.errors[0].message == "product is blank"

    def test_stores_the_upload_as_a_blob(self, db, csv_source) -> None:
        preview = svc.preview_csv(
            db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="export.csv"
        )
        assert preview.blob_id is not None

    def test_non_csv_source_is_rejected(self, db, monkeypatch) -> None:
        from unittest.mock import patch

        from advisory_hub.config import get_settings

        monkeypatch.setenv("OUTBOUND_ALLOWLIST", "dc.internal.example")
        get_settings.cache_clear()
        with patch(
            "advisory_hub.core.security.ssrf.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.1.1.1", 443))],
        ):
            api_source = svc.create_source(
                db,
                name="API Src",
                kind=InventorySourceKind.API_DESKTOP_CENTRAL,
                config={"base_url": "https://dc.internal.example"},
                actor=ACTOR,
            )
        with pytest.raises(svc.InvalidSourceConfigError, match="not a CSV source"):
            svc.preview_csv(db, api_source.id, file_bytes=LANSWEEPER_CSV, filename="x.csv")

    def test_unknown_source_raises(self, db) -> None:
        with pytest.raises(svc.SourceNotFoundError):
            svc.preview_csv(db, uuid.uuid4(), file_bytes=LANSWEEPER_CSV, filename="x.csv")

    def test_oversized_file_is_rejected(self, db, csv_source, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("CSV_MAX_BYTES", "10")
        get_settings.cache_clear()
        try:
            with pytest.raises(svc.CsvTooLargeError):
                svc.preview_csv(db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="export.csv")
        finally:
            monkeypatch.delenv("CSV_MAX_BYTES", raising=False)
            get_settings.cache_clear()

    def test_reuses_a_previously_saved_mapping(self, db, csv_source) -> None:
        custom_mapping = {
            "product": "SoftwareName",
            "vendor": None,
            "version": "SoftwareVersion",
            "device_count": None,
        }
        svc.update_source(db, csv_source.id, config={"column_mapping": custom_mapping}, actor=ACTOR)
        preview = svc.preview_csv(
            db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="export.csv"
        )
        assert preview.mapping == custom_mapping


class TestCommitCsvSnapshot:
    def _preview_and_commit(self, db, source, mapping=None):
        preview = svc.preview_csv(db, source.id, file_bytes=LANSWEEPER_CSV, filename="export.csv")
        return svc.commit_csv_snapshot(
            db,
            source.id,
            blob_id=preview.blob_id,
            mapping=mapping or preview.mapping,
            actor=ACTOR,
        )

    def test_creates_a_snapshot_marked_latest(self, db, csv_source) -> None:
        snapshot = self._preview_and_commit(db, csv_source)
        assert snapshot.is_latest is True
        assert snapshot.raw_file_blob_id is not None

    def test_aggregates_duplicate_product_version_rows(self, db, csv_source) -> None:
        snapshot = self._preview_and_commit(db, csv_source)
        rows = db.query(InventorySoftware).filter_by(snapshot_id=snapshot.id).all()
        chrome = next(r for r in rows if r.product_raw == "Google Chrome")
        assert chrome.device_count == 50  # 41 + 9, aggregated
        assert len(rows) == 2  # Chrome + Log4j; blank-product row excluded

    def test_version_normalisation_is_populated(self, db, csv_source) -> None:
        snapshot = self._preview_and_commit(db, csv_source)
        rows = db.query(InventorySoftware).filter_by(snapshot_id=snapshot.id).all()
        chrome = next(r for r in rows if r.product_raw == "Google Chrome")
        assert chrome.version_normalized == "120.0.6099.109"
        assert chrome.version_parts == [120, 0, 6099, 109]
        assert chrome.kind == InventoryItemKind.SOFTWARE

    def test_second_commit_demotes_the_first_snapshot(self, db, csv_source) -> None:
        first = self._preview_and_commit(db, csv_source)
        second = self._preview_and_commit(db, csv_source)

        db.refresh(first)
        assert first.is_latest is False
        assert second.is_latest is True

        latest_count = (
            db.query(InventorySnapshot).filter_by(source_id=csv_source.id, is_latest=True).count()
        )
        assert latest_count == 1

    def test_updates_source_sync_status_to_partial_on_row_errors(self, db, csv_source) -> None:
        self._preview_and_commit(db, csv_source)
        db.refresh(csv_source)
        assert csv_source.last_sync_status == SyncStatus.PARTIAL
        assert csv_source.last_sync_error is not None
        assert csv_source.last_sync_at is not None

    def test_updates_source_sync_status_to_ok_with_no_errors(self, db, csv_source) -> None:
        clean_csv = b"SoftwareName,SoftwareVersion,Publisher,Count\nGoogle Chrome,1.0,Google,5\n"
        preview = svc.preview_csv(db, csv_source.id, file_bytes=clean_csv, filename="x.csv")
        svc.commit_csv_snapshot(
            db, csv_source.id, blob_id=preview.blob_id, mapping=preview.mapping, actor=ACTOR
        )
        db.refresh(csv_source)
        assert csv_source.last_sync_status == SyncStatus.OK
        assert csv_source.last_sync_error is None

    def test_persists_the_mapping_onto_the_source(self, db, csv_source) -> None:
        preview = svc.preview_csv(db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="x.csv")
        svc.commit_csv_snapshot(
            db, csv_source.id, blob_id=preview.blob_id, mapping=preview.mapping, actor=ACTOR
        )
        db.refresh(csv_source)
        assert csv_source.config["column_mapping"] == preview.mapping

    def test_unknown_blob_raises(self, db, csv_source) -> None:
        with pytest.raises(svc.CsvBlobNotFoundError):
            svc.commit_csv_snapshot(
                db,
                csv_source.id,
                blob_id=uuid.uuid4(),
                mapping={"product": "SoftwareName"},
                actor=ACTOR,
            )

    def test_unmapped_product_column_is_rejected(self, db, csv_source) -> None:
        preview = svc.preview_csv(db, csv_source.id, file_bytes=LANSWEEPER_CSV, filename="x.csv")
        with pytest.raises(svc.InvalidSourceConfigError):
            svc.commit_csv_snapshot(
                db,
                csv_source.id,
                blob_id=preview.blob_id,
                mapping={"product": None},
                actor=ACTOR,
            )

    def test_all_rows_failing_is_rejected(self, db, csv_source) -> None:
        all_bad = b"SoftwareName\n\n\n"
        preview = svc.preview_csv(db, csv_source.id, file_bytes=all_bad, filename="x.csv")
        with pytest.raises(svc.InvalidSourceConfigError, match="No valid rows"):
            svc.commit_csv_snapshot(
                db,
                csv_source.id,
                blob_id=preview.blob_id,
                mapping=preview.mapping,
                actor=ACTOR,
            )
