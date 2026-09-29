"""`core.services.scan.run_scan()` — end-to-end persistence.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from advisory_hub.core.models.advisory import Advisory, AdvisoryCve, AdvisoryProduct, CveCpe, Source
from advisory_hub.core.models.enums import (
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    ClaimSource,
    EnrichmentStatus,
    InventoryItemKind,
    InventoryMode,
    InventorySourceKind,
    MatchConfidence,
    ScanStatus,
    Severity,
)
from advisory_hub.core.models.inventory import InventorySnapshot, InventorySoftware, InventorySource
from advisory_hub.core.services import scan as svc
from advisory_hub.core.services.audit import Actor
from advisory_hub.core.services.vendor_alias import seed_vendor_aliases

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TR2D", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def advisory(db, source) -> Advisory:
    received = datetime(2026, 8, 1, tzinfo=UTC)
    adv = Advisory(
        source_id=source.id,
        external_ref="TEST-SCAN-1",
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
    # A non-vulnerable context row — must never turn into an AffectedSpec.
    db.add(
        CveCpe(
            cve_id="CVE-2021-44228",
            cpe_uri="cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
            vendor="apache",
            product="log4j",
            version_start=None,
            version_start_inclusive=False,
            version_end=None,
            version_end_inclusive=False,
            vulnerable=False,
        )
    )
    db.flush()
    return adv


def _snapshot(db, *, rows: list[tuple[str, str, str, int]]) -> InventorySnapshot:
    inv_source = InventorySource(
        name=f"Test Inventory Src {uuid.uuid4()}",
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
        software_row_count=len(rows),
        is_latest=True,
    )
    db.add(snap)
    db.flush()
    for vendor, product, version, count in rows:
        db.add(
            InventorySoftware(
                snapshot_id=snap.id,
                vendor_raw=vendor,
                product_raw=product,
                vendor=vendor.lower(),
                product=product.lower(),
                version_raw=version,
                device_count=count,
                kind=InventoryItemKind.SOFTWARE,
            )
        )
    db.flush()
    return snap


class TestRunScan:
    def test_confirmed_match_is_persisted(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 6)])
        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        assert result.status == ScanStatus.COMPLETE
        assert result.match_count == 1
        assert result.affected_device_count == 6
        assert result.matches[0].confidence == MatchConfidence.CONFIRMED
        assert result.matches[0].cve_id == "CVE-2021-44228"

    def test_non_vulnerable_cpe_rows_never_become_specs(self, db, advisory) -> None:
        # If the non-vulnerable CPE row leaked into matching, this exact
        # version (2.15.0, the patched release) would falsely match.
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.15.0", 1)])
        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert result.match_count == 0

    def test_no_matching_inventory_yields_a_clean_empty_scan(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("microsoft", "Excel", "16.0", 10)])
        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert result.status == ScanStatus.COMPLETE
        assert result.match_count == 0
        assert result.affected_device_count == 0

    def test_vendor_alias_downgrades_confidence_to_likely(self, db, advisory) -> None:
        seed_vendor_aliases(db)
        snap = _snapshot(db, rows=[("Apache Software Foundation", "Log4j", "2.14.1", 2)])
        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert result.match_count == 1
        assert result.matches[0].confidence == MatchConfidence.LIKELY

    def test_spans_multiple_snapshots(self, db, advisory) -> None:
        snap1 = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 3)])
        snap2 = _snapshot(db, rows=[("apache", "Log4j", "2.10.0", 5)])
        result = svc.run_scan(db, advisory.id, [snap1.id, snap2.id], actor=ACTOR)
        assert result.match_count == 2
        assert result.affected_device_count == 8
        assert {m.snapshot_id for m in result.matches} == {snap1.id, snap2.id}

    def test_unknown_advisory_raises(self, db) -> None:
        with pytest.raises(svc.AdvisoryNotFoundError):
            svc.run_scan(db, uuid.uuid4(), [], actor=ACTOR)

    def test_unknown_snapshot_raises(self, db, advisory) -> None:
        with pytest.raises(svc.SnapshotNotFoundError):
            svc.run_scan(db, advisory.id, [uuid.uuid4()], actor=ACTOR)

    def test_scan_run_records_which_snapshots_were_scanned(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 1)])
        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert result.snapshot_ids == [snap.id]
        assert result.started_at is not None
        assert result.finished_at is not None


class TestTextDerivedMatching:
    """`AdvisoryProduct.parsed_range` specs — D-032. Distinct from NVD CPE:
    no CVE attribution, always capped at POSSIBLE confidence."""

    def test_text_derived_match_is_found_and_capped_at_possible(self, db, advisory) -> None:
        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor="examplevendor",
                product="Example Widget",
                version_expression="< 3.0.0",
                parsed_range={
                    "min_version": None,
                    "min_inclusive": True,
                    "max_version": "3.0.0",
                    "max_inclusive": False,
                    "exact_version": None,
                },
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
        db.flush()
        snap = _snapshot(db, rows=[("examplevendor", "Example Widget", "2.5.0", 4)])

        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        assert result.match_count == 1
        match = result.matches[0]
        assert match.confidence == MatchConfidence.POSSIBLE
        assert match.cve_id is None
        assert "not NVD-verified" in match.rationale

    def test_out_of_range_text_derived_claim_does_not_match(self, db, advisory) -> None:
        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor="examplevendor",
                product="Example Widget",
                version_expression="< 3.0.0",
                parsed_range={
                    "min_version": None,
                    "min_inclusive": True,
                    "max_version": "3.0.0",
                    "max_inclusive": False,
                    "exact_version": None,
                },
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
        db.flush()
        snap = _snapshot(db, rows=[("examplevendor", "Example Widget", "3.5.0", 4)])

        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        assert result.match_count == 0

    def test_unparsed_claim_contributes_no_spec(self, db, advisory) -> None:
        """A product claim whose text didn't parse cleanly (`parsed_range`
        is `None`) must never silently become an unbounded "any version"
        match."""
        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor="examplevendor",
                product="Example Widget",
                version_expression="7.0, 7.2, 7.4 (multiple discrete releases)",
                parsed_range=None,
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
        db.flush()
        snap = _snapshot(db, rows=[("examplevendor", "Example Widget", "1.0.0", 4)])

        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        assert result.match_count == 0

    def test_nvd_and_text_derived_matches_coexist_in_one_scan(self, db, advisory) -> None:
        """`advisory` (from the module fixture) already carries a real NVD
        CPE spec for apache:log4j — adding a text-derived claim for a
        second, unrelated product must not disturb that."""
        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor="examplevendor",
                product="Example Widget",
                version_expression="< 3.0.0",
                parsed_range={
                    "min_version": None,
                    "min_inclusive": True,
                    "max_version": "3.0.0",
                    "max_inclusive": False,
                    "exact_version": None,
                },
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
        db.flush()
        snap = _snapshot(
            db,
            rows=[
                ("apache", "Log4j", "2.14.1", 6),
                ("examplevendor", "Example Widget", "2.5.0", 4),
            ],
        )

        result = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        assert result.match_count == 2
        confidences = {m.confidence for m in result.matches}
        assert MatchConfidence.CONFIRMED in confidences
        assert MatchConfidence.POSSIBLE in confidences


class TestScanHistory:
    def test_newest_first(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 1)])
        first = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        second = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        history = svc.scan_history(db, advisory.id)
        assert [run.id for run in history] == [second.id, first.id]

    def test_empty_for_unscanned_advisory(self, db, advisory) -> None:
        assert svc.scan_history(db, advisory.id) == []


class TestGetScanRun:
    def test_returns_the_run(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 1)])
        run = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert svc.get_scan_run(db, run.id).id == run.id

    def test_unknown_id_returns_none(self, db) -> None:
        assert svc.get_scan_run(db, uuid.uuid4()) is None


class TestCoverageGaps:
    def test_product_with_no_inventory_candidate_at_all_is_a_gap(self, db, advisory) -> None:
        # A different, unrelated product in inventory — log4j is never seen.
        snap = _snapshot(db, rows=[("microsoft", "Excel", "16.0", 10)])
        run = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert svc.coverage_gaps(db, run) == [("apache", "log4j")]

    def test_product_present_but_out_of_range_is_not_a_gap(self, db, advisory) -> None:
        # log4j is present (just not in the vulnerable range) — a genuine
        # "checked, not affected" result, not a coverage gap.
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.20.0", 1)])
        run = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert svc.coverage_gaps(db, run) == []

    def test_confirmed_match_is_not_a_gap(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 1)])
        run = svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)
        assert svc.coverage_gaps(db, run) == []


class TestParsedRangeSqlNull:
    """Regression: `AdvisoryProduct.parsed_range` must store a Python
    `None` as a true SQL `NULL`, not a literal JSON `null` — see D-033.
    Found by inspecting the real ah-test corpus at the SQL level after a
    live reparse; the ORM read path (`row.parsed_range is None`) silently
    masks the bug, so this test checks the raw column value instead."""

    def test_none_is_stored_as_true_sql_null_not_json_null(self, db, advisory) -> None:
        from sqlalchemy import text

        db.add(
            AdvisoryProduct(
                advisory_id=advisory.id,
                vendor="examplevendor",
                product="Unparsed Product",
                version_expression="7.0, 7.2, 7.4 (discrete list, won't parse)",
                parsed_range=None,
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
        db.flush()

        is_null = db.execute(
            text("SELECT parsed_range IS NULL FROM advisory_product WHERE advisory_id = :aid"),
            {"aid": str(advisory.id)},
        ).scalar()
        assert is_null is True


class TestListAffectedSoftware:
    def test_no_scans_yields_no_rows(self, db) -> None:
        assert svc.list_affected_software(db) == []

    def test_row_reflects_the_latest_scan_only(self, db, advisory) -> None:
        snap1 = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 3)])
        svc.run_scan(db, advisory.id, [snap1.id], actor=ACTOR)
        snap2 = _snapshot(db, rows=[("apache", "Log4j", "2.10.0", 5)])
        second_run = svc.run_scan(db, advisory.id, [snap2.id], actor=ACTOR)

        rows = svc.list_affected_software(db)
        assert len(rows) == 1
        assert rows[0].scan_run_id == second_run.id
        assert rows[0].device_count == 5
        assert rows[0].product == "Log4j"
        assert rows[0].advisory_id == advisory.id

    def test_advisory_never_scanned_contributes_nothing(self, db, advisory) -> None:
        assert svc.list_affected_software(db) == []

    def test_sorted_by_severity_then_product(self, db, source) -> None:
        received = datetime(2026, 8, 2, tzinfo=UTC)
        low_adv = Advisory(
            source_id=source.id,
            external_ref="TEST-SCAN-LOW",
            type=AdvisoryType.CVE_ADVISORY,
            title="Low severity advisory",
            received_at=received,
            dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
            parser_version="1",
            status=AdvisoryStatus.NEW,
            severity=Severity.LOW,
        )
        high_adv = Advisory(
            source_id=source.id,
            external_ref="TEST-SCAN-HIGH",
            type=AdvisoryType.CVE_ADVISORY,
            title="High severity advisory",
            received_at=received,
            dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
            parser_version="1",
            status=AdvisoryStatus.NEW,
            severity=Severity.HIGH,
        )
        db.add_all([low_adv, high_adv])
        db.flush()
        for adv in (low_adv, high_adv):
            db.add(
                AdvisoryCve(
                    advisory_id=adv.id,
                    cve_id=f"CVE-2026-{adv.external_ref[-4:]}",
                    found_in=["PDF"],
                    enrichment_status=EnrichmentStatus.OK,
                )
            )
            db.add(
                CveCpe(
                    cve_id=f"CVE-2026-{adv.external_ref[-4:]}",
                    cpe_uri="cpe:2.3:a:vendorx:widget:*:*:*:*:*:*:*:*",
                    vendor="vendorx",
                    product="widget",
                    version_start=None,
                    version_start_inclusive=False,
                    version_end="9.0",
                    version_end_inclusive=False,
                    vulnerable=True,
                )
            )
        db.flush()

        snap = _snapshot(db, rows=[("vendorx", "Widget", "1.0", 1)])
        svc.run_scan(db, low_adv.id, [snap.id], actor=ACTOR)
        svc.run_scan(db, high_adv.id, [snap.id], actor=ACTOR)

        rows = svc.list_affected_software(db)
        assert [r.advisory_id for r in rows] == [high_adv.id, low_adv.id]


class TestRefreshAllScans:
    def test_refreshes_every_previously_scanned_advisory(self, db, advisory) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 3)])
        svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        report = svc.refresh_all_scans(db, actor=ACTOR)
        assert report.refreshed == [advisory.id]
        assert report.failed == []

        history = svc.scan_history(db, advisory.id)
        assert len(history) == 2

    def test_never_scanned_advisory_is_untouched(self, db, advisory) -> None:
        report = svc.refresh_all_scans(db, actor=ACTOR)
        assert report.refreshed == []
        assert svc.scan_history(db, advisory.id) == []

    def test_uses_current_active_snapshots_not_the_original_scan_snapshot(
        self, db, advisory
    ) -> None:
        snap1 = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 3)])
        svc.run_scan(db, advisory.id, [snap1.id], actor=ACTOR)

        # A newer snapshot from the same source becomes the active/latest one.
        snap2 = _snapshot(db, rows=[("apache", "Log4j", "2.10.0", 9)])
        snap1.is_latest = False
        db.flush()

        report = svc.refresh_all_scans(db, actor=ACTOR)
        assert report.refreshed == [advisory.id]

        rows = svc.list_affected_software(db)
        assert len(rows) == 1
        assert rows[0].device_count == 9
        refreshed_run = svc.get_scan_run(db, rows[0].scan_run_id)
        assert refreshed_run is not None
        assert snap2.id in refreshed_run.snapshot_ids

    def test_one_advisory_failing_does_not_block_others(
        self, db, advisory, source, monkeypatch
    ) -> None:
        snap = _snapshot(db, rows=[("apache", "Log4j", "2.14.1", 3)])
        svc.run_scan(db, advisory.id, [snap.id], actor=ACTOR)

        other_adv = Advisory(
            source_id=source.id,
            external_ref="TEST-SCAN-OTHER",
            type=AdvisoryType.CVE_ADVISORY,
            title="Second advisory",
            received_at=datetime(2026, 8, 3, tzinfo=UTC),
            dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
            parser_version="1",
            status=AdvisoryStatus.NEW,
        )
        db.add(other_adv)
        db.flush()
        svc.run_scan(db, other_adv.id, [snap.id], actor=ACTOR)

        real_run_scan = svc.run_scan

        def _flaky_run_scan(db_, advisory_id, snapshot_ids, *, actor):
            if advisory_id == other_adv.id:
                raise RuntimeError("simulated scan failure")
            return real_run_scan(db_, advisory_id, snapshot_ids, actor=actor)

        monkeypatch.setattr(svc, "run_scan", _flaky_run_scan)

        report = svc.refresh_all_scans(db, actor=ACTOR)
        assert advisory.id in report.refreshed
        assert any(adv_id == other_adv.id for adv_id, _ in report.failed)
