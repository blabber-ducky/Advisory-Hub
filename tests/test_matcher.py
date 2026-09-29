"""The matching engine — confidence classification and rationale strings."""

from __future__ import annotations

import uuid

from advisory_hub.core.models.enums import MatchConfidence, MatchMethod
from advisory_hub.inventory.matcher import AffectedSpec, InventoryCandidate, match_candidates

SNAPSHOT = uuid.uuid4()

ALIAS_MAP = {"google llc": "google", "apache software foundation": "apache"}

LOG4J_CVE = "CVE-2021-44228"
LOG4J_SPEC = AffectedSpec(
    cve_id=LOG4J_CVE,
    vendor="apache",
    product="log4j",
    min_version="2.0",
    min_inclusive=True,
    max_version="2.15.0",
    max_inclusive=False,
)


class TestExactVendorMatchIsConfirmed:
    def test_matching_vendor_and_version_in_range(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT, vendor="apache", product="Log4j", version="2.14.1", device_count=6
        )
        results = match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP)
        assert len(results) == 1
        match = results[0]
        assert match.confidence == MatchConfidence.CONFIRMED
        assert match.match_method == MatchMethod.CPE_RANGE
        assert match.cve_id == LOG4J_CVE
        assert match.device_count == 6
        assert "2.14.1" in match.rationale
        assert LOG4J_CVE in match.rationale

    def test_version_outside_range_is_not_a_match(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT, vendor="apache", product="Log4j", version="2.17.0", device_count=1
        )
        assert match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP) == []

    def test_different_product_is_not_a_match(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT,
            vendor="apache",
            product="Tomcat",
            version="2.14.1",
            device_count=1,
        )
        assert match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP) == []

    def test_different_vendor_is_not_a_match(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT,
            vendor="someone else",
            product="Log4j",
            version="2.14.1",
            device_count=1,
        )
        assert match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP) == []


class TestVendorViaAliasIsLikely:
    def test_alias_mapped_vendor_downgrades_confidence(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT,
            vendor="Apache Software Foundation",  # needs the alias to reach "apache"
            product="Log4j",
            version="2.14.1",
            device_count=3,
        )
        results = match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP)
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.LIKELY
        assert "alias" in results[0].rationale.lower()


class TestExactVersionMatch:
    def test_cpe_exact_version_match(self) -> None:
        spec = AffectedSpec(
            cve_id="CVE-2026-0001",
            vendor="acme",
            product="widget",
            min_version=None,
            min_inclusive=False,
            max_version=None,
            max_inclusive=False,
            exact_version="1.2.3",
        )
        hit = InventoryCandidate(SNAPSHOT, "acme", "Widget", "1.2.3", 1)
        miss = InventoryCandidate(SNAPSHOT, "acme", "Widget", "1.2.4", 1)
        results = match_candidates([spec], [hit, miss], {})
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.CONFIRMED
        assert results[0].match_method == MatchMethod.CPE_EXACT


class TestPossibleConfidence:
    def test_unparseable_version_is_possible_not_dropped(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT,
            vendor="apache",
            product="Log4j",
            version="unknown-build",
            device_count=2,
        )
        results = match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP)
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.POSSIBLE
        assert "not comparable" in results[0].rationale

    def test_missing_version_is_possible_not_dropped(self) -> None:
        candidate = InventoryCandidate(
            snapshot_id=SNAPSHOT, vendor="apache", product="Log4j", version=None, device_count=4
        )
        results = match_candidates([LOG4J_SPEC], [candidate], ALIAS_MAP)
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.POSSIBLE
        assert "no version was recorded" in results[0].rationale

    def test_open_ended_range_with_no_lower_bound_is_possible(self) -> None:
        spec = AffectedSpec(
            cve_id="CVE-2026-0002",
            vendor="acme",
            product="widget",
            min_version=None,
            min_inclusive=False,
            max_version="5.0",
            max_inclusive=False,
        )
        candidate = InventoryCandidate(SNAPSHOT, "acme", "Widget", "1.0", 1)
        results = match_candidates([spec], [candidate], {})
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.POSSIBLE
        assert "open-ended" in results[0].rationale


class TestMultipleSpecsAndCandidates:
    def test_each_spec_matched_independently(self) -> None:
        # NVD's own CPE product component is "chrome", not the display name
        # "Google Chrome" — no fuzzy matching in this pass (see the matcher's
        # module docstring), so the inventory row's product must already be
        # spelled to match after normalisation.
        chrome_spec = AffectedSpec(
            cve_id="CVE-2026-1111",
            vendor="google",
            product="chrome",
            min_version="120.0.0.0",
            min_inclusive=True,
            max_version="120.0.6099.130",
            max_inclusive=False,
        )
        inventory = [
            InventoryCandidate(SNAPSHOT, "Google LLC", "Chrome", "120.0.6099.109", 41),
            InventoryCandidate(SNAPSHOT, "apache", "Log4j", "2.14.1", 6),
        ]
        results = match_candidates([chrome_spec, LOG4J_SPEC], inventory, ALIAS_MAP)
        assert len(results) == 2
        cve_ids = {r.cve_id for r in results}
        assert cve_ids == {"CVE-2026-1111", LOG4J_CVE}

    def test_product_name_noise_is_normalised_before_matching(self) -> None:
        # Vendor is already spelled canonically ("microsoft") so no alias is
        # needed — isolates the product-normalisation behaviour under test
        # from the separate alias-downgrades-confidence behaviour.
        spec = AffectedSpec(
            cve_id="CVE-2026-2222",
            vendor="microsoft",
            product="windows 10 enterprise 2016 ltsb",
            min_version=None,
            min_inclusive=False,
            max_version=None,
            max_inclusive=False,
            exact_version="10.0.14393",
        )
        candidate = InventoryCandidate(
            SNAPSHOT,
            "microsoft",
            "Windows 10 Enterprise 2016 LTSB (x64)",
            "10.0.14393",
            3,
        )
        results = match_candidates([spec], [candidate], {})
        assert len(results) == 1
        assert results[0].confidence == MatchConfidence.CONFIRMED
