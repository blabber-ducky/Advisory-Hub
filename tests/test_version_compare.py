"""Tiered version comparison — `compare_versions()` / `version_in_range()`."""

from __future__ import annotations

from advisory_hub.inventory.version import compare_versions, version_in_range


class TestCompareVersions:
    def test_simple_ordering(self) -> None:
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_chrome_style_four_part_versions(self) -> None:
        assert compare_versions("120.0.6099.109", "120.0.6099.130") == -1
        assert compare_versions("120.0.6099.130", "120.0.6099.109") == 1

    def test_pep440_prerelease_ordering(self) -> None:
        """A naive digit-run comparison gets this wrong — rc1 sorts as if
        the "1" were a fourth version component, not a pre-release marker."""
        assert compare_versions("2.15.0rc1", "2.15.0") == -1
        assert compare_versions("2.15.0", "2.15.0rc1") == 1

    def test_tier1_fallback_when_not_pep440_shaped(self) -> None:
        # "8u391" isn't valid PEP 440 but both sides extract clean digit
        # runs, so tier 1 still gives a correct, confident answer.
        assert compare_versions("8u391", "8u400") == -1

    def test_padded_equal_lengths(self) -> None:
        assert compare_versions("1.2", "1.2.0") == 0
        assert compare_versions("1.2", "1.3.0") == -1

    def test_incomparable_returns_none(self) -> None:
        assert compare_versions("latest", "2.0.0") is None
        assert compare_versions("'-", "10.0.19045") is None


class TestVersionInRange:
    def test_within_range(self) -> None:
        assert (
            version_in_range(
                "2.14.1",
                min_version="2.0",
                min_inclusive=True,
                max_version="2.15.0",
                max_inclusive=False,
            )
            is True
        )

    def test_at_exclusive_upper_bound_is_out_of_range(self) -> None:
        assert (
            version_in_range("2.15.0", min_version="2.0", max_version="2.15.0", max_inclusive=False)
            is False
        )

    def test_at_inclusive_upper_bound_is_in_range(self) -> None:
        assert (
            version_in_range("2.15.0", min_version="2.0", max_version="2.15.0", max_inclusive=True)
            is True
        )

    def test_below_inclusive_lower_bound_is_out_of_range(self) -> None:
        assert version_in_range("1.9", min_version="2.0", min_inclusive=True) is False

    def test_at_inclusive_lower_bound_is_in_range(self) -> None:
        assert version_in_range("2.0", min_version="2.0", min_inclusive=True) is True

    def test_no_bounds_is_always_in_range(self) -> None:
        assert version_in_range("9.9.9") is True

    def test_uncomparable_version_returns_none_not_a_guess(self) -> None:
        assert version_in_range("latest", min_version="1.0", max_version="2.0") is None
