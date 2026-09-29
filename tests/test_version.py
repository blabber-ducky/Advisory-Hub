"""Tier-1 version normalisation — numeric tuple extraction only."""

from __future__ import annotations

from advisory_hub.inventory.version import normalise_version


class TestNormaliseVersion:
    def test_simple_dotted_version(self) -> None:
        assert normalise_version("17.0.9") == ("17.0.9", [17, 0, 9])

    def test_four_part_chrome_style_version(self) -> None:
        assert normalise_version("120.0.6099.109") == ("120.0.6099.109", [120, 0, 6099, 109])

    def test_pre_release_suffix_is_ignored_by_tier_1(self) -> None:
        _normalized, parts = normalise_version("2.14.1-rc2")
        assert parts == [2, 14, 1, 2]  # honest limitation: rc2's "2" is swept in

    def test_none_input_returns_none(self) -> None:
        assert normalise_version(None) == (None, None)

    def test_empty_string_returns_none(self) -> None:
        assert normalise_version("") == (None, None)

    def test_no_digits_at_all_returns_none(self) -> None:
        assert normalise_version("latest") == (None, None)

    def test_java_update_notation_extracts_what_it_can(self) -> None:
        # Tier 1 doesn't understand "8u391" specially (that's Phase 2d) — it
        # extracts every digit run it can find, honestly, not a wrong parse.
        assert normalise_version("8u391") == ("8.391", [8, 391])

    def test_implausibly_large_component_is_rejected_not_stored(self) -> None:
        # Regression: a real "Asure ID" row in this project's Inventory/
        # sample data has a corrupted 195-digit version field that
        # overflowed the int32 `version_parts` column and crashed the
        # insert — found by running real data through the pipeline, not by
        # inspection. Giving up honestly here is what CLAUDE.md §2.2 calls
        # for; silently truncating the number would be a wrong guess.
        huge = "7." + "8" * 200
        assert normalise_version(huge) == (None, None)

    def test_component_at_int32_max_is_kept(self) -> None:
        assert normalise_version("2147483647.0") == ("2147483647.0", [2147483647, 0])

    def test_component_over_int32_max_is_rejected(self) -> None:
        assert normalise_version("2147483648.0") == (None, None)
