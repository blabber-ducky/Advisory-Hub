"""Vendor/product normalisation."""

from __future__ import annotations

from advisory_hub.inventory.normalise import (
    SEED_VENDOR_ALIASES,
    normalise_product,
    normalise_vendor,
)


class TestNormaliseVendor:
    def test_alias_hit(self) -> None:
        alias_map = {"microsoft corporation": "microsoft"}
        assert normalise_vendor("Microsoft Corporation", alias_map) == "microsoft"

    def test_alias_lookup_is_case_insensitive(self) -> None:
        alias_map = {"google llc": "google"}
        assert normalise_vendor("GOOGLE LLC", alias_map) == "google"

    def test_falls_back_to_lowercase_trim_when_no_alias(self) -> None:
        assert normalise_vendor("  Some Random Vendor  ", {}) == "some random vendor"

    def test_none_input_returns_none(self) -> None:
        assert normalise_vendor(None, {}) is None

    def test_blank_input_returns_none(self) -> None:
        assert normalise_vendor("   ", {}) is None

    def test_seed_aliases_are_all_lowercase_canonical_forms(self) -> None:
        for _alias, canonical in SEED_VENDOR_ALIASES:
            assert canonical == canonical.lower()


class TestNormaliseProduct:
    def test_lowercases_and_trims(self) -> None:
        assert normalise_product("  Google Chrome  ") == "google chrome"

    def test_collapses_internal_whitespace(self) -> None:
        assert normalise_product("Google   Chrome") == "google chrome"

    def test_strips_architecture_noise(self) -> None:
        assert (
            normalise_product("Windows 10 Enterprise 2016 LTSB (x64)")
            == "windows 10 enterprise 2016 ltsb"
        )

    def test_strips_64_bit_word_form(self) -> None:
        assert normalise_product("Some App 64-bit") == "some app"

    def test_no_noise_is_unchanged_besides_case(self) -> None:
        assert normalise_product("Apache Log4j") == "apache log4j"
