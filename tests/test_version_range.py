"""`ingest.version_range.parse_version_range()` — structured range extraction
from PDF-parsed advisory text.

Patterns below are synthetic but shaped like real regulator advisory text
(build numbers, LTS annotations, semicolon-separated multi-range lists,
unicode dashes from PDF extraction) — not verbatim corpus text, which is
restricted and never committed (CLAUDE.md §6).
"""

from __future__ import annotations

from advisory_hub.ingest.version_range import parse_version_range


class TestComparatorPatterns:
    def test_less_than(self) -> None:
        result = parse_version_range("< 17.0.9", None)
        assert result == {
            "min_version": None,
            "min_inclusive": True,
            "max_version": "17.0.9",
            "max_inclusive": False,
            "exact_version": None,
            "source": "version_expression",
        }

    def test_less_than_or_equal(self) -> None:
        result = parse_version_range("<= 29.0", None)
        assert result is not None
        assert result["max_version"] == "29.0"
        assert result["max_inclusive"] is True

    def test_greater_than_or_equal(self) -> None:
        result = parse_version_range(">= 2.0", None)
        assert result is not None
        assert result["min_version"] == "2.0"
        assert result["min_inclusive"] is True

    def test_greater_than(self) -> None:
        result = parse_version_range("> 5.2.1", None)
        assert result is not None
        assert result["min_version"] == "5.2.1"
        assert result["min_inclusive"] is False

    def test_comparator_embedded_in_a_sentence(self) -> None:
        """A real shape: "Vulnerable builds compiled with OpenSSL < 1.1.0"
        — the comparator clause is trusted even inside a longer sentence,
        since it's still a single unambiguous claim."""
        result = parse_version_range("Vulnerable builds compiled with Foo < 1.1.0", None)
        assert result is not None
        assert result["max_version"] == "1.1.0"
        assert result["max_inclusive"] is False

    def test_trailing_parenthetical_does_not_break_the_match(self) -> None:
        result = parse_version_range("<= 29.0 (all releases at time of disclosure)", None)
        assert result is not None
        assert result["max_version"] == "29.0"


class TestWordPatterns:
    def test_below(self) -> None:
        result = parse_version_range("Builds below 16.0.19725.20434", None)
        assert result is not None
        assert result["max_version"] == "16.0.19725.20434"
        assert result["max_inclusive"] is False

    def test_prior_to(self) -> None:
        result = parse_version_range("releases prior to 2.14.9", None)
        assert result is not None
        assert result["max_version"] == "2.14.9"
        assert result["max_inclusive"] is False

    def test_before(self) -> None:
        result = parse_version_range("Versions before 6.6.14", None)
        assert result is not None
        assert result["max_version"] == "6.6.14"

    def test_up_to(self) -> None:
        result = parse_version_range("Affected versions up to 3.2.0", None)
        assert result is not None
        assert result["max_version"] == "3.2.0"
        assert result["max_inclusive"] is False

    def test_and_earlier_is_inclusive(self) -> None:
        result = parse_version_range("1.26.1 and earlier", None)
        assert result is not None
        assert result["max_version"] == "1.26.1"
        assert result["max_inclusive"] is True

    def test_and_below_is_inclusive(self) -> None:
        result = parse_version_range("4.2.0 and below", None)
        assert result is not None
        assert result["max_version"] == "4.2.0"
        assert result["max_inclusive"] is True

    def test_and_later_is_inclusive_min(self) -> None:
        result = parse_version_range("2.0.0 and later", None)
        assert result is not None
        assert result["min_version"] == "2.0.0"
        assert result["min_inclusive"] is True

    def test_or_above(self) -> None:
        result = parse_version_range("3.5.0 or above", None)
        assert result is not None
        assert result["min_version"] == "3.5.0"


class TestSimpleRange:
    def test_hyphen_range(self) -> None:
        result = parse_version_range("3.4.0 - 3.4.5", None)
        assert result is not None
        assert result["min_version"] == "3.4.0"
        assert result["min_inclusive"] is True
        assert result["max_version"] == "3.4.5"
        assert result["max_inclusive"] is True

    def test_en_dash_range_is_normalised(self) -> None:
        """Real PDF extraction commonly yields an en-dash, not a hyphen."""
        result = parse_version_range("3.4.0–3.4.5", None)
        assert result is not None
        assert result["min_version"] == "3.4.0"
        assert result["max_version"] == "3.4.5"

    def test_double_hyphen_artifact_is_normalised(self) -> None:
        """Another real PDF-extraction artifact: a doubled hyphen."""
        result = parse_version_range("Versions 9.0-- 9.16", None)
        assert result is not None
        assert result["min_version"] == "9.0"
        assert result["max_version"] == "9.16"

    def test_through(self) -> None:
        result = parse_version_range("versions 1.2.68 through 1.2.83", None)
        assert result is not None
        assert result["min_version"] == "1.2.68"
        assert result["max_version"] == "1.2.83"

    def test_to(self) -> None:
        result = parse_version_range("2.0.0 to 2.5.0", None)
        assert result is not None
        assert result["min_version"] == "2.0.0"
        assert result["max_version"] == "2.5.0"


class TestBareVersion:
    def test_bare_version_is_an_exact_match(self) -> None:
        result = parse_version_range("4.0.0", None)
        assert result is not None
        assert result["exact_version"] == "4.0.0"
        assert result["min_version"] is None
        assert result["max_version"] is None

    def test_build_qualified_bare_version(self) -> None:
        result = parse_version_range("37.0.3.1", None)
        assert result is not None
        assert result["exact_version"] == "37.0.3.1"


class TestHonestNonMatches:
    """The majority of real advisory text — multi-clause, prose, discrete
    lists — must come back `None`, never a guessed range."""

    def test_semicolon_separated_multi_range_is_not_guessed(self) -> None:
        text = "10.3.0-10.3.1 (LTS); 10.2.0-10.2.5 (LTS); 9.4.0-9.4.22 (LTS)"
        assert parse_version_range(text, None) is None

    def test_comma_separated_discrete_list_is_not_guessed(self) -> None:
        assert parse_version_range("7.0, 7.2, 7.4, 7.6, 7.7, 10.0", None) is None

    def test_pure_prose_with_no_version_at_all(self) -> None:
        text = "The vulnerability affects the product regardless of device configuration"
        assert parse_version_range(text, None) is None

    def test_two_separate_comparator_clauses_for_different_variants(self) -> None:
        assert parse_version_range("< 7.5.3 (v7), < 8.1.7.1 (v8)", None) is None

    def test_none_input(self) -> None:
        assert parse_version_range(None, None) is None

    def test_empty_string(self) -> None:
        assert parse_version_range("", None) is None

    def test_a_cve_id_alone_is_not_a_version(self) -> None:
        assert parse_version_range("CVE-2026-43499", None) is None


class TestFixedVersionFallback:
    def test_bare_fixed_version_implies_an_exclusive_upper_bound(self) -> None:
        """version_expression is prose (no clean range), but fixed_version
        alone is a bare version — "vulnerable if strictly older than this"
        is a legitimate, honest inference."""
        result = parse_version_range(
            "The vulnerability affects the product regardless of configuration", "4.0.1"
        )
        assert result is not None
        assert result["max_version"] == "4.0.1"
        assert result["max_inclusive"] is False
        assert result["source"] == "fixed_version"

    def test_version_expression_takes_priority_over_fixed_version(self) -> None:
        result = parse_version_range("< 17.0.9", "17.0.9")
        assert result is not None
        assert result["source"] == "version_expression"

    def test_messy_fixed_version_does_not_fall_back_either(self) -> None:
        result = parse_version_range(None, "Upgrade to a verified clean release")
        assert result is None

    def test_no_expression_and_no_fixed_version(self) -> None:
        assert parse_version_range(None, None) is None
