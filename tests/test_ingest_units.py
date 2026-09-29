"""Unit tests for the ingestion primitives: defang, extractors, coercion."""

from __future__ import annotations

import pytest

from advisory_hub.core.models.enums import IocType, Priority, Severity
from advisory_hub.ingest.coerce import (
    higher_severity,
    parse_severity,
    priority_for,
    severity_from_text,
    title_fingerprint,
)
from advisory_hub.ingest.defang import defang, defang_url, is_defanged, refang
from advisory_hub.ingest.extractors import (
    extract_cves,
    extract_cvss,
    extract_iocs_from_section,
    extract_ttps,
    make_ioc,
    normalise_ioc_type,
)
from advisory_hub.ingest.message import parse_advisory_date, parse_body_fields
from advisory_hub.ingest.patterns import SUBJECT


class TestDefang:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("154[.]196[.]162[.]76", "154.196.162.76"),
            ("about[.]blsouqs[.]com", "about.blsouqs.com"),
            ("hxxps://evil[.]test", "https://evil.test"),
            ("hXXp://evil[.]test", "http://evil.test"),
            ("evil(.)test", "evil.test"),
            ("evil{.}test", "evil.test"),
            ("evil[dot]test", "evil.test"),
            ("http[:]//evil.test", "http://evil.test"),
            ("user[@]evil.test", "user@evil.test"),
        ],
    )
    def test_refang(self, given: str, expected: str) -> None:
        assert refang(given) == expected

    def test_punycode_idn_survives(self) -> None:
        """The corpus contains xn-- IDNs; they must round-trip."""
        assert refang("xn--90aguaqgfu[.]xn--p1ai") == "xn--90aguaqgfu.xn--p1ai"

    def test_defang_is_never_clickable(self) -> None:
        assert defang("192.0.2.1") == "192[.]0[.]2[.]1"
        url = defang_url("https://evil.test/x")
        # Both the scheme and the separator must be neutered, so nothing in the
        # string is an autolink-able URL.
        assert url.startswith("hxxps")
        assert "https://" not in url
        assert "[://]" in url

    def test_round_trip(self) -> None:
        for value in ("192.0.2.1", "evil.test", "sub.evil.test"):
            assert refang(defang(value)) == value

    def test_is_defanged(self) -> None:
        assert is_defanged("1[.]2[.]3[.]4")
        assert is_defanged("hxxp://x")
        assert not is_defanged("1.2.3.4")

    def test_empty_input(self) -> None:
        assert refang("") == ""
        assert defang("") == ""


class TestCveExtraction:
    def test_basic(self) -> None:
        assert extract_cves("Fixes CVE-2026-58319 and cve-2021-44228") == [
            "CVE-2021-44228",
            "CVE-2026-58319",
        ]

    def test_deduplicates_and_sorts(self) -> None:
        assert extract_cves("CVE-2026-1234 CVE-2026-1234") == ["CVE-2026-1234"]

    def test_tolerates_pdf_unicode_dashes(self) -> None:
        """pdfplumber emits non-breaking and en dashes inside CVE IDs."""
        assert extract_cves("CVE‑2026‑58319") == ["CVE-2026-58319"]
        assert extract_cves("CVE–2026–1234") == ["CVE-2026-1234"]

    def test_seven_digit_ids(self) -> None:
        assert extract_cves("CVE-2026-1234567") == ["CVE-2026-1234567"]

    def test_rejects_non_cves(self) -> None:
        assert extract_cves("CVE-26-1 and CVSS-2026-1234") == []

    def test_empty(self) -> None:
        assert extract_cves("") == []


class TestCvss:
    def test_prefers_vector_over_prose_number(self) -> None:
        findings = extract_cvss("CVSS v3.1: 9.1 (Critical) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H")
        assert findings[0].vector is not None
        assert findings[0].score is not None

    def test_score_without_vector(self) -> None:
        findings = extract_cvss("CVSS v3.1: 7.5")
        assert findings and findings[0].score is not None and float(findings[0].score) == 7.5

    def test_ignores_out_of_range(self) -> None:
        assert all(0 <= float(f.score) <= 10 for f in extract_cvss("CVSS v3.1: 99.9") if f.score)


class TestIocs:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("IP Address", IocType.IPV4),
            ("ip address", IocType.IPV4),
            ("Domain", IocType.DOMAIN),
            ("SHA-256", IocType.SHA256),
            ("SHA256", IocType.SHA256),
            ("MD5", IocType.MD5),
            ("URL", IocType.URL),
            ("Email", IocType.EMAIL),
        ],
    )
    def test_regulator_labels_map_to_enum(self, label: str, expected: IocType) -> None:
        assert normalise_ioc_type(label)[0] is expected

    def test_unknown_label_keeps_raw_rather_than_dropping(self) -> None:
        """Dropping the row would lose an indicator."""
        ioc_type, raw = normalise_ioc_type("Bitcoin Wallet Address")
        assert ioc_type is IocType.OTHER
        assert raw == "Bitcoin Wallet Address"

    def test_registry_variants(self) -> None:
        assert normalise_ioc_type("Registry Run Keys / Startup Items")[0] is IocType.REGISTRY_KEY

    def test_make_ioc_stores_both_forms(self) -> None:
        ioc = make_ioc("154[.]196[.]162[.]76", "IP Address", source="PDF_TABLE")
        assert ioc is not None
        assert ioc.value == "154.196.162.76"
        assert ioc.defanged_value == "154[.]196[.]162[.]76"

    def test_parses_the_corpus_table_shape(self) -> None:
        section = (
            "Indicator Type\n"
            "192[.]0[.]2[.]1 IP Address\n"
            "about[.]example[.]invalid Domain\n"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb MD5\n"
            f"{'a' * 64} SHA256\n"
        )
        iocs = extract_iocs_from_section(section)
        assert {i.ioc_type for i in iocs} == {
            IocType.IPV4,
            IocType.DOMAIN,
            IocType.MD5,
            IocType.SHA256,
        }

    def test_header_row_is_not_an_indicator(self) -> None:
        assert extract_iocs_from_section("Indicator Type\n") == []


class TestTtps:
    def test_attack_techniques(self) -> None:
        values = {t.value for t in extract_ttps("Uses T1566.001 and T1059")}
        assert values == {"T1566.001", "T1059"}

    def test_threat_actors(self) -> None:
        values = {t.value for t in extract_ttps("APT29 and Storm-1175 and UNC 2452")}
        assert {"APT29", "STORM1175", "UNC2452"} <= values


class TestSeverityCoercion:
    def test_reads_leading_token(self) -> None:
        assert parse_severity("Critical") is Severity.CRITICAL

    def test_survives_the_field_bleed(self) -> None:
        """DOH-2026562 has `Risk level: High` running into a repeated subject."""
        assert parse_severity("High Security Advisory :: DOH- 2026562 - CVE…") is Severity.HIGH

    def test_unknown_is_none(self) -> None:
        assert parse_severity("Bananas") is None
        assert parse_severity(None) is None

    def test_higher_severity_wins(self) -> None:
        """Under-triaging a Critical is the more expensive error — D-019."""
        assert higher_severity(Severity.HIGH, Severity.CRITICAL) is Severity.CRITICAL
        assert higher_severity(Severity.CRITICAL, Severity.HIGH) is Severity.CRITICAL
        assert higher_severity(None, Severity.MEDIUM) is Severity.MEDIUM
        assert higher_severity(Severity.MEDIUM, None) is Severity.MEDIUM

    def test_severity_from_text_takes_the_max(self) -> None:
        assert severity_from_text("Medium then Critical") is Severity.CRITICAL

    def test_priority_mapping(self) -> None:
        assert priority_for(Severity.CRITICAL) is Priority.P1
        assert priority_for(Severity.HIGH) is Priority.P2
        assert priority_for(Severity.MEDIUM) is Priority.P3
        assert priority_for(Severity.LOW) is Priority.P4
        assert priority_for(None) is None


class TestDates:
    @pytest.mark.parametrize(
        "given", ["23-July-2026", "4-Aug-2026", "04- Aug-2026", " 23 - July - 2026 "]
    )
    def test_corpus_date_shapes(self, given: str) -> None:
        assert parse_advisory_date(given) is not None

    def test_invalid(self) -> None:
        assert parse_advisory_date("2026-07-23") is None
        assert parse_advisory_date("32-July-2026") is None
        assert parse_advisory_date(None) is None


class TestSubjectPattern:
    @pytest.mark.parametrize(
        ("subject", "ref", "title_starts"),
        [
            ("[EXTERNAL] Security Advisory :: DOH- 2026550 - Critical Flaw", "2026550", "Critical"),
            ("[EXTERNAL] Security Advisory :: DOH-2026512- Multiple Vulns", "2026512", "Multiple"),
            ("[EXTERNAL] Security Advisory :: DOH-2026607 Multiple Vulns", "2026607", "Multiple"),
            ("Security Advisory :: DOH-2026508 - IBM WebSphere", "2026508", "IBM"),
        ],
    )
    def test_real_corpus_variants(self, subject: str, ref: str, title_starts: str) -> None:
        m = SUBJECT.match(subject)
        assert m is not None, subject
        assert m.group("number") == ref
        assert m.group("title").startswith(title_starts)


class TestBodyFields:
    def test_label_scan_slices_between_labels(self) -> None:
        body = (
            "Affected Product:\n\nApache Doris\n\n"
            "Reference:\n\nOpenwall\n\n"
            "Detected on:\n\n23-July-2026\n\n"
            "Type:\n\nVulnerability\n\n"
            "Risk level:\n\nCritical\n\n"
            "Description:\n\nA critical flaw.\n\n"
        )
        fields = parse_body_fields(body)
        assert fields["affected_product"] == "Apache Doris"
        assert fields["reference"] == "Openwall"
        assert fields["detected_on"] == "23-July-2026"
        assert fields["type"] == "Vulnerability"
        assert fields["risk_level"] == "Critical"

    def test_normalises_nbsp(self) -> None:
        assert parse_body_fields("Type:  Vulnerability\n")["type"] == "Vulnerability"

    def test_first_occurrence_wins(self) -> None:
        fields = parse_body_fields("Type: Vulnerability\n\nType: Campaign\n")
        assert fields["type"] == "Vulnerability"


class TestTitleFingerprint:
    def test_ignores_punctuation_and_case(self) -> None:
        assert title_fingerprint("Critical Flaw in X") == title_fingerprint("critical-flaw-in-x!")

    def test_differs_for_different_titles(self) -> None:
        assert title_fingerprint("Flaw in X") != title_fingerprint("Flaw in Y")
