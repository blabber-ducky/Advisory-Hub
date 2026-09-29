"""Regression tests against redacted samples from the real DOH corpus.

Each fixture pins a behaviour that a real advisory forced. Fixtures are
redacted per CLAUDE.md §6: IOCs replaced with RFC 5737 / .invalid values,
contact block and recipient-identifying SafeLinks removed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from advisory_hub.core.models.enums import AdvisoryType, IocType, Severity
from advisory_hub.ingest.classify import classify
from advisory_hub.ingest.coerce import parse_severity
from advisory_hub.ingest.extractors import (
    extract_cves,
    extract_iocs_from_section,
    extract_products_from_table,
)
from advisory_hub.ingest.message import parse_body_fields
from advisory_hub.ingest.patterns import (
    ADVISORY_NUMBER,
    COVER_SEVERITY,
    IOC_ROW,
    SUBJECT,
)
from advisory_hub.ingest.sections import split_sections

FIXTURES = Path(__file__).parent / "fixtures" / "corpus_samples.json"


@pytest.fixture(scope="module")
def samples() -> dict[str, Any]:
    if not FIXTURES.is_file():
        pytest.skip("corpus fixtures not generated")
    return json.loads(FIXTURES.read_text())


def _doc(sample: dict[str, Any]):
    return split_sections(sample["pdf_text"])


class TestTemplateStructure:
    """The regulator's PDF template — present in 132-135 of 135."""

    @pytest.mark.parametrize("name", ["single_cve", "products_table", "ioc_table", "many_cves"])
    def test_core_sections_present(self, samples: dict[str, Any], name: str) -> None:
        headings = {h.upper() for h in _doc(samples[name]).headings()}
        assert {"OVERVIEW", "TECHNICAL DETAILS"} <= headings

    def test_page_header_is_stripped(self, samples: dict[str, Any]) -> None:
        """Repeats on every page; left in, every extractor double-counts."""
        assert "Advisory Number:" not in _doc(samples["single_cve"]).content_text

    def test_boilerplate_excluded_from_content(self, samples: dict[str, Any]) -> None:
        doc = _doc(samples["single_cve"])
        assert any(s.is_boilerplate for s in doc.sections)
        assert "Change Management process" not in doc.content_text

    def test_arabic_is_excluded(self, samples: dict[str, Any]) -> None:
        """Emitted in reversed logical order; excluded, not reordered."""
        content = _doc(samples["single_cve"]).content_text
        assert not any("؀" <= ch <= "ۿ" for ch in content)


class TestPdfIsTheDocumentOfRecord:
    """D-013: the PDF yields 6x the CVEs of the email body."""

    def test_pdf_finds_cves_the_email_omits(self, samples: dict[str, Any]) -> None:
        sample = samples["many_cves"]
        body_cves = set(extract_cves(sample["body"]))
        pdf_cves = set(extract_cves(sample["pdf_text"]))
        assert len(pdf_cves) > len(body_cves)
        assert pdf_cves - body_cves

    def test_bulk_advisory_has_many_cves(self, samples: dict[str, Any]) -> None:
        assert len(extract_cves(samples["many_cves"]["pdf_text"])) >= 20


class TestIocExtraction:
    def test_ioc_section_is_found_despite_lowercase_plural(self, samples: dict[str, Any]) -> None:
        """The heading is literally 'IOCs'. A strict ALL-CAPS pattern skipped
        every one of them."""
        doc = _doc(samples["ioc_table"])
        assert any(s.is_ioc for s in doc.sections), doc.headings()

    def test_indicators_parse_with_their_labelled_types(self, samples: dict[str, Any]) -> None:
        doc = _doc(samples["ioc_table"])
        section = next(s for s in doc.sections if s.is_ioc)
        iocs = extract_iocs_from_section(section.body)
        # Redaction collapses every IP to 192.0.2.1 and every domain to one
        # name, so *unique* IOC counts here are an artefact of the fixture, not
        # of the parser. Assert type coverage and raw row count instead.
        raw_rows = [ln for ln in section.body.splitlines() if IOC_ROW.match(ln)]
        assert len(raw_rows) >= 10, f"only {len(raw_rows)} labelled rows"
        assert {IocType.IPV4, IocType.DOMAIN, IocType.MD5} <= {i.ioc_type for i in iocs}

    def test_every_ioc_is_stored_defanged(self, samples: dict[str, Any]) -> None:
        doc = _doc(samples["ioc_table"])
        section = next(s for s in doc.sections if s.is_ioc)
        for ioc in extract_iocs_from_section(section.body):
            if ioc.ioc_type in {IocType.IPV4, IocType.DOMAIN, IocType.URL}:
                assert "[.]" in ioc.defanged_value, ioc


class TestAffectedProducts:
    def test_table_survives_spacer_columns(self, samples: dict[str, Any]) -> None:
        """extract_tables() pads rows with empty spacer cells; the corpus
        SharePoint table is 9 wide with 5 real columns."""
        tables = samples["products_table"]["tables"]
        claims: list[Any] = []
        for table in tables:
            claims.extend(extract_products_from_table(table))
        assert claims
        assert all(c.product for c in claims)

    def test_captures_fixed_version_when_present(self, samples: dict[str, Any]) -> None:
        claims: list[Any] = []
        for table in samples["products_table"]["tables"]:
            claims.extend(extract_products_from_table(table))
        assert any(c.fixed_version for c in claims)


class TestCrossValidation:
    def test_ref_mismatch_is_detectable(self, samples: dict[str, Any]) -> None:
        """DOH-2026515's PDF says DOH2026516 — a real regulator typo (D-019)."""
        sample = samples["ref_mismatch"]
        subject_match = SUBJECT.match(sample["subject"])
        pdf_match = ADVISORY_NUMBER.search(sample["pdf_text"])
        assert subject_match and pdf_match
        subject_ref = f"{subject_match.group('prefix').upper()}-{subject_match.group('number')}"
        pdf_ref = f"{pdf_match.group('prefix').upper()}-{pdf_match.group('number')}"
        assert subject_ref != pdf_ref

    def test_cover_severity_is_readable(self, samples: dict[str, Any]) -> None:
        m = COVER_SEVERITY.search(samples["single_cve"]["pdf_text"])
        assert m and parse_severity(m.group("value")) is not None


class TestSubjectEdgeCases:
    def test_missing_separator(self, samples: dict[str, Any]) -> None:
        """DOH-2026607 has no dash between the number and the title."""
        m = SUBJECT.match(samples["no_subject_separator"]["subject"])
        assert m is not None
        assert m.group("title").strip()

    def test_field_bleed_still_yields_a_severity(self, samples: dict[str, Any]) -> None:
        """DOH-2026562's Risk level runs into a repeated subject line."""
        fields = parse_body_fields(samples["field_bleed"]["body"])
        assert parse_severity(fields.get("risk_level")) is Severity.HIGH


class TestClassification:
    def test_single_cve_advisory(self, samples: dict[str, Any]) -> None:
        sample = samples["single_cve"]
        doc = _doc(sample)
        result = classify(
            title=SUBJECT.match(sample["subject"]).group("title"),  # type: ignore[union-attr]
            doc=doc,
            cve_count=len(extract_cves(sample["pdf_text"])),
            ioc_count=0,
            has_cvss_vector=False,
            regulator_type="Vulnerability",
            body_text=sample["body"],
        )
        assert result.type is AdvisoryType.CVE_ADVISORY

    def test_campaign_beats_the_regulator_label(self, samples: dict[str, Any]) -> None:
        """The regulator labels this 'Vulnerability'; structure says otherwise."""
        sample = samples["ioc_table"]
        doc = _doc(sample)
        result = classify(
            title=SUBJECT.match(sample["subject"]).group("title"),  # type: ignore[union-attr]
            doc=doc,
            cve_count=0,
            ioc_count=38,
            has_cvss_vector=False,
            regulator_type="Vulnerability",
            body_text=sample["body"],
        )
        assert result.type is AdvisoryType.THREAT_LANDSCAPE

    def test_threat_report_without_iocs_still_classifies(self, samples: dict[str, Any]) -> None:
        """DOH-2026638 (IoT botnet) has no IOC section and no CVEs, and the
        regulator called it 'Vulnerability'."""
        sample = samples["threat_no_ioc"]
        result = classify(
            title=SUBJECT.match(sample["subject"]).group("title"),  # type: ignore[union-attr]
            doc=_doc(sample),
            cve_count=0,
            ioc_count=0,
            has_cvss_vector=False,
            regulator_type="Vulnerability",
            body_text=sample["body"],
        )
        assert result.type is AdvisoryType.THREAT_LANDSCAPE

    def test_cve_advisory_never_wins_without_a_cve(self, samples: dict[str, Any]) -> None:
        result = classify(
            title="Some Threat Report",
            doc=None,
            cve_count=0,
            ioc_count=0,
            has_cvss_vector=False,
            regulator_type="Vulnerability",
            body_text="ransomware campaign",
        )
        assert result.type is not AdvisoryType.CVE_ADVISORY

    def test_classification_is_deterministic(self, samples: dict[str, Any]) -> None:
        """No dependence on dict insertion order."""
        args = {
            "title": "Ambiguous",
            "doc": None,
            "cve_count": 0,
            "ioc_count": 0,
            "has_cvss_vector": False,
            "regulator_type": None,
            "body_text": "campaign",
        }
        assert len({classify(**args).type for _ in range(20)}) == 1  # type: ignore[arg-type]

    def test_confidence_reflects_evidence_not_just_split(self) -> None:
        """A single weak signal must not read as certainty."""
        weak = classify(
            title="Something",
            doc=None,
            cve_count=0,
            ioc_count=0,
            has_cvss_vector=False,
            regulator_type=None,
            body_text="malware",
        )
        assert weak.is_low_confidence, weak.confidence

    def test_absent_section_is_not_evidence(self) -> None:
        """With no PDF there is no affected-products section to be missing;
        that absence must not be scored as a signal."""
        no_doc = classify(
            title="X",
            doc=None,
            cve_count=0,
            ioc_count=0,
            has_cvss_vector=False,
            regulator_type=None,
            body_text="ransomware campaign",
        )
        assert "affected-products section" not in " ".join(no_doc.signals)

    def test_signals_are_recorded_for_audit(self, samples: dict[str, Any]) -> None:
        """Every classification must be explainable — D-008."""
        result = classify(
            title="Security Updates - Vendor",
            doc=None,
            cve_count=3,
            ioc_count=0,
            has_cvss_vector=True,
            regulator_type="Vulnerability",
            body_text="",
        )
        assert result.signals
