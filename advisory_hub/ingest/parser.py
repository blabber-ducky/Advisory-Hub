"""Turn a message + its attachments into a structured advisory.

Pure: no database, no filesystem. Produces a ``ParsedAdvisory`` that the
pipeline persists. This is the unit the corpus regression suite exercises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal

from ..core.models.enums import (
    AdvisoryType,
    ClaimSource,
    ExtractionMethod,
    FlagKind,
    Priority,
    Severity,
)
from . import patterns
from .classify import Classification, classify
from .coerce import (
    higher_severity,
    parse_severity,
    priority_for,
    severity_from_text,
    title_fingerprint,
)
from .extractors import (
    CvssFinding,
    Ioc,
    ProductClaim,
    Ttp,
    extract_cves,
    extract_cvss,
    extract_iocs_by_regex,
    extract_iocs_from_section,
    extract_products_from_prose,
    extract_products_from_table,
    extract_reference_urls,
    extract_ttps,
    highest_cvss,
)
from .message import Attachment, ParsedMessage, parse_advisory_date
from .pdf import PdfExtraction, extract_pdf
from .sections import SectionedDocument, split_sections
from .sidecars import parse_sidecar
from .version_range import parse_version_range

#: Bump when extraction changes materially. Stamped on every advisory so
#: `reparse` can target older versions. See docs/ingestion.md §15.
#: 2: structured `parsed_range` extraction from version_expression/
#: fixed_version — see ingest/version_range.py and D-032.
PARSER_VERSION = "2"


@dataclass(slots=True)
class AttachmentResult:
    attachment: Attachment
    extraction: PdfExtraction | None = None
    ioc_count: int = 0

    @property
    def method(self) -> ExtractionMethod | None:
        return self.extraction.method if self.extraction else None


@dataclass(slots=True)
class ParsedAdvisory:
    message: ParsedMessage
    external_ref: str | None
    title: str
    description: str | None
    body_text: str
    type: AdvisoryType
    type_confidence: Decimal
    classification_signals: list[str]
    source_type_raw: str | None
    severity: Severity | None
    priority: Priority | None
    cvss_score: Decimal | None
    published_at: date | None
    detected_on: date | None
    upstream_reference: str | None
    title_fingerprint: str
    parser_version: str = PARSER_VERSION

    cves: dict[str, list[str]] = field(default_factory=dict)  # cve -> provenance
    cvss: list[CvssFinding] = field(default_factory=list)
    iocs: list[Ioc] = field(default_factory=list)
    ttps: list[Ttp] = field(default_factory=list)
    products: list[ProductClaim] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)
    attachments: list[AttachmentResult] = field(default_factory=list)
    flags: list[tuple[FlagKind, dict[str, object]]] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)

    @property
    def cve_ids(self) -> list[str]:
        return sorted(self.cves)


def parse_advisory(message: ParsedMessage, *, extract_pdfs: bool = True) -> ParsedAdvisory:
    """Parse a message into a structured advisory."""
    flags: list[tuple[FlagKind, dict[str, object]]] = []

    # ─── PDF extraction ─────────────────────────────────────────────────────
    results: list[AttachmentResult] = []
    doc: SectionedDocument | None = None
    pdf_text = ""
    pdf_tables: list[list[list[str | None]]] = []

    for att in message.attachments:
        if not att.is_pdf:
            results.append(AttachmentResult(attachment=att))
            continue
        if not extract_pdfs:
            results.append(AttachmentResult(attachment=att))
            continue
        extraction = extract_pdf(att.data)
        results.append(AttachmentResult(attachment=att, extraction=extraction))
        if extraction.ok:
            pdf_text = f"{pdf_text}\n{extraction.text}" if pdf_text else extraction.text
            pdf_tables.extend(extraction.tables)
        else:
            kind = (
                FlagKind.NO_TEXT_LAYER
                if extraction.error and extraction.error.startswith("NO_TEXT_LAYER")
                else FlagKind.PDF_PARSE_FAILED
            )
            flags.append((kind, {"filename": att.filename, "error": extraction.error}))

    if pdf_text:
        doc = split_sections(pdf_text)

    # ─── CVEs: union of subject, body, and PDF, with provenance (D-013) ─────
    cves: dict[str, list[str]] = {}
    for source, text in (
        ("SUBJECT", message.subject),
        ("EMAIL_BODY", message.body_text),
        ("PDF", doc.content_text if doc else ""),
    ):
        for cve in extract_cves(text):
            cves.setdefault(cve, []).append(source)

    # ─── CVSS ───────────────────────────────────────────────────────────────
    cvss_text = doc.content_text if doc else message.body_text
    cvss = extract_cvss(cvss_text)

    # ─── IOCs: sidecar > PDF IOC section > regex fallback ───────────────────
    iocs: list[Ioc] = []
    seen_iocs: set[tuple[object, str]] = set()

    for att in message.sidecars:
        for ioc in parse_sidecar(att.filename, att.data):
            if ioc.key() not in seen_iocs:
                seen_iocs.add(ioc.key())
                iocs.append(ioc)
        for r in results:
            if r.attachment is att:
                r.ioc_count = len(iocs)

    if doc:
        for section in (s for s in doc.sections if s.is_ioc):
            found = extract_iocs_from_section(section.body) or extract_iocs_by_regex(section.body)
            for ioc in found:
                if ioc.key() not in seen_iocs:
                    seen_iocs.add(ioc.key())
                    iocs.append(ioc)

    # ─── Products, TTPs, references ─────────────────────────────────────────
    products: list[ProductClaim] = []
    if doc:
        for section in (s for s in doc.sections if s.is_affected_products):
            products.extend(extract_products_from_prose(section.body))
        for table in pdf_tables:
            products.extend(extract_products_from_table(table))

    stated_product = message.fields.get("affected_product") or message.fields.get(
        "affected_products"
    )
    if stated_product and not products:
        products.append(
            ProductClaim(product=stated_product[:200], source_of_claim=ClaimSource.EMAIL_BODY)
        )

    for claim in products:
        claim.parsed_range = parse_version_range(claim.version_expression, claim.fixed_version)

    scan_text = f"{message.subject}\n{doc.content_text if doc else message.body_text}"
    ttps = extract_ttps(scan_text)
    reference_urls = extract_reference_urls(doc) if doc else []

    # ─── Cross-validation (docs/ingestion.md §10) ───────────────────────────
    email_severity = parse_severity(message.fields.get("risk_level"))
    pdf_severity = _cover_severity(pdf_text)
    if email_severity and pdf_severity and email_severity is not pdf_severity:
        flags.append(
            (
                FlagKind.SEVERITY_MISMATCH,
                {"email_risk_level": email_severity.value, "pdf_severity": pdf_severity.value},
            )
        )
    severity = higher_severity(email_severity, pdf_severity)

    external_ref = message.external_ref
    pdf_ref = _pdf_advisory_number(pdf_text)
    if external_ref and pdf_ref and pdf_ref != external_ref:
        # Trust the subject: it is the routing key. See D-019.
        flags.append((FlagKind.REF_MISMATCH, {"subject_ref": external_ref, "pdf_ref": pdf_ref}))

    # ─── Classification ─────────────────────────────────────────────────────
    regulator_type = message.fields.get("type")
    classification: Classification = classify(
        title=message.title,
        doc=doc,
        cve_count=len(cves),
        ioc_count=len(iocs),
        has_cvss_vector=any(f.vector for f in cvss),
        regulator_type=regulator_type,
        body_text=message.body_text,
    )
    if classification.is_low_confidence:
        flags.append(
            (
                FlagKind.LOW_TYPE_CONFIDENCE,
                {
                    "type": classification.type.value,
                    "confidence": str(classification.confidence),
                    "signals": classification.signals,
                },
            )
        )
    if not cves and classification.type is AdvisoryType.CVE_ADVISORY:
        flags.append((FlagKind.NO_CVE_FOUND, {"type": classification.type.value}))

    # ─── Description and body ───────────────────────────────────────────────
    description = _pick_description(message, doc)
    body_parts = [message.body_text]
    if doc:
        body_parts.append(doc.content_text)
    body_text = "\n\n".join(p for p in body_parts if p and p.strip())

    return ParsedAdvisory(
        message=message,
        external_ref=external_ref,
        title=message.title,
        description=description,
        body_text=body_text,
        type=classification.type,
        type_confidence=classification.confidence,
        classification_signals=classification.signals,
        source_type_raw=regulator_type,
        severity=severity,
        priority=priority_for(severity),
        cvss_score=highest_cvss(cvss),
        published_at=_pdf_published_on(pdf_text),
        detected_on=parse_advisory_date(message.fields.get("detected_on")),
        upstream_reference=(message.fields.get("reference") or None),
        title_fingerprint=title_fingerprint(message.title),
        cves=cves,
        cvss=cvss,
        iocs=iocs,
        ttps=ttps,
        products=products,
        reference_urls=reference_urls,
        attachments=results,
        flags=flags,
        sections=doc.headings() if doc else [],
    )


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _cover_severity(pdf_text: str) -> Severity | None:
    if not pdf_text:
        return None
    m = patterns.COVER_SEVERITY.search(pdf_text)
    return severity_from_text(m.group("value")) if m else None


def _pdf_advisory_number(pdf_text: str) -> str | None:
    if not pdf_text:
        return None
    m = patterns.ADVISORY_NUMBER.search(pdf_text)
    return f"{m.group('prefix').upper()}-{m.group('number')}" if m else None


def _pdf_published_on(pdf_text: str) -> datetime | None:
    if not pdf_text:
        return None
    m = patterns.PUBLISHED_ON.search(pdf_text)
    if not m:
        return None
    parsed = parse_advisory_date(m.group("value").replace(" ", ""))
    if parsed is None:
        return None
    from datetime import UTC, time

    return datetime.combine(parsed, time.min, tzinfo=UTC)


def _pick_description(message: ParsedMessage, doc: SectionedDocument | None) -> str | None:
    """Prefer the PDF OVERVIEW (present 135/135); fall back to the email."""
    if doc:
        overview = doc.get("OVERVIEW")
        if overview and overview.body.strip():
            return _tidy(overview.body)
    stated = message.fields.get("description")
    return _tidy(stated) if stated else None


def _tidy(text: str, limit: int = 2000) -> str:
    import re

    out = re.sub(r"\s+", " ", text).strip()
    return out[:limit].rsplit(" ", 1)[0] + "…" if len(out) > limit else out
