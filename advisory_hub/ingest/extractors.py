"""Entity extraction.

Everything here produces *evidence*, not truth: each result carries where it
came from, so the UI can present provenance rather than assert a fact
(CLAUDE.md §2.2). Extraction is section-scoped — see D-016.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal

from ..core.models.enums import ClaimSource, IocType, TtpKind
from . import patterns
from .defang import defang, defang_url, refang
from .sections import SectionedDocument
from .version_range import ParsedRange

# ─── CVEs ────────────────────────────────────────────────────────────────────


def extract_cves(text: str) -> list[str]:
    """Return canonical, deduplicated, sorted CVE IDs.

    Tolerates unicode dashes and stray spaces, both of which appear in PDF text
    extraction (``CVE-2026-58319`` with unicode dashes, ``CVE- 2026-1234``).
    """
    found = {f"CVE-{m.group(1)}-{m.group(2)}" for m in patterns.CVE.finditer(text or "")}
    return sorted(found)


# ─── CVSS ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CvssFinding:
    version: str
    score: Decimal | None
    vector: str | None


def extract_cvss(text: str) -> list[CvssFinding]:
    """Extract CVSS findings, preferring the vector over any prose number.

    A vector is machine-generated; a nearby number is what a human typed.
    """
    out: list[CvssFinding] = []
    text = text or ""

    for vec_pattern, score_pattern, version in (
        (patterns.CVSS_VECTOR_V3, patterns.CVSS_SCORE_V3, "3.1"),
        (patterns.CVSS_VECTOR_V4, patterns.CVSS_SCORE_V4, "4.0"),
    ):
        vectors = [m.group(0) for m in vec_pattern.finditer(text)]
        scores = [Decimal(m.group(1)) for m in score_pattern.finditer(text)]
        scores = [s for s in scores if Decimal("0") <= s <= Decimal("10")]

        if vectors:
            out.extend(
                CvssFinding(version, scores[i] if i < len(scores) else None, v)
                for i, v in enumerate(vectors)
            )
        elif scores:
            out.extend(CvssFinding(version, s, None) for s in scores)
    return out


def highest_cvss(findings: list[CvssFinding]) -> Decimal | None:
    scores = [f.score for f in findings if f.score is not None]
    return max(scores) if scores else None


# ─── IOCs ────────────────────────────────────────────────────────────────────

#: The regulator labels every indicator's type — do not infer it. Observed
#: vocabulary across the corpus, normalised to the IocType enum.
_IOC_TYPE_MAP: dict[str, IocType] = {
    "ip address": IocType.IPV4,
    "ip addresses": IocType.IPV4,
    "ipv4": IocType.IPV4,
    "ipv6": IocType.IPV6,
    "domain": IocType.DOMAIN,
    "domains": IocType.DOMAIN,
    "url": IocType.URL,
    "urls": IocType.URL,
    "md5": IocType.MD5,
    "md-5": IocType.MD5,
    "sha1": IocType.SHA1,
    "sha-1": IocType.SHA1,
    "sha256": IocType.SHA256,
    "sha-256": IocType.SHA256,
    "email": IocType.EMAIL,
    "emails": IocType.EMAIL,
    "e-mail": IocType.EMAIL,
    "filename": IocType.FILENAME,
    "file name": IocType.FILENAME,
    "filepath": IocType.FILEPATH,
    "file path": IocType.FILEPATH,
    "mutex": IocType.MUTEX,
    "user agent": IocType.USER_AGENT,
    "user-agent": IocType.USER_AGENT,
}


@dataclass(frozen=True, slots=True)
class Ioc:
    ioc_type: IocType
    value: str
    defanged_value: str
    type_raw: str | None = None
    context: str | None = None
    extraction_source: str = "PDF_TABLE"

    def key(self) -> tuple[IocType, str]:
        return (self.ioc_type, self.value)


def normalise_ioc_type(raw: str) -> tuple[IocType, str | None]:
    """Map a regulator type label onto the enum, keeping the raw label when
    it doesn't map — dropping the row would lose an indicator."""
    key = re.sub(r"\s+", " ", raw or "").strip().lower()
    if key in _IOC_TYPE_MAP:
        return _IOC_TYPE_MAP[key], None
    if key.startswith("registry"):
        return IocType.REGISTRY_KEY, raw.strip()
    if "hash" in key:
        return IocType.SHA256, raw.strip()
    return IocType.OTHER, raw.strip() or None


def make_ioc(
    raw_value: str, raw_type: str, *, source: str, context: str | None = None
) -> Ioc | None:
    """Build an IOC, refanging the value and storing both forms."""
    ioc_type, type_raw = normalise_ioc_type(raw_type)
    value = refang((raw_value or "").strip().strip(",;"))
    if not value or len(value) > 2048:
        return None
    display = defang_url(value) if ioc_type is IocType.URL else defang(value)
    return Ioc(
        ioc_type=ioc_type,
        value=value,
        defanged_value=display,
        type_raw=type_raw,
        context=context,
        extraction_source=source,
    )


def extract_iocs_from_section(section_text: str) -> list[Ioc]:
    """Parse the ``Indicator | Type`` rows of a PDF IOC section.

    The line-oriented form is the primary path: ``extract_tables()`` returns
    padded rows with empty spacer columns, so cell indices are unreliable.
    """
    out: list[Ioc] = []
    seen: set[tuple[IocType, str]] = set()
    for m in patterns.IOC_ROW.finditer(section_text or ""):
        ioc = make_ioc(m.group("value"), m.group("type"), source="PDF_TABLE")
        if ioc and ioc.key() not in seen and not _looks_like_heading(m.group("value")):
            seen.add(ioc.key())
            out.append(ioc)
    return out


def extract_iocs_by_regex(section_text: str) -> list[Ioc]:
    """Fallback for IOC sections whose rows don't carry a type label.

    Only ever run against an IOC section — never the whole document.
    """
    refanged = refang(section_text or "")
    out: list[Ioc] = []
    seen: set[tuple[IocType, str]] = set()

    for pattern, ioc_type in (
        (patterns.SHA256, IocType.SHA256),
        (patterns.SHA1, IocType.SHA1),
        (patterns.MD5, IocType.MD5),
        (patterns.URL, IocType.URL),
        (patterns.IPV4, IocType.IPV4),
        (patterns.EMAIL, IocType.EMAIL),
        (patterns.DOMAIN, IocType.DOMAIN),
    ):
        for m in pattern.finditer(refanged):
            value = m.group(0).rstrip(".,;")
            # A domain inside an already-captured URL is not a separate IOC.
            if ioc_type is IocType.DOMAIN and any(value in v for t, v in seen if t is IocType.URL):
                continue
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            display = defang_url(value) if ioc_type is IocType.URL else defang(value)
            out.append(
                Ioc(
                    ioc_type=ioc_type,
                    value=value,
                    defanged_value=display,
                    extraction_source="REGEX_FALLBACK",
                )
            )
    return out


def _looks_like_heading(value: str) -> bool:
    return value.strip().lower() in {"indicator", "indicators", "value", "ioc", "type"}


# ─── TTPs ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Ttp:
    kind: TtpKind
    value: str


def extract_ttps(text: str) -> list[Ttp]:
    out: dict[tuple[TtpKind, str], Ttp] = {}
    for m in patterns.ATTACK_TECHNIQUE.finditer(text or ""):
        t = Ttp(TtpKind.ATTACK_TECHNIQUE, m.group(0).upper())
        out[(t.kind, t.value)] = t
    for m in patterns.THREAT_ACTOR.finditer(text or ""):
        value = re.sub(r"[-\s]+", "", m.group(0)).upper()
        t = Ttp(TtpKind.THREAT_ACTOR, value)
        out[(t.kind, t.value)] = t
    return sorted(out.values(), key=lambda t: (t.kind.value, t.value))


# ─── Affected products ───────────────────────────────────────────────────────


@dataclass(slots=True)
class ProductClaim:
    product: str
    vendor: str | None = None
    version_expression: str | None = None
    fixed_version: str | None = None
    source_of_claim: ClaimSource = ClaimSource.PDF_TEXT
    parsed_range: ParsedRange | None = field(default=None)


def extract_products_from_table(rows: list[list[str | None]]) -> list[ProductClaim]:
    """Parse an affected-products table.

    ``extract_tables()`` pads rows with empty spacer columns — the corpus
    SharePoint table is 9 columns wide with only 5 real ones — so cells are
    coalesced left-to-right rather than indexed.
    """
    claims: list[ProductClaim] = []
    if not rows:
        return claims

    header = [_clean_cell(c) for c in rows[0]]
    header_text = " ".join(h.lower() for h in header if h)
    if "product" not in header_text:
        return claims

    fixed_idx = _column_index(header, ("fixed", "patch", "remediat"))
    version_idx = _column_index(header, ("affected version", "version", "build"))

    for raw in rows[1:]:
        cells = [_clean_cell(c) for c in raw]
        compact = [c for c in cells if c]
        if not compact:
            continue
        product = compact[0]
        if not product or product.lower() in {"product", "products"}:
            continue
        claims.append(
            ProductClaim(
                product=product,
                version_expression=_cell_at(cells, version_idx)
                or (compact[1] if len(compact) > 1 else None),
                fixed_version=_cell_at(cells, fixed_idx),
                source_of_claim=ClaimSource.PDF_TEXT,
            )
        )
    return claims


def extract_products_from_prose(text: str) -> list[ProductClaim]:
    """Parse prose affected-product statements.

    The corpus form is e.g. *"Check Point Security Management … versions R77.30,
    R80, R80.10, …"* — a product phrase followed by an enumeration.
    """
    claims: list[ProductClaim] = []
    for line in (text or "").splitlines():
        line = line.strip(" •-\t")
        if len(line) < 6 or len(line) > 400:
            continue
        m = patterns.VERSION_RANGE.search(line)
        if m:
            product = line[: m.start()].strip(" ,.:;")
            if product:
                claims.append(
                    ProductClaim(
                        product=product[:200],
                        version_expression=m.group(0)[:400],
                        source_of_claim=ClaimSource.PDF_TEXT,
                    )
                )
    return claims


def _clean_cell(cell: str | None) -> str:
    return re.sub(r"\s+", " ", (cell or "")).strip()


def _column_index(header: list[str], needles: tuple[str, ...]) -> int | None:
    for i, h in enumerate(header):
        low = h.lower()
        if any(n in low for n in needles):
            return i
    return None


def _cell_at(cells: list[str], idx: int | None) -> str | None:
    if idx is None or idx >= len(cells):
        return None
    return cells[idx] or None


# ─── Reference URLs ──────────────────────────────────────────────────────────


def extract_reference_urls(doc: SectionedDocument) -> list[str]:
    """URLs from the REFERENCES section only. These are citations, not IOCs."""
    section = next((s for s in doc.sections if s.is_references), None)
    if section is None:
        return []
    seen: dict[str, None] = {}
    for m in patterns.URL.finditer(refang(section.body)):
        seen.setdefault(m.group(0).rstrip(".,;)"), None)
    return list(seen)
