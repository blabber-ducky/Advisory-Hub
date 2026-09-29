"""Split a PDF's text into its labelled sections.

The regulator's template is fixed: OVERVIEW, TECHNICAL DETAILS, RECOMMENDATIONS,
REFERENCES, PLEASE NOTE, and ACTION appear in 132-135 of the 135 corpus PDFs.
Every extractor is scoped to a section — a document-wide URL regex returns 216
hits across the corpus, almost all of them REFERENCES citations rather than
indicators. See D-016.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import patterns


@dataclass(slots=True)
class Section:
    heading: str
    body: str
    start: int

    @property
    def is_affected_products(self) -> bool:
        return bool(patterns.AFFECTED_HEADING.match(self.heading))

    @property
    def is_ioc(self) -> bool:
        return bool(patterns.IOC_HEADING.match(self.heading))

    @property
    def is_references(self) -> bool:
        return bool(patterns.REFERENCES_HEADING.match(self.heading))

    @property
    def is_campaign(self) -> bool:
        return bool(patterns.CAMPAIGN_HEADING.match(self.heading))

    @property
    def is_boilerplate(self) -> bool:
        return bool(patterns.BOILERPLATE_HEADING.match(self.heading))


@dataclass(slots=True)
class SectionedDocument:
    sections: list[Section] = field(default_factory=list)
    preamble: str = ""

    def get(self, *names: str) -> Section | None:
        wanted = {n.upper() for n in names}
        for s in self.sections:
            if s.heading.upper() in wanted:
                return s
        return None

    def find(self, predicate: str) -> list[Section]:
        return [s for s in self.sections if getattr(s, predicate)]

    def headings(self) -> list[str]:
        return [s.heading for s in self.sections]

    @property
    def content_text(self) -> str:
        """Everything except boilerplate — what goes into search and CVE scan."""
        parts = [self.preamble] if self.preamble.strip() else []
        parts.extend(s.body for s in self.sections if not s.is_boilerplate)
        return "\n".join(p for p in parts if p.strip())


def strip_page_furniture(text: str) -> str:
    """Remove the repeating page header, classification banner, and Arabic runs.

    The ``Advisory Number: … Published on: …`` header repeats on every page; left
    in, it double-counts in every extractor. Arabic is bilingual boilerplate that
    pdfplumber emits in reversed logical order — excluded rather than reordered.
    """
    out = patterns.PAGE_HEADER.sub("", text)
    out = patterns.CLASSIFICATION.sub("", out)
    kept = [ln for ln in out.splitlines() if not _is_mostly_arabic(ln)]
    return "\n".join(kept)


def _is_mostly_arabic(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    arabic = len(patterns.ARABIC.findall(stripped))
    return arabic > 0 and arabic / max(len(stripped.replace(" ", "")), 1) > 0.3


def split_sections(text: str) -> SectionedDocument:
    """Split on ALL-CAPS headings that sit alone on a line."""
    cleaned = strip_page_furniture(text)
    marks: list[tuple[int, int, str]] = []
    for m in patterns.SECTION_HEADING.finditer(cleaned):
        heading = m.group(1).strip().rstrip(":").strip()
        if _is_plausible_heading(heading):
            marks.append((m.start(), m.end(), heading))

    if not marks:
        return SectionedDocument(preamble=cleaned.strip())

    doc = SectionedDocument(preamble=cleaned[: marks[0][0]].strip())
    for i, (start, end, heading) in enumerate(marks):
        stop = marks[i + 1][0] if i + 1 < len(marks) else len(cleaned)
        doc.sections.append(Section(heading=heading, body=cleaned[end:stop].strip(), start=start))
    return doc


def _is_plausible_heading(heading: str) -> bool:
    """Reject ALL-CAPS lines that are really content.

    The corpus has titles like ``MICROSOFT SHAREPOINT SERVER CRITICAL
    DESERIALIZATION REMOTE CODE EXECUTION`` on the cover page, and IOC values in
    caps. A heading is short, has few words, and is not a bare identifier.
    """
    if not (3 <= len(heading) <= 60):
        return False
    words = heading.split()
    if len(words) > 6:
        return False
    if heading.replace("-", "").replace(".", "").isdigit():
        return False
    # Hex-looking runs are hashes, not headings.
    return not (len(words) == 1 and len(heading) >= 32)
