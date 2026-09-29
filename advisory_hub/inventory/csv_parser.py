"""CSV inventory parsing: header sniffing, profile-based auto-mapping, and
row-level parsing with per-row error reporting.

Untrusted input — an analyst-uploaded file — but `csv.DictReader` has none
of the XXE/entity-expansion risk XML sidecars do (see `ingest/sidecars.py`,
which needs `defusedxml` for exactly that reason; this doesn't). Still
capped on rows via `settings.csv_max_rows`, checked as parsing proceeds so a
hostile or just enormous file can't run unbounded.

The delimiter is auto-detected, not assumed to be a comma: a real
Lansweeper "web50" export in this project's `Inventory/` sample data uses
semicolons (a common regional CSV convention) — see
docs/inventory-matching.md's "As built" note.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

from ..config import settings
from .csv_profiles import ColumnProfile

#: Rows are either standalone software or an operating system row, detected
#: via `os_indicator` (see `parse_rows()`). Kept as plain strings here —
#: mapping onto `InventoryItemKind` is the caller's job, so this module has
#: no dependency on `core.models`.
KIND_SOFTWARE = "SOFTWARE"
KIND_OPERATING_SYSTEM = "OPERATING_SYSTEM"

#: Canonical mapping keys, in the order a mapping-editor UI would show them.
MAPPING_FIELDS = (
    "product",
    "vendor",
    "version",
    "device_count",
    "os_indicator",
    "os_name",
    "os_version",
)

_CANDIDATE_DELIMITERS = ",;\t|"


class CsvTooLargeError(Exception):
    def __init__(self, max_rows: int) -> None:
        super().__init__(f"CSV has more than {max_rows} data rows")
        self.max_rows = max_rows


class MissingMappingError(Exception):
    """The `product` column — the one field every row needs — isn't mapped."""


@dataclass(slots=True)
class ParsedRow:
    line_number: int
    vendor: str | None
    product: str
    version: str | None
    device_count: int
    kind: str


@dataclass(slots=True)
class RowError:
    line_number: int
    message: str


@dataclass(slots=True)
class CsvParseResult:
    headers: list[str]
    mapping: dict[str, str | None]
    rows: list[ParsedRow]
    errors: list[RowError]
    total_rows: int


def _detect_delimiter(text: str) -> str:
    sample = text[:4096]
    try:
        return csv.Sniffer().sniff(sample, delimiters=_CANDIDATE_DELIMITERS).delimiter
    except csv.Error:
        return ","


def sniff_headers(text: str) -> list[str]:
    reader = csv.reader(io.StringIO(text), delimiter=_detect_delimiter(text))
    try:
        return next(reader)
    except StopIteration:
        return []


def auto_map(headers: list[str], profile: ColumnProfile) -> dict[str, str | None]:
    """Case-insensitive, whitespace-trimmed matching against the profile's
    alias lists. Unmatched fields come back `None` — the analyst fills them
    in on the mapping-preview screen; nothing here guesses."""
    by_lower = {h.strip().lower(): h for h in headers}

    def find(aliases: tuple[str, ...]) -> str | None:
        for alias in aliases:
            hit = by_lower.get(alias.strip().lower())
            if hit is not None:
                return hit
        return None

    return {
        "product": find(profile.product),
        "vendor": find(profile.vendor),
        "version": find(profile.version),
        "device_count": find(profile.device_count),
        "os_indicator": find(profile.os_indicator),
        "os_name": find(profile.os_name),
        "os_version": find(profile.os_version),
    }


def parse_rows(
    text: str, mapping: dict[str, str | None], *, os_indicator_value: str | None = None
) -> CsvParseResult:
    """`os_indicator_value` distinguishes the two OS-row conventions seen in
    real exports: Azure signals an OS row by any non-blank value in
    `os_indicator` and supplies the name/version from separate `os_name`/
    `os_version` columns; Endpoint Central signals it by `os_indicator`
    equalling this exact value (e.g. `"Operating System"`) and reuses the
    regular `product`/`version` columns for the OS's own name/version."""
    product_col = mapping.get("product")
    if not product_col:
        raise MissingMappingError("The 'product' column must be mapped before parsing")

    vendor_col = mapping.get("vendor")
    version_col = mapping.get("version")
    count_col = mapping.get("device_count")
    os_indicator_col = mapping.get("os_indicator")
    os_name_col = mapping.get("os_name")
    os_version_col = mapping.get("os_version")

    reader = csv.DictReader(io.StringIO(text), delimiter=_detect_delimiter(text))
    headers = list(reader.fieldnames or [])
    rows: list[ParsedRow] = []
    errors: list[RowError] = []
    total = 0

    for line_number, raw_row in enumerate(reader, start=2):  # header occupies line 1
        total += 1
        if total > settings.csv_max_rows:
            raise CsvTooLargeError(settings.csv_max_rows)

        raw_indicator = (raw_row.get(os_indicator_col) or "").strip() if os_indicator_col else ""
        if os_indicator_value is not None:
            is_os_row = raw_indicator == os_indicator_value
        else:
            is_os_row = bool(raw_indicator)

        if is_os_row and os_name_col:
            # Separate OS name/version columns (Azure).
            product = (raw_row.get(os_name_col) or "").strip()
            version = (
                (raw_row.get(os_version_col) or "").strip() or None if os_version_col else None
            )
            kind = KIND_OPERATING_SYSTEM
        else:
            # Either plain software, or an OS row that reuses the regular
            # product/version columns (Endpoint Central).
            product = (raw_row.get(product_col) or "").strip()
            version = (raw_row.get(version_col) or "").strip() or None if version_col else None
            kind = KIND_OPERATING_SYSTEM if is_os_row else KIND_SOFTWARE

        if not product:
            errors.append(RowError(line_number, "product is blank"))
            continue

        vendor = ((raw_row.get(vendor_col) or "").strip() or None) if vendor_col else None

        count = 1
        if count_col:
            raw_count = (raw_row.get(count_col) or "").strip()
            if raw_count:
                try:
                    # Tolerates "12.0"-shaped exports without accepting junk.
                    count = int(float(raw_count))
                except ValueError:
                    errors.append(
                        RowError(line_number, f"device_count {raw_count!r} is not a number")
                    )
                    continue
                if count < 0:
                    errors.append(RowError(line_number, "device_count is negative"))
                    continue

        rows.append(ParsedRow(line_number, vendor, product, version, count, kind))

    return CsvParseResult(
        headers=headers, mapping=mapping, rows=rows, errors=errors, total_rows=total
    )
