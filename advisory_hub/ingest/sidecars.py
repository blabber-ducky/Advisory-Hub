"""Parse structured IOC sidecars (``.csv`` / ``.xlsx``).

The highest-confidence IOC source: the regulator attaches a spreadsheet with an
``Indicator,Type[,Description]`` header, already defanged. Preferred over
scraping the PDF — see docs/ingestion.md §8.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile

# defusedxml, not the stdlib: this XML arrives as an email attachment from
# outside the organisation, so entity expansion and XXE are in scope.
from defusedxml.ElementTree import fromstring as _xml_fromstring

from .extractors import Ioc, make_ioc

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def parse_sidecar(filename: str, data: bytes) -> list[Ioc]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix == "csv":
        return _from_rows(_read_csv(data), source="CSV_SIDECAR")
    if suffix in {"xlsx", "xlsm"}:
        return _from_rows(_read_xlsx(data), source="XLSX_SIDECAR")
    return []


def _read_csv(data: bytes) -> list[list[str]]:
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return []
    return [row for row in csv.reader(io.StringIO(text)) if any(c.strip() for c in row)]


def _read_xlsx(data: bytes) -> list[list[str]]:
    """Minimal XLSX reader — avoids adding openpyxl for two files a month."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return []

    shared: list[str] = []
    if "xl/sharedStrings.xml" in archive.namelist():
        root = _xml_fromstring(archive.read("xl/sharedStrings.xml"))
        for si in root.findall("m:si", _NS):
            shared.append("".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t")))

    sheets = [n for n in archive.namelist() if n.startswith("xl/worksheets/sheet")]
    if not sheets:
        return []

    root = _xml_fromstring(archive.read(sorted(sheets)[0]))
    rows: list[list[str]] = []
    for row in root.iter(f"{{{_NS['m']}}}row"):
        cells: list[str] = []
        for cell in row.iter(f"{{{_NS['m']}}}c"):
            value_el = cell.find("m:v", _NS)
            raw = value_el.text if value_el is not None else None
            if raw is None:
                inline = cell.find("m:is", _NS)
                raw = (
                    "".join(t.text or "" for t in inline.iter(f"{{{_NS['m']}}}t"))
                    if inline is not None
                    else ""
                )
            elif cell.get("t") == "s":
                idx = int(raw)
                raw = shared[idx] if 0 <= idx < len(shared) else ""
            cells.append((raw or "").strip())
        if any(cells):
            rows.append(cells)
    return rows


def _from_rows(rows: list[list[str]], *, source: str) -> list[Ioc]:
    if not rows:
        return []

    header_idx = _find_header(rows)
    if header_idx is None:
        return []

    header = [c.strip().lower() for c in rows[header_idx]]
    ind_col = _column(header, ("indicator", "ioc", "value"))
    type_col = _column(header, ("indicator type", "type"))
    desc_col = _column(header, ("description", "notes", "comment"))
    if ind_col is None or type_col is None:
        return []

    out: list[Ioc] = []
    seen: set[tuple[object, str]] = set()
    last_type = ""
    for row in rows[header_idx + 1 :]:
        value = row[ind_col].strip() if ind_col < len(row) else ""
        if not value or value.lower() in {"source", "indicator"}:
            continue
        raw_type = row[type_col].strip() if type_col < len(row) else ""
        # Spreadsheets often leave the type blank for runs of the same kind.
        last_type = raw_type or last_type
        context = row[desc_col].strip() if desc_col is not None and desc_col < len(row) else None
        ioc = make_ioc(value, last_type, source=source, context=context or None)
        if ioc and ioc.key() not in seen:
            seen.add(ioc.key())
            out.append(ioc)
    return out


def _find_header(rows: list[list[str]]) -> int | None:
    for i, row in enumerate(rows[:5]):
        joined = ",".join(c.strip().lower() for c in row)
        if re.search(r"\bindicator\b", joined) and re.search(r"\btype\b", joined):
            return i
    return None


def _column(header: list[str], needles: tuple[str, ...]) -> int | None:
    for needle in needles:
        for i, h in enumerate(header):
            if h == needle:
                return i
    for needle in needles:
        for i, h in enumerate(header):
            if needle in h:
                return i
    return None
