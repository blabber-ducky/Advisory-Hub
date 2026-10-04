"""Minimal, defensive XLSX reader — every sheet, cells in their real columns.

Why not ``ingest.sidecars._read_xlsx``: that reader only looks at the first
sheet and appends cells in document order, so a blank cell (which XLSX
simply omits) shifts every later value one column left. The tracker has
several month sheets and plenty of blank cells, so cells are placed by their
``r="C5"`` reference here instead.

Why not openpyxl: the upload is user-supplied, and the project already
parses XLSX with ``defusedxml`` (XXE / entity-expansion safe, CLAUDE.md
§2.3) rather than taking on a large dependency. Archive members are size-
checked *before* decompression, so a zip bomb is rejected, not inflated.
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import fromstring as _xml_fromstring

_NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
}
_M = "{" + _NS["m"] + "}"

#: Per-member and whole-archive decompressed size caps. A real tracker is
#: well under 1 MB uncompressed; these leave two orders of magnitude spare.
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_ROWS_PER_SHEET = 20_000
MAX_COLUMNS = 200

_CELL_REF = re.compile(r"^([A-Z]{1,3})(\d+)$")


class XlsxError(Exception):
    """The file isn't a readable, sane XLSX workbook."""


@dataclass(slots=True)
class Sheet:
    name: str
    #: Rows as lists of strings, cells at their real column index; blank
    #: cells are "". Trailing fully-blank rows are dropped.
    rows: list[list[str]] = field(default_factory=list)


@dataclass(slots=True)
class Workbook:
    sheets: list[Sheet]
    #: Workbook uses the 1904 date system (old Mac Excel) — needed to turn
    #: a date serial into a date correctly.
    date1904: bool = False


def read_workbook(data: bytes) -> Workbook:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise XlsxError("Not an XLSX file (not a zip archive)") from exc

    _check_sizes(archive)
    names = set(archive.namelist())
    if "xl/workbook.xml" not in names:
        raise XlsxError("Not an XLSX workbook (no xl/workbook.xml)")

    workbook_xml = _parse(archive, "xl/workbook.xml")
    pr = workbook_xml.find("m:workbookPr", _NS)
    date1904 = pr is not None and pr.get("date1904") in {"1", "true"}

    shared = _shared_strings(archive) if "xl/sharedStrings.xml" in names else []
    targets = _sheet_targets(archive) if "xl/_rels/workbook.xml.rels" in names else {}

    sheets: list[Sheet] = []
    sheets_el = workbook_xml.find("m:sheets", _NS)
    for sheet_el in sheets_el if sheets_el is not None else []:
        name = sheet_el.get("name") or "Sheet"
        rid = sheet_el.get(f"{{{_NS['r']}}}id")
        path = targets.get(rid or "")
        if path is None or path not in names:
            continue
        sheets.append(Sheet(name=name, rows=_sheet_rows(_parse(archive, path), shared)))
    return Workbook(sheets=sheets, date1904=date1904)


def _check_sizes(archive: zipfile.ZipFile) -> None:
    total = 0
    for info in archive.infolist():
        if info.file_size > MAX_MEMBER_BYTES:
            raise XlsxError(f"Workbook member {info.filename} is too large")
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise XlsxError("Workbook is compressed suspiciously well (possible zip bomb)")
        total += info.file_size
    if total > MAX_TOTAL_BYTES:
        raise XlsxError("Workbook is too large once decompressed")


def _parse(archive: zipfile.ZipFile, name: str) -> Element:
    try:
        root: Element = _xml_fromstring(archive.read(name))
    except Exception as exc:  # defusedxml raises several distinct types
        raise XlsxError(f"Unreadable workbook part {name}") from exc
    return root


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    out: list[str] = []
    for si in _parse(archive, "xl/sharedStrings.xml").findall("m:si", _NS):
        # Plain <t>, or rich-text runs <r><t>. Phonetic hints (<rPh>) are
        # deliberately skipped — they aren't part of the visible text.
        parts = [t.text or "" for t in si.findall("m:t", _NS)]
        parts += [t.text or "" for t in si.findall("m:r/m:t", _NS)]
        out.append("".join(parts))
    return out


def _sheet_targets(archive: zipfile.ZipFile) -> dict[str, str]:
    targets: dict[str, str] = {}
    for rel in _parse(archive, "xl/_rels/workbook.xml.rels").findall("rel:Relationship", _NS):
        rid, target = rel.get("Id"), rel.get("Target")
        if not rid or not target:
            continue
        path = target.lstrip("/") if target.startswith("/") else posixpath.join("xl", target)
        targets[rid] = posixpath.normpath(path)
    return targets


def _column_index(letters: str) -> int:
    index = 0
    for ch in letters:
        index = index * 26 + (ord(ch) - ord("A") + 1)
    return index - 1


def _cell_text(cell: Element, shared: list[str]) -> str:
    kind = cell.get("t")
    if kind == "inlineStr":
        inline = cell.find("m:is", _NS)
        return "".join(t.text or "" for t in inline.iter(f"{_M}t")) if inline is not None else ""
    value_el = cell.find("m:v", _NS)
    raw = (value_el.text or "") if value_el is not None else ""
    if kind == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError):
            return ""
    if kind == "b":
        return "TRUE" if raw == "1" else "FALSE"
    if kind in {None, "n"} and raw:
        # Integers stored as floats ("940435.0") read back as integers.
        try:
            number = float(raw)
        except ValueError:
            return raw
        return str(int(number)) if number.is_integer() else raw
    return raw  # "str" (formula result), "e" (error), or empty


def _sheet_rows(root: Element, shared: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row_el in root.iter(f"{_M}row"):
        try:
            row_number = int(row_el.get("r") or len(rows) + 1)
        except ValueError:
            row_number = len(rows) + 1
        if row_number > MAX_ROWS_PER_SHEET:
            raise XlsxError(f"Sheet has more than {MAX_ROWS_PER_SHEET} rows")
        cells: dict[int, str] = {}
        next_col = 0
        for cell in row_el.findall("m:c", _NS):
            match = _CELL_REF.match(cell.get("r") or "")
            col = _column_index(match.group(1)) if match else next_col
            next_col = col + 1
            if col >= MAX_COLUMNS:
                continue
            cells[col] = _cell_text(cell, shared).strip()
        while len(rows) < row_number - 1:  # rows XLSX omitted entirely
            rows.append([])
        width = max(cells) + 1 if cells else 0
        rows.append([cells.get(i, "") for i in range(width)])
    while rows and not any(rows[-1]):
        rows.pop()
    return rows
