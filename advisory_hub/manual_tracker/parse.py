"""Manual-tracker rows, from the workbook or from the converted CSV.

Workbook: every sheet whose header row has both an advisory-number column
and an "action taken" column is a month sheet; anything else (the Summary
and Pending Actions roll-ups, which are formulas over the month sheets) is
ignored. Columns are matched by header name, not position — the month
sheets don't share a column order (September dropped three columns).
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from .xlsx import Workbook

#: Normalised header → field. Normalised = lowercase, punctuation and
#: repeated spaces collapsed.
HEADER_ALIASES: dict[str, str] = {
    "advisory no": "ref",
    "advisory number": "ref",
    "advisory ref": "ref",
    "advisory_ref": "ref",
    "received date": "received",
    "received_date": "received",
    "security advisory subject": "subject",
    "subject": "subject",
    "mcme owner": "owner",
    "owner": "owner",
    "action taken by mcme infosec": "action",
    "action taken": "action",
    "comments": "notes",
    "notes": "notes",
}

#: Converted-CSV columns, in order. ``status`` and ``comment`` are what the
#: import acts on; the rest are there so a person editing the file can tell
#: rows apart.
CSV_COLUMNS = ("advisory_ref", "received_date", "subject", "status", "comment", "source")

_HEADER_SCAN_ROWS = 5


@dataclass(slots=True)
class WorkbookRow:
    sheet: str
    row_number: int
    ref: str
    received: date | None
    subject: str
    owner: str
    action: str
    notes: str

    @property
    def source(self) -> str:
        return f"{self.sheet} row {self.row_number}"


@dataclass(slots=True)
class CsvRow:
    line: int
    ref: str
    received: str
    subject: str
    status: str
    comment: str
    source: str


class TrackerFormatError(Exception):
    """The upload doesn't look like the manual tracker or its CSV."""


def _norm_header(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[.:/\\-]+", " ", value.lower())).strip()


def _header_map(row: list[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for index, cell in enumerate(row):
        field = HEADER_ALIASES.get(_norm_header(cell)) or HEADER_ALIASES.get(cell.strip().lower())
        if field and field not in found:
            found[field] = index
    return found


def _excel_date(value: str, *, date1904: bool) -> date | None:
    """A date cell is either an Excel serial ("46235") or text the team
    typed ("10-Jul-2026", "2026-08-01")."""
    text = value.strip()
    if not text:
        return None
    try:
        serial = float(text)
    except ValueError:
        pass
    else:
        if 1 <= serial < 2_958_466:  # Excel's own valid range
            base = date(1904, 1, 1) if date1904 else date(1899, 12, 30)
            return base + timedelta(days=int(serial))
        return None
    for fmt in ("%d-%b-%Y", "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def rows_from_workbook(workbook: Workbook) -> list[WorkbookRow]:
    rows: list[WorkbookRow] = []
    month_sheets = 0
    for sheet in workbook.sheets:
        header_index, columns = None, {}
        for i, candidate in enumerate(sheet.rows[:_HEADER_SCAN_ROWS]):
            columns = _header_map(candidate)
            if "ref" in columns and "action" in columns:
                header_index = i
                break
        if header_index is None:
            continue
        month_sheets += 1

        def cell(values: list[str], field: str, cols: dict[str, int] = columns) -> str:
            index = cols.get(field)
            return values[index].strip() if index is not None and index < len(values) else ""

        for offset, values in enumerate(sheet.rows[header_index + 1 :], start=header_index + 2):
            ref = cell(values, "ref")
            if not ref:
                continue
            rows.append(
                WorkbookRow(
                    sheet=sheet.name,
                    row_number=offset,
                    ref=ref,
                    received=_excel_date(cell(values, "received"), date1904=workbook.date1904),
                    subject=cell(values, "subject"),
                    owner=cell(values, "owner"),
                    action=cell(values, "action"),
                    notes=cell(values, "notes"),
                )
            )
    if month_sheets == 0:
        raise TrackerFormatError(
            "No tracker sheet found — expected a sheet with 'Advisory No.' and "
            "'Action Taken by MCME Infosec' columns."
        )
    return rows


def rows_from_csv(text: str) -> list[CsvRow]:
    reader = csv.DictReader(io.StringIO(text))
    fields = {(name or "").strip().lower() for name in reader.fieldnames or []}
    missing = {"advisory_ref", "status", "comment"} - fields
    if missing:
        raise TrackerFormatError(
            f"Not a converted tracker CSV — missing column(s): {', '.join(sorted(missing))}. "
            f"Expected: {', '.join(CSV_COLUMNS)}."
        )
    out: list[CsvRow] = []
    for line, record in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in record.items()}
        if not row.get("advisory_ref"):
            continue
        out.append(
            CsvRow(
                line=line,
                ref=row["advisory_ref"],
                received=row.get("received_date", ""),
                subject=row.get("subject", ""),
                status=row.get("status", ""),
                comment=row.get("comment", ""),
                source=row.get("source", "") or f"CSV line {line}",
            )
        )
    return out


def write_csv(records: list[dict[str, str]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow({column: record.get(column, "") for column in CSV_COLUMNS})
    return buffer.getvalue()
