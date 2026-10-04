"""Manual-tracker import: the XLSX reader, status inference, conversion to
CSV, and the preview/apply service + web routes.

Workbooks are built synthetically in-test (``_xlsx``) but shaped like the
real tracker: several month sheets with different column sets, sparse
cells, Excel date serials alongside typed dates, and a formula-only Summary
sheet. The real tracker is internal and is never committed.
"""

from __future__ import annotations

import io
import uuid
import zipfile
from datetime import UTC, date, datetime, timedelta
from typing import Any
from xml.sax.saxutils import escape

import pytest
from sqlalchemy import func, select

from advisory_hub.core.models.enums import (
    SLA_HOURS,
    AdvisoryStatus,
    AdvisoryType,
    Priority,
    Severity,
)
from advisory_hub.core.services import tracker_import as svc
from advisory_hub.manual_tracker.parse import TrackerFormatError, rows_from_workbook
from advisory_hub.manual_tracker.xlsx import XlsxError, read_workbook

S = AdvisoryStatus

# ─── Synthetic workbook builder ──────────────────────────────────────────────

_MONTH_HEADERS = [
    "Received Date",
    "Advisory No.",
    "Security Advisory Subject",
    "Sender",
    "MCME Owner",
    "Action Taken by MCME Infosec",
    "Comments",
]


def _col(index: int) -> str:
    out = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def _xlsx(sheets: dict[str, list[list[Any]]], *, date1904: bool = False) -> bytes:
    """Strings go to sharedStrings, numbers stay numeric; ``None`` cells are
    omitted entirely, exactly like Excel does."""
    shared: list[str] = []
    sheet_xml: list[str] = []
    for rows in sheets.values():
        out = []
        for r, row in enumerate(rows, start=1):
            cells = []
            for c, value in enumerate(row):
                ref = f"{_col(c)}{r}"
                if value is None:
                    continue
                if isinstance(value, (int, float)):
                    cells.append(f'<c r="{ref}"><v>{value}</v></c>')
                else:
                    shared.append(str(value))
                    cells.append(f'<c r="{ref}" t="s"><v>{len(shared) - 1}</v></c>')
            out.append(f'<row r="{r}">{"".join(cells)}</row>')
        sheet_xml.append(
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f"<sheetData>{''.join(out)}</sheetData></worksheet>"
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        sheets_el = "".join(
            f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
            for i, name in enumerate(sheets, start=1)
        )
        z.writestr(
            "xl/workbook.xml",
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            + ('<workbookPr date1904="1"/>' if date1904 else "")
            + f"<sheets>{sheets_el}</sheets></workbook>",
        )
        rels = "".join(
            f'<Relationship Id="rId{i}" Target="worksheets/sheet{i}.xml" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>'
            for i in range(1, len(sheets) + 1)
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{rels}</Relationships>",
        )
        sst = "".join(f"<si><t>{escape(s)}</t></si>" for s in shared)
        z.writestr(
            "xl/sharedStrings.xml",
            f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">{sst}</sst>',
        )
        for i, xml in enumerate(sheet_xml, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", xml)
    return buf.getvalue()


def _tracker() -> bytes:
    """Three months, shaped like the real file. 46235 = 2026-08-01."""
    return _xlsx(
        {
            "Summary": [["Security Advisories Tracker"], [], [], ["Month", "Total Advisories"]],
            "July 2026": [
                _MONTH_HEADERS[:6],  # July has no Comments column
                ["10-Jul-2026", "DOH-1001", "Cisco thing", "DoH", "Network Team", "Not Applicable"],
                [
                    "14-Jul-2026",
                    "DOH-1002",
                    "Langflow",
                    "DoH",
                    "Systems Team",
                    "Assessment required",
                ],
            ],
            "August 2026": [
                _MONTH_HEADERS,
                [
                    46235,
                    "DOH-1003",
                    "VMware",
                    "DoH",
                    "Systems Team",
                    "Ticket raised : 111",
                    "Compensating control for vcenter",
                ],
                # Sender and action blank: cells omitted, columns must not shift.
                [46236, "DOH-1004", "Blank action", None, "Systems Team", None, None],
            ],
            "September 2026": [
                # Different column order, and no Sender column at all.
                [
                    "Advisory No.",
                    "Received Date",
                    "Security Advisory Subject",
                    "Action Taken by MCME Infosec",
                    "MCME Owner",
                    "Comments",
                ],
                [
                    "DOH-1005",
                    46266,
                    "Chrome",
                    "Ticket Raised : 222",
                    "Systems Team",
                    "Closed with comments that automation Job in place",
                ],
                [
                    "DOH-1006",
                    46267,
                    "Unknown",
                    "Pending response from someone",
                    "Systems Team",
                    None,
                ],
            ],
            "Pending Actions": [["September — Pending"], [], [], ["Owner", "Pending"]],
        }
    )


# ─── XLSX reader ─────────────────────────────────────────────────────────────


class TestXlsxReader:
    def test_reads_every_sheet_by_name(self) -> None:
        wb = read_workbook(_tracker())
        assert [s.name for s in wb.sheets] == [
            "Summary",
            "July 2026",
            "August 2026",
            "September 2026",
            "Pending Actions",
        ]

    def test_omitted_cells_keep_later_columns_in_place(self) -> None:
        wb = read_workbook(_tracker())
        august = next(s for s in wb.sheets if s.name == "August 2026")
        blank_row = august.rows[2]
        assert blank_row[1] == "DOH-1004"
        assert blank_row[3] == ""  # Sender omitted
        assert blank_row[4] == "Systems Team"  # still under MCME Owner

    def test_integer_numbers_read_back_as_integers(self) -> None:
        wb = read_workbook(_xlsx({"S": [["a"], [940435.0]]}))
        assert wb.sheets[0].rows[1] == ["940435"]

    def test_not_a_zip_is_rejected(self) -> None:
        with pytest.raises(XlsxError):
            read_workbook(b"just text")

    def test_zip_without_workbook_is_rejected(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", "x")
        with pytest.raises(XlsxError, match="workbook"):
            read_workbook(buf.getvalue())

    def test_decompression_bomb_is_rejected_before_inflating(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("xl/workbook.xml", "<workbook/>")
            z.writestr("xl/worksheets/sheet1.xml", "0" * 5_000_000)
        with pytest.raises(XlsxError, match="zip bomb"):
            read_workbook(buf.getvalue())

    def test_external_entities_are_refused(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "xl/workbook.xml",
                '<?xml version="1.0"?><!DOCTYPE w [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                "<workbook>&x;</workbook>",
            )
        with pytest.raises(XlsxError):
            read_workbook(buf.getvalue())


# ─── Row parsing ─────────────────────────────────────────────────────────────


class TestRowsFromWorkbook:
    def test_month_sheets_only_and_all_rows(self) -> None:
        rows = rows_from_workbook(read_workbook(_tracker()))
        assert [r.ref for r in rows] == [f"DOH-100{i}" for i in range(1, 7)]
        assert {r.sheet for r in rows} == {"July 2026", "August 2026", "September 2026"}

    def test_columns_matched_by_header_not_position(self) -> None:
        rows = {r.ref: r for r in rows_from_workbook(read_workbook(_tracker()))}
        sept = rows["DOH-1005"]
        assert sept.owner == "Systems Team"
        assert sept.action == "Ticket Raised : 222"
        assert sept.notes.startswith("Closed with comments")

    def test_dates_from_typed_text_and_excel_serials(self) -> None:
        rows = {r.ref: r for r in rows_from_workbook(read_workbook(_tracker()))}
        assert rows["DOH-1001"].received == date(2026, 7, 10)
        assert rows["DOH-1003"].received == date(2026, 8, 1)
        assert rows["DOH-1005"].received == date(2026, 9, 1)

    def test_1904_date_system(self) -> None:
        data = _xlsx(
            {"M": [["Advisory No.", "Received Date", "Action Taken"], ["DOH-1", 0, "x"]]},
            date1904=True,
        )
        assert rows_from_workbook(read_workbook(data))[0].received is None  # 0 is out of range
        data = _xlsx(
            {"M": [["Advisory No.", "Received Date", "Action Taken"], ["DOH-1", 1, "x"]]},
            date1904=True,
        )
        assert rows_from_workbook(read_workbook(data))[0].received == date(1904, 1, 2)

    def test_source_names_sheet_and_spreadsheet_row(self) -> None:
        rows = {r.ref: r for r in rows_from_workbook(read_workbook(_tracker()))}
        assert rows["DOH-1003"].source == "August 2026 row 2"

    def test_workbook_without_a_tracker_sheet_is_rejected(self) -> None:
        with pytest.raises(TrackerFormatError):
            rows_from_workbook(read_workbook(_xlsx({"Other": [["a", "b"], ["1", "2"]]})))


# ─── Status inference ────────────────────────────────────────────────────────


class TestInferStatus:
    @pytest.mark.parametrize(
        ("action", "notes", "expected"),
        [
            # Every phrasing the real tracker used (ticket numbers changed).
            ("Not Applicable", "", S.NOT_APPLICABLE),
            ("General Information", "", S.NOT_APPLICABLE),
            ("Generic advisory", "", S.NOT_APPLICABLE),
            ("Duplicate of DOH-2026599", "", S.NOT_APPLICABLE),
            ("Assessment required", "", S.TRIAGED),
            ("Need to raise ticket", "", S.TRIAGED),
            ("Need more informaiton", "", S.TRIAGED),  # sic
            ("Need more information", "", S.TRIAGED),
            ("Bulk Vulnerabilities", "", S.TRIAGED),
            ("Ticket raised : 111", "", S.IN_PROGRESS),
            ("Ticket raised :222", "", S.IN_PROGRESS),
            ("Ticket raised : 333, In progress", "", S.IN_PROGRESS),
            ("Hash Blocked : 444", "", S.REMEDIATED),
            ("Blocked Hashes", "", S.REMEDIATED),
            ("Auto Patching is in Place", "", S.REMEDIATED),
            ("Automatic Patching update policy is in Place", "", S.REMEDIATED),
            ("No Blocking mechanisom available", "", S.RISK_ACCEPTED),  # sic
            ("Raised as a risk already", "", S.RISK_ACCEPTED),
        ],
    )
    def test_real_phrasings(self, action: str, notes: str, expected: AdvisoryStatus) -> None:
        assert svc.infer_status(action, notes)[0] is expected

    @pytest.mark.parametrize(
        ("action", "notes", "expected"),
        [
            # Comments verdict outranks the action that's also present.
            ("Ticket raised : 1", "Resolved and Fixed", S.REMEDIATED),
            (
                "Ticket raised : 1",
                "Closed with comments that automation Job in place",
                S.REMEDIATED,
            ),
            # Specific wording before the general "ticket raised" it contains.
            (
                "Ticket raised : 1, closed with IT recommendations "
                "will upgrade after stable version",
                "",
                S.AWAITING_VENDOR,
            ),
            # A duplicate is not applicable even if it also mentions patching.
            ("Duplicate of DOH-1, Autopatching in place", "", S.NOT_APPLICABLE),
            # Partial blocking still counts as the hashes having been blocked.
            (
                "Blocked Hashes, No Blocking mechanisom available for IP and Domain",
                "",
                S.REMEDIATED,
            ),
            # A compensating control alongside a ticket: still in progress.
            ("Ticket raised : 1", "Compensating control for vcenter", S.IN_PROGRESS),
        ],
    )
    def test_rule_order(self, action: str, notes: str, expected: AdvisoryStatus) -> None:
        assert svc.infer_status(action, notes)[0] is expected

    def test_blank_and_unrecognised_change_nothing(self) -> None:
        assert svc.infer_status("", "") == (None, None)
        assert svc.infer_status("Pending response from someone", "") == (None, None)

    def test_reason_names_the_rule(self) -> None:
        assert svc.infer_status("Ticket raised : 1", "")[1] == "Ticket raised"


class TestBuildComment:
    def test_only_unparsed_fields_and_no_blank_lines(self) -> None:
        body = svc.build_comment("August 2026", "Systems Team", "Ticket raised : 1", "")
        assert body.splitlines() == [
            "From manual tracker (August 2026):",
            "Owner: Systems Team",
            "Action taken: Ticket raised : 1",
        ]

    def test_nothing_to_say_is_empty(self) -> None:
        assert svc.build_comment("July 2026", "", "", "") == ""


# ─── Transition paths ────────────────────────────────────────────────────────


class TestTransitionPath:
    def test_remediated_goes_through_the_plain_lifecycle(self) -> None:
        # Shortest path by length alone could pass through AWAITING_VENDOR —
        # history that never happened.
        assert svc.transition_path(S.NEW, S.REMEDIATED) == [S.TRIAGED, S.IN_PROGRESS, S.REMEDIATED]

    def test_meaningful_statuses_are_never_stepping_stones(self) -> None:
        for current in S:
            for target in S:
                path = svc.transition_path(current, target) or []
                for step in path[:-1]:
                    assert step in {S.TRIAGED, S.IN_PROGRESS, S.REMEDIATED}, (current, target)

    def test_every_forward_move_is_reachable(self) -> None:
        for current in S:
            for target in S:
                if svc.STATUS_RANK[target] > svc.STATUS_RANK[current]:
                    assert svc.transition_path(current, target), (current, target)

    def test_never_steps_through_acknowledged(self) -> None:
        assert S.ACKNOWLEDGED not in (svc.transition_path(S.NEW, S.IN_PROGRESS) or [])

    def test_each_step_is_a_legal_transition(self) -> None:
        from advisory_hub.core.models.enums import ALLOWED_TRANSITIONS

        for current in S:
            for target in S:
                prev = current
                for step in svc.transition_path(current, target) or []:
                    assert step in ALLOWED_TRANSITIONS[prev]
                    prev = step


# ─── Conversion to / from CSV ────────────────────────────────────────────────


class TestCsv:
    def test_workbook_converts_and_round_trips(self) -> None:
        entries, problems = svc.entries_from_upload(_tracker(), "t.xlsx")
        assert not problems
        text = svc.entries_to_csv(entries)
        again, _ = svc.entries_from_upload(text.encode(), "t.csv")
        assert [(e.ref, e.status, e.comment) for e in again] == [
            (e.ref, e.status, e.comment) for e in entries
        ]
        assert svc.entries_to_csv(again) == text

    def test_csv_status_accepts_labels_and_blank(self) -> None:
        text = (
            "advisory_ref,status,comment\nDOH-1,In progress,a\nDOH-2,not-applicable,b\nDOH-3,,c\n"
        )
        entries, problems = svc.entries_from_upload(text.encode(), "t.csv")
        assert not problems
        assert [e.status for e in entries] == [S.IN_PROGRESS, S.NOT_APPLICABLE, None]

    def test_unknown_csv_status_is_a_row_problem_not_a_guess(self) -> None:
        entries, problems = svc.entries_from_upload(
            b"advisory_ref,status,comment\nDOH-1,Done,x\n", "t.csv"
        )
        assert entries == []
        assert "Unknown status" in problems[0].message

    def test_csv_missing_columns_is_rejected(self) -> None:
        with pytest.raises(svc.TrackerImportError, match="missing column"):
            svc.entries_from_upload(b"a,b\n1,2\n", "t.csv")

    def test_oversize_upload_is_rejected(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("CSV_MAX_BYTES", "100")
        get_settings.cache_clear()
        try:
            with pytest.raises(svc.TrackerImportError, match="limit"):
                svc.entries_from_upload(b"x" * 101, "t.csv")
        finally:
            get_settings.cache_clear()


# ─── Preview / apply against the database ────────────────────────────────────


@pytest.fixture
def _blob_root(tmp_path, monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("BLOB_ROOT", str(tmp_path / "blobs"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def source(db):
    from advisory_hub.core.models.advisory import Source

    src = Source(name="Test Regulator", short_code="TR", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def actor(db):
    from advisory_hub.core.models.enums import ActorKind
    from advisory_hub.core.models.user import User
    from advisory_hub.core.services.audit import Actor

    user = User(email="analyst@example.invalid", display_name="Analyst", role="ANALYST")
    db.add(user)
    db.flush()
    return Actor(kind=ActorKind.USER, user_id=user.id, label=user.email)


def _advisory(db, source, ref: str, status: AdvisoryStatus = S.NEW, days: int = 0):
    from advisory_hub.core.models.advisory import Advisory

    received = datetime(2026, 8, 1, 12, 0, tzinfo=UTC) + timedelta(days=days)
    ack, resolve = SLA_HOURS[Priority.P2]
    a = Advisory(
        source_id=source.id,
        external_ref=ref,
        type=AdvisoryType.CVE_ADVISORY,
        title=f"Advisory {ref}",
        received_at=received,
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        severity=Severity.HIGH,
        priority=Priority.P2,
        status=status,
        ack_due_at=received + timedelta(hours=ack),
        resolution_due_at=received + timedelta(hours=resolve),
    )
    db.add(a)
    db.flush()
    return a


def _csv(*rows: tuple[str, str, str]) -> bytes:
    lines = ["advisory_ref,status,comment"] + [f'{r},{s},"{c}"' for r, s, c in rows]
    return ("\n".join(lines) + "\n").encode()


@pytest.mark.integration
@pytest.mark.usefixtures("_blob_root")
class TestPreviewAndApply:
    def test_preview_plans_without_changing_anything(self, db, source) -> None:
        from advisory_hub.core.models.advisory import StatusChange

        a = _advisory(db, source, "DOH-1")
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "REMEDIATED", "done")), filename="t.csv"
        )
        [change] = preview.plan.changes
        assert change.outcome is svc.Outcome.UPDATE
        assert change.path == [S.TRIAGED, S.IN_PROGRESS, S.REMEDIATED]
        db.refresh(a)
        assert a.status is S.NEW
        assert db.scalar(select(func.count()).select_from(StatusChange)) == 0

    def test_apply_walks_every_step_through_change_status(self, db, source, actor) -> None:
        from advisory_hub.core.models.advisory import Comment, StatusChange
        from advisory_hub.core.models.user import AuditLog

        a = _advisory(db, source, "DOH-1")
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "REMEDIATED", "Owner: Systems Team")), filename="t.csv"
        )
        result = svc.apply_import(db, blob_id=preview.blob_id, actor=actor)

        db.refresh(a)
        assert a.status is S.REMEDIATED
        assert (result.advisories_updated, result.status_changes, result.comments_added) == (
            1,
            3,
            1,
        )
        steps = db.scalars(
            select(StatusChange)
            .where(StatusChange.advisory_id == a.id)
            .order_by(StatusChange.created_at)
        ).all()
        assert [s.to_status for s in steps] == [S.TRIAGED, S.IN_PROGRESS, S.REMEDIATED]
        assert all(s.actor_id == actor.user_id for s in steps)
        bodies = db.scalars(select(Comment.body).where(Comment.advisory_id == a.id)).all()
        assert "Owner: Systems Team" in bodies  # the tracker comment, once, on the final step
        assert sum("intermediate step" in b for b in bodies) == 2
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "tracker.imported")
            )
            == 1
        )

    def test_reimport_is_a_no_op(self, db, source, actor) -> None:
        from advisory_hub.core.models.advisory import Comment

        a = _advisory(db, source, "DOH-1")
        data = _csv(("DOH-1", "IN_PROGRESS", "Ticket raised : 1"))
        svc.apply_import(
            db,
            blob_id=svc.preview_import(db, file_bytes=data, filename="t.csv").blob_id,
            actor=actor,
        )
        comments_before = db.scalar(
            select(func.count()).select_from(Comment).where(Comment.advisory_id == a.id)
        )

        preview = svc.preview_import(db, file_bytes=data, filename="t.csv")
        assert [c.outcome for c in preview.plan.changes] == [svc.Outcome.UNCHANGED]
        result = svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        assert (result.status_changes, result.comments_added) == (0, 0)
        assert (
            db.scalar(select(func.count()).select_from(Comment).where(Comment.advisory_id == a.id))
            == comments_before
        )

    def test_never_moves_backwards_but_still_adds_the_comment(self, db, source, actor) -> None:
        a = _advisory(db, source, "DOH-1", status=S.CLOSED)
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "TRIAGED", "note")), filename="t.csv"
        )
        [change] = preview.plan.changes
        assert change.outcome is svc.Outcome.KEPT and change.add_comment
        result = svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        db.refresh(a)
        assert a.status is S.CLOSED
        assert (result.kept, result.comments_added, result.status_changes) == (1, 1, 0)

    def test_same_rank_disagreement_keeps_the_tool(self, db, source, actor) -> None:
        a = _advisory(db, source, "DOH-1", status=S.RISK_ACCEPTED)
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "REMEDIATED", "x")), filename="t.csv"
        )
        assert preview.plan.changes[0].outcome is svc.Outcome.KEPT
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        db.refresh(a)
        assert a.status is S.RISK_ACCEPTED

    def test_reissued_advisories_sharing_a_number_are_all_updated(self, db, source, actor) -> None:
        first = _advisory(db, source, "DOH-1")
        reissue = _advisory(db, source, "DOH-1", days=3)
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "NOT_APPLICABLE", "n/a")), filename="t.csv"
        )
        assert len(preview.plan.changes) == 2
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        for a in (first, reissue):
            db.refresh(a)
            assert a.status is S.NOT_APPLICABLE

    def test_unknown_number_is_reported_not_created(self, db, source, actor) -> None:
        from advisory_hub.core.models.advisory import Advisory

        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-404", "TRIAGED", "x")), filename="t.csv"
        )
        assert preview.plan.changes[0].outcome is svc.Outcome.NOT_FOUND
        result = svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        assert result.not_found == 1
        assert db.scalar(select(func.count()).select_from(Advisory)) == 0

    def test_no_status_still_posts_the_comment(self, db, source, actor) -> None:
        from advisory_hub.core.models.advisory import Comment

        a = _advisory(db, source, "DOH-1")
        preview = svc.preview_import(
            db, file_bytes=_csv(("DOH-1", "", "Owner: Network Team")), filename="t.csv"
        )
        assert preview.plan.changes[0].outcome is svc.Outcome.COMMENT_ONLY
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        db.refresh(a)
        assert a.status is S.NEW
        assert db.scalars(select(Comment.body).where(Comment.advisory_id == a.id)).all() == [
            "Owner: Network Team"
        ]

    def test_workbook_upload_end_to_end(self, db, source, actor) -> None:
        a1 = _advisory(db, source, "DOH-1001")
        a3 = _advisory(db, source, "DOH-1003")
        a5 = _advisory(db, source, "DOH-1005")
        a6 = _advisory(db, source, "DOH-1006")
        preview = svc.preview_import(db, file_bytes=_tracker(), filename="tracker.xlsx")
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)
        for a in (a1, a3, a5, a6):
            db.refresh(a)
        assert a1.status is S.NOT_APPLICABLE
        assert a3.status is S.IN_PROGRESS
        assert a5.status is S.REMEDIATED
        assert a6.status is S.NEW  # unrecognised text: comment only

    def test_apply_refuses_a_blob_that_is_not_a_tracker_upload(self, db, actor) -> None:
        from advisory_hub.core.models.advisory import Blob

        blob = Blob(
            sha256="0" * 64, size_bytes=1, content_type="message/rfc822", original_filename="x.eml"
        )
        db.add(blob)
        db.flush()
        with pytest.raises(svc.TrackerBlobNotFoundError):
            svc.apply_import(db, blob_id=blob.id, actor=actor)


# ─── Web routes ──────────────────────────────────────────────────────────────


@pytest.fixture
def web(db, tmp_path, monkeypatch):
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    from fastapi.testclient import TestClient

    from advisory_hub.api.deps import SESSION_COOKIE, db_session, sign
    from advisory_hub.config import get_settings
    from advisory_hub.core.models.user import User
    from advisory_hub.core.services.auth import start_session
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override

    def client_for(role: str) -> TestClient:
        user = User(
            email=f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.invalid",
            display_name=role,
            role=role,
        )
        db.add(user)
        db.flush()
        session = start_session(db, user, ip_address="127.0.0.1", user_agent="test")
        db.flush()
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        return client

    yield client_for
    get_settings.cache_clear()


@pytest.mark.integration
class TestWeb:
    def test_viewer_cannot_open_the_import(self, web) -> None:
        assert web("VIEWER").get("/tracker-import").status_code == 403

    def test_preview_apply_and_csv_download(self, db, web, source) -> None:
        a = _advisory(db, source, "DOH-1003")
        client = web("ANALYST")
        page = client.get("/tracker-import")
        assert page.status_code == 200 and "Import manual tracker" in page.text

        r = client.post(
            "/tracker-import/preview",
            files={"file": ("tracker.xlsx", _tracker(), svc.XLSX_CONTENT_TYPE)},
        )
        assert r.status_code == 200
        assert "DOH-1003" in r.text and "Change status" in r.text
        blob_id = r.text.split('name="blob_id" value="')[1].split('"')[0]

        csv = client.get(f"/tracker-import/{blob_id}/csv")
        assert csv.status_code == 200
        assert csv.headers["content-type"].startswith("text/csv")
        assert csv.content.startswith(b"\xef\xbb\xbfadvisory_ref,")

        applied = client.post("/tracker-import/apply", data={"blob_id": blob_id})
        assert applied.status_code == 303
        assert "updated=1" in applied.headers["location"]
        db.refresh(a)
        assert a.status is S.IN_PROGRESS

    def test_unreadable_upload_shows_an_error_not_a_500(self, web) -> None:
        r = web("ANALYST").post(
            "/tracker-import/preview", files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")}
        )
        assert r.status_code == 200
        assert "missing column" in r.text


# ─── Regressions found while building the status export ──────────────────────


@pytest.mark.integration
@pytest.mark.usefixtures("_blob_root")
class TestImportRegressions:
    def test_acknowledged_without_a_channel_is_a_row_problem_not_a_crash(
        self, db, source, actor
    ) -> None:
        a = _advisory(db, source, "DOH-1")
        data = _csv(("DOH-1", "ACKNOWLEDGED", "acked by phone"))
        preview = svc.preview_import(db, file_bytes=data, filename="t.csv")
        assert any("ack_channel" in p.message for p in preview.plan.problems)
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)  # must not raise
        db.refresh(a)
        assert a.status is S.NEW

    def test_two_rows_for_one_advisory_apply_in_sequence(self, db, source, actor) -> None:
        a = _advisory(db, source, "DOH-1")
        data = _csv(("DOH-1", "TRIAGED", "first"), ("DOH-1", "REMEDIATED", "second"))
        preview = svc.preview_import(db, file_bytes=data, filename="t.csv")
        second = preview.plan.changes[1]
        assert second.current is S.TRIAGED  # planned from where row 1 leaves it
        svc.apply_import(db, blob_id=preview.blob_id, actor=actor)  # must not raise
        db.refresh(a)
        assert a.status is S.REMEDIATED
