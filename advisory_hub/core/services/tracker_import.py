"""Importing the team's manual spreadsheet tracker.

Two halves:

* **Conversion** — the workbook's month sheets become one flat list of
  entries: advisory number, a *proposed* tool status inferred from the
  free-text "Action Taken" / "Comments" columns (``infer_status``), and a
  comment carrying the tracker information the tool doesn't already parse
  (owner, action taken, notes). Exportable as CSV so a person can check and
  correct it before importing.
* **Import** — ``preview_import`` plans what each entry would do to the
  matching advisories without writing anything; ``apply_import`` re-plans
  against current state and executes it in one transaction.

Rules the import keeps (docs/architecture.md §3.3.3, D-042):

* Every status change goes through ``advisories.change_status()``, one
  legal transition at a time, each with its comment — never a direct write.
* It never moves an advisory backwards. If the tool's status is already as
  far along as the tracker's, the tool wins.
* It's idempotent: re-importing the same file changes nothing and adds no
  duplicate comments.
* The inferred status is evidence, not truth: the rule that produced it is
  shown in the preview, and text no rule recognises changes no status.
"""

from __future__ import annotations

import re
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ...manual_tracker import parse
from ...manual_tracker.xlsx import XlsxError, read_workbook
from ..models.advisory import Advisory, Blob, Comment
from ..models.enums import ALLOWED_TRANSITIONS, AdvisoryStatus
from ..storage.blobs import FilesystemBlobStore
from . import advisories as advisories_svc
from .audit import Actor, record

XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
CSV_CONTENT_TYPE = "text/csv"
_ALLOWED_CONTENT_TYPES = {XLSX_CONTENT_TYPE, CSV_CONTENT_TYPE}


class TrackerImportError(Exception):
    """The upload can't be read as a tracker (shown to the user verbatim)."""


class TrackerBlobNotFoundError(Exception):
    def __init__(self, blob_id: uuid.UUID) -> None:
        super().__init__(f"Uploaded tracker {blob_id} not found")
        self.blob_id = blob_id


# ─── Status inference ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StatusRule:
    label: str
    pattern: re.Pattern[str]
    status: AdvisoryStatus


def _rule(label: str, pattern: str, status: AdvisoryStatus) -> StatusRule:
    return StatusRule(label, re.compile(pattern, re.IGNORECASE), status)


#: Checked in order against "<comments> | <action taken>"; the first match
#: wins, so specific wording (a ticket "closed … will upgrade after stable
#: version") is listed before the general pattern it also contains ("ticket
#: raised"), and the Comments column's verdict before the action's.
#: Patterns tolerate the tracker's real spellings ("informaiton",
#: "mechanisom", "Autopatching"). Documented as a table in
#: docs/architecture.md §3.3.3 — keep the two in step.
STATUS_RULES: tuple[StatusRule, ...] = (
    _rule("Resolved / fixed", r"\bresolved\b|\bfixed\b", AdvisoryStatus.REMEDIATED),
    _rule("Closed — automation in place", r"closed\b.*\bautomation", AdvisoryStatus.REMEDIATED),
    _rule("Duplicate of another advisory", r"\bduplicate of\b", AdvisoryStatus.NOT_APPLICABLE),
    _rule(
        "Not applicable / informational",
        r"\bnot applicable\b|\bgeneral information\b|\bgeneric advisory\b",
        AdvisoryStatus.NOT_APPLICABLE,
    ),
    _rule("Raised as a risk", r"raised as (a )?risk|risk accepted", AdvisoryStatus.RISK_ACCEPTED),
    _rule(
        "Waiting for a vendor release",
        r"upgrade after|stable version|awaiting vendor|waiting for vendor",
        AdvisoryStatus.AWAITING_VENDOR,
    ),
    _rule("In progress", r"\bin progress\b", AdvisoryStatus.IN_PROGRESS),
    _rule("Hashes blocked", r"hash(es)? blocked|blocked hash", AdvisoryStatus.REMEDIATED),
    _rule("No blocking mechanism", r"no blocking mechani", AdvisoryStatus.RISK_ACCEPTED),
    _rule(
        "Automatic patching in place",
        r"auto ?patching|automatic patching",
        AdvisoryStatus.REMEDIATED,
    ),
    _rule("Ticket raised", r"ticket raised", AdvisoryStatus.IN_PROGRESS),
    _rule(
        "Needs assessment / information / a ticket",
        r"assessment required|need(s)? (more )?inform|need to raise|bulk vulnerab",
        AdvisoryStatus.TRIAGED,
    ),
)


def infer_status(action: str, notes: str) -> tuple[AdvisoryStatus | None, str | None]:
    """Proposed tool status for a tracker row, and the rule that chose it.
    ``(None, None)`` when nothing recognisable was written — the import then
    adds the comment but leaves the status alone."""
    text = re.sub(r"\s+", " ", f"{notes} | {action}").strip(" |")
    if not text:
        return None, None
    for rule in STATUS_RULES:
        if rule.pattern.search(text):
            return rule.status, rule.label
    return None, None


def build_comment(sheet: str, owner: str, action: str, notes: str) -> str:
    """The tracker information the tool doesn't parse itself. Subject,
    dates, products, CVEs, severity, type, summary and IOCs are all
    extracted from the email and PDF already, so they aren't repeated."""
    lines = [
        f"{label}: {value}"
        for label, value in (("Owner", owner), ("Action taken", action), ("Notes", notes))
        if value
    ]
    if not lines:
        return ""
    return "\n".join([f"From manual tracker ({sheet}):", *lines])


# ─── Entries (the converted, editable form) ──────────────────────────────────


@dataclass(slots=True)
class TrackerEntry:
    ref: str
    status: AdvisoryStatus | None
    comment: str
    source: str
    received: str = ""
    subject: str = ""
    #: Why this status — the matching rule's label, or "Set in CSV".
    reason: str | None = None


@dataclass(slots=True)
class EntryProblem:
    source: str
    message: str


def _parse_status(value: str) -> AdvisoryStatus | None:
    key = re.sub(r"[\s-]+", "_", value.strip()).upper()
    if not key:
        return None
    try:
        return AdvisoryStatus(key)
    except ValueError:
        raise ValueError(
            f"Unknown status {value!r} — use one of "
            + ", ".join(s.value for s in AdvisoryStatus)
            + ", or leave it blank"
        ) from None


def entries_from_upload(
    data: bytes, filename: str
) -> tuple[list[TrackerEntry], list[EntryProblem]]:
    """Workbook or converted CSV → entries. Raises ``TrackerImportError``
    for a file that isn't a tracker at all; per-row issues are returned."""
    if len(data) > settings.csv_max_bytes:
        raise TrackerImportError(
            f"File is {len(data):,} bytes, over the {settings.csv_max_bytes:,}-byte limit"
        )
    problems: list[EntryProblem] = []
    try:
        if data[:2] == b"PK" or filename.lower().endswith(".xlsx"):
            entries = []
            for row in parse.rows_from_workbook(read_workbook(data)):
                status, reason = infer_status(row.action, row.notes)
                entries.append(
                    TrackerEntry(
                        ref=row.ref,
                        status=status,
                        comment=build_comment(row.sheet, row.owner, row.action, row.notes),
                        source=row.source,
                        received=row.received.isoformat() if row.received else "",
                        subject=row.subject,
                        reason=reason,
                    )
                )
            return entries, problems

        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("cp1252")
        entries = []
        for csv_row in parse.rows_from_csv(text):
            try:
                status = _parse_status(csv_row.status)
            except ValueError as exc:
                problems.append(EntryProblem(csv_row.source, str(exc)))
                continue
            entries.append(
                TrackerEntry(
                    ref=csv_row.ref,
                    status=status,
                    comment=csv_row.comment,
                    source=csv_row.source,
                    received=csv_row.received,
                    subject=csv_row.subject,
                    reason="Set in CSV" if status else None,
                )
            )
        return entries, problems
    except (XlsxError, parse.TrackerFormatError) as exc:
        raise TrackerImportError(str(exc)) from exc


def entries_to_csv(entries: list[TrackerEntry]) -> str:
    return parse.write_csv(
        [
            {
                "advisory_ref": e.ref,
                "received_date": e.received,
                "subject": e.subject,
                "status": e.status.value if e.status else "",
                "comment": e.comment,
                "source": e.source,
            }
            for e in entries
        ]
    )


# ─── Planning ────────────────────────────────────────────────────────────────

#: How far along the lifecycle a status is. The import only ever moves an
#: advisory to a *higher* rank; same rank but a different status (say the
#: tool has RISK_ACCEPTED, the tracker says REMEDIATED) is a disagreement,
#: and the tool's own record wins.
STATUS_RANK: dict[AdvisoryStatus, int] = {
    AdvisoryStatus.NEW: 0,
    AdvisoryStatus.ACKNOWLEDGED: 1,
    AdvisoryStatus.TRIAGED: 2,
    AdvisoryStatus.IN_PROGRESS: 3,
    AdvisoryStatus.AWAITING_VENDOR: 3,
    AdvisoryStatus.REMEDIATED: 4,
    AdvisoryStatus.RISK_ACCEPTED: 4,
    AdvisoryStatus.NOT_APPLICABLE: 4,
    AdvisoryStatus.CLOSED: 5,
}


#: Statuses the import may pass *through* on the way to a target. The
#: plain lifecycle only: stepping through AWAITING_VENDOR, RISK_ACCEPTED or
#: NOT_APPLICABLE would write history that never happened ("waited on the
#: vendor") — those are only ever a destination. ACKNOWLEDGED is excluded
#: too: it requires an acknowledgement channel the tracker doesn't record.
_INTERMEDIATE_STATUSES = frozenset(
    {AdvisoryStatus.TRIAGED, AdvisoryStatus.IN_PROGRESS, AdvisoryStatus.REMEDIATED}
)


def transition_path(current: AdvisoryStatus, target: AdvisoryStatus) -> list[AdvisoryStatus] | None:
    """Shortest chain of legal transitions from ``current`` to ``target``
    (excluding ``current``), stepping only through the plain lifecycle —
    e.g. NEW → TRIAGED → IN_PROGRESS → REMEDIATED."""
    if current is target:
        return []
    queue: deque[AdvisoryStatus] = deque([current])
    previous: dict[AdvisoryStatus, AdvisoryStatus] = {}
    while queue:
        node = queue.popleft()
        for nxt in sorted(ALLOWED_TRANSITIONS.get(node, frozenset()), key=lambda s: s.value):
            if nxt in previous or nxt is current:
                continue
            if nxt is not target and nxt not in _INTERMEDIATE_STATUSES:
                continue
            previous[nxt] = node
            if nxt is target:
                path = [nxt]
                while previous[path[-1]] is not current:
                    path.append(previous[path[-1]])
                return path[::-1]
            queue.append(nxt)
    return None


class Outcome(StrEnum):
    UPDATE = "UPDATE"  # status will change (and the comment is posted with it)
    COMMENT_ONLY = "COMMENT_ONLY"  # no status change; tracker comment is new
    UNCHANGED = "UNCHANGED"  # already at the tracker's status, comment already there
    KEPT = "KEPT"  # tool is already as far along or further — tool wins
    NOT_FOUND = "NOT_FOUND"  # no advisory with this number in the tool
    NOTHING = "NOTHING"  # row has no status and no comment


@dataclass(slots=True)
class PlannedChange:
    entry: TrackerEntry
    outcome: Outcome
    advisory_id: uuid.UUID | None = None
    advisory_title: str | None = None
    current: AdvisoryStatus | None = None
    path: list[AdvisoryStatus] = field(default_factory=list)
    add_comment: bool = False
    note: str = ""


@dataclass(slots=True)
class ImportPlan:
    changes: list[PlannedChange]
    problems: list[EntryProblem]

    def count(self, outcome: Outcome) -> int:
        return sum(1 for c in self.changes if c.outcome is outcome)

    @property
    def comments_to_add(self) -> int:
        return sum(1 for c in self.changes if c.add_comment)


def _plan(db: DbSession, entries: list[TrackerEntry], problems: list[EntryProblem]) -> ImportPlan:
    refs = {e.ref for e in entries}
    by_ref: dict[str, list[Advisory]] = {}
    for advisory in db.scalars(select(Advisory).where(Advisory.external_ref.in_(refs))):
        by_ref.setdefault(advisory.external_ref or "", []).append(advisory)

    ids = [a.id for found in by_ref.values() for a in found]
    existing: set[tuple[uuid.UUID, str]] = set()
    if ids:
        for advisory_id, body in db.execute(
            select(Comment.advisory_id, Comment.body).where(Comment.advisory_id.in_(ids))
        ):
            existing.add((advisory_id, body.strip()))

    changes: list[PlannedChange] = []
    for entry in entries:
        matches = sorted(by_ref.get(entry.ref, []), key=lambda a: a.received_at)
        if not matches:
            changes.append(
                PlannedChange(entry, Outcome.NOT_FOUND, note="No advisory with this number")
            )
            continue
        comment = entry.comment.strip()
        for advisory in matches:
            new_comment = bool(comment) and (advisory.id, comment) not in existing
            change = PlannedChange(
                entry,
                Outcome.NOTHING,
                advisory_id=advisory.id,
                advisory_title=advisory.title,
                current=advisory.status,
                add_comment=new_comment,
            )
            target = entry.status
            if target is not None and STATUS_RANK[target] > STATUS_RANK[advisory.status]:
                path = transition_path(advisory.status, target)
                if path:
                    change.outcome, change.path = Outcome.UPDATE, path
                else:  # pragma: no cover — every forward status is reachable today
                    change.outcome = Outcome.KEPT
                    change.note = f"No legal route from {advisory.status.value} to {target.value}"
            elif target is not None and target is not advisory.status:
                change.outcome = Outcome.KEPT
                change.note = (
                    f"Tool already has {advisory.status.value}; tracker says {target.value}"
                )
            elif new_comment:
                change.outcome = Outcome.COMMENT_ONLY
            elif comment or target is not None:
                change.outcome = Outcome.UNCHANGED
            if change.outcome is Outcome.KEPT and new_comment:
                change.note += " — tracker comment will still be added"
            changes.append(change)
            existing.add((advisory.id, comment))  # duplicate rows in one file
    return ImportPlan(changes=changes, problems=problems)


# ─── Preview / apply ─────────────────────────────────────────────────────────


@dataclass(slots=True)
class ImportPreview:
    blob_id: uuid.UUID
    filename: str
    plan: ImportPlan


def _store(db: DbSession, data: bytes, filename: str) -> Blob:
    stored = FilesystemBlobStore(settings.blob_root).put_bytes(data)
    blob = db.scalar(select(Blob).where(Blob.sha256 == stored.sha256))
    if blob is None:
        is_xlsx = data[:2] == b"PK"
        blob = Blob(
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            content_type=XLSX_CONTENT_TYPE if is_xlsx else CSV_CONTENT_TYPE,
            original_filename=filename,
        )
        db.add(blob)
        db.flush()
    return blob


def _load(db: DbSession, blob_id: uuid.UUID) -> tuple[Blob, bytes]:
    blob = db.get(Blob, blob_id)
    if blob is None or blob.content_type not in _ALLOWED_CONTENT_TYPES:
        raise TrackerBlobNotFoundError(blob_id)
    data = FilesystemBlobStore(settings.blob_root).get_bytes(blob.sha256)
    return blob, data


def preview_import(db: DbSession, *, file_bytes: bytes, filename: str) -> ImportPreview:
    """Reads the upload and plans the import — writes nothing but the blob."""
    entries, problems = entries_from_upload(file_bytes, filename)
    blob = _store(db, file_bytes, filename)
    return ImportPreview(blob_id=blob.id, filename=filename, plan=_plan(db, entries, problems))


def converted_csv(db: DbSession, blob_id: uuid.UUID) -> tuple[str, str]:
    """The previewed upload as the editable CSV, and a filename for it."""
    blob, data = _load(db, blob_id)
    entries, _ = entries_from_upload(data, blob.original_filename or "tracker")
    stem = (blob.original_filename or "tracker").rsplit(".", 1)[0]
    return entries_to_csv(entries), f"{stem}.csv"


@dataclass(slots=True)
class ImportResult:
    advisories_updated: int = 0
    status_changes: int = 0
    comments_added: int = 0
    kept: int = 0
    not_found: int = 0


def apply_import(db: DbSession, *, blob_id: uuid.UUID, actor: Actor) -> ImportResult:
    """Re-reads the previewed upload, re-plans against the database as it is
    *now*, and applies it in the caller's transaction — all or nothing.
    The caller commits."""
    blob, data = _load(db, blob_id)
    entries, problems = entries_from_upload(data, blob.original_filename or "tracker")
    plan = _plan(db, entries, problems)

    result = ImportResult()
    for change in plan.changes:
        if change.outcome is Outcome.NOT_FOUND:
            result.not_found += 1
            continue
        if change.outcome is Outcome.KEPT:
            result.kept += 1
        assert change.advisory_id is not None
        comment = change.entry.comment.strip()
        if change.outcome is Outcome.UPDATE:
            target = change.path[-1]
            for step in change.path:
                if step is target and change.add_comment:
                    body = comment
                elif step is target:
                    # The tracker comment is already on the advisory (or
                    # the row had none) — don't post it twice.
                    body = (
                        f"Status set to {target.value} from manual tracker import "
                        f"({change.entry.source})."
                    )
                else:
                    body = (
                        f"Manual tracker import ({change.entry.source}): intermediate step "
                        f"towards {target.value}."
                    )
                advisories_svc.change_status(
                    db, change.advisory_id, to_status=step, comment_body=body, actor=actor
                )
                result.status_changes += 1
            result.advisories_updated += 1
            if change.add_comment:
                result.comments_added += 1
        elif change.add_comment:
            advisories_svc.add_comment(db, change.advisory_id, body=comment, actor=actor)
            result.comments_added += 1

    record(
        db,
        actor=actor,
        action="tracker.imported",
        entity_type="blob",
        entity_id=blob.id,
        detail={
            "filename": blob.original_filename,
            "advisories_updated": result.advisories_updated,
            "status_changes": result.status_changes,
            "comments_added": result.comments_added,
            "kept": result.kept,
            "not_found": result.not_found,
        },
    )
    db.flush()
    return result
