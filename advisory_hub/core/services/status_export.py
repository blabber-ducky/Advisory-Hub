"""Export every advisory's status as a CSV the tracker import can read back.

The point is recovery: if a deployment is lost beyond what backups can
restore, a fresh one re-ingests the original emails and then imports this
file to put statuses, acknowledgements and comment history back. It's the
same CSV format as the manual-tracker import (``manual_tracker.parse``),
so the same upload page restores it — with the same preview, forward-only
and idempotency rules (docs/architecture.md §3.3.4).

What survives a restore, and what doesn't:

* **Status** — reached again through legal transitions, each recorded.
* **Acknowledgement** — re-recorded with its channel. Its *time* becomes
  the import time; the original time and person are in the comment.
* **Comments** — all of them, carried as one comment per advisory with each
  original's date and author. Re-created comments are authored by whoever
  runs the import.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import Advisory, Comment, StatusChange
from ..models.user import User
from .tracker_import import RESTORE_SOURCE_PREFIX, TrackerEntry, entries_to_csv

FILENAME_PREFIX = "status-export-"


def _user_label(user: User | None) -> str:
    return user.email if user is not None else "system"


def _history_comment(
    advisory: Advisory,
    comments: list[tuple[Comment, StatusChange | None]],
    users: dict[uuid.UUID, User],
    today: date,
) -> str:
    lines: list[str] = []
    if advisory.acknowledged_at is not None:
        who = _user_label(
            users.get(advisory.acknowledged_by_id) if advisory.acknowledged_by_id else None
        )
        how = advisory.ack_channel.value if advisory.ack_channel else "unknown channel"
        lines.append(
            f"Acknowledged {advisory.acknowledged_at:%Y-%m-%d %H:%M} UTC by {who} via {how}."
        )
    for comment, change in comments:
        author = users.get(comment.author_id) if comment.author_id else None
        stamp = f"{comment.created_at:%Y-%m-%d %H:%M} UTC · {_user_label(author)}"
        if change is not None:
            stamp += f" · status → {change.to_status.value}"
        body = comment.body.strip().replace("\n", "\n    ")
        lines.append(f"[{stamp}]\n    {body}")
    if not lines:
        return ""
    return "\n".join([f"Restored from status export ({today.isoformat()}):", *lines])


def export_entries(db: DbSession, *, today: date | None = None) -> list[TrackerEntry]:
    """One entry per advisory that has an advisory number, oldest first.
    Advisories without one can't be matched on re-import, so aren't
    exported (none in the real corpus lack one)."""
    today = today or datetime.now(UTC).date()
    advisories = db.scalars(
        select(Advisory)
        .where(Advisory.external_ref.is_not(None))
        .order_by(Advisory.received_at, Advisory.external_ref)
    ).all()

    changes_by_comment = {sc.comment_id: sc for sc in db.scalars(select(StatusChange))}
    comments: dict[uuid.UUID, list[tuple[Comment, StatusChange | None]]] = defaultdict(list)
    for comment in db.scalars(select(Comment).order_by(Comment.created_at, Comment.id)):
        comments[comment.advisory_id].append((comment, changes_by_comment.get(comment.id)))
    users = {u.id: u for u in db.scalars(select(User))}

    source = f"{RESTORE_SOURCE_PREFIX} {today.isoformat()}"
    return [
        TrackerEntry(
            ref=a.external_ref or "",
            status=a.status,
            comment=_history_comment(a, comments[a.id], users, today),
            source=source,
            received=a.received_at.date().isoformat(),
            subject=a.title,
            ack_channel=a.ack_channel if a.acknowledged_at is not None else None,
        )
        for a in advisories
    ]


def export_csv(db: DbSession, *, today: date | None = None) -> str:
    return entries_to_csv(export_entries(db, today=today))


def export_filename(day: date) -> str:
    return f"{FILENAME_PREFIX}{day.isoformat()}.csv"


def write_export_file(db: DbSession, directory: Path, *, day: date) -> Path:
    """Writes ``status-export-<day>.csv`` atomically (temp file + rename), so
    a crash mid-write never leaves a truncated backup under the real name."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / export_filename(day)
    data = export_csv(db, today=day).encode("utf-8-sig")  # BOM: opens cleanly in Excel
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".incoming-", suffix=".csv")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def prune_exports(directory: Path, *, keep_days: int, today: date) -> list[Path]:
    """Deletes daily exports older than ``keep_days``. Only files matching
    the export name pattern are considered — nothing else in the folder is
    ever touched."""
    cutoff = today - timedelta(days=keep_days)
    removed: list[Path] = []
    for path in directory.glob(f"{FILENAME_PREFIX}*.csv"):
        try:
            day = date.fromisoformat(path.stem.removeprefix(FILENAME_PREFIX))
        except ValueError:
            continue
        if day < cutoff:
            path.unlink(missing_ok=True)
            removed.append(path)
    return removed


def due_export_day(cron: str, now: datetime) -> date:
    """The day of the most recent scheduled run at or before ``now`` — the
    export file that should exist by now. A worker that was down at the
    scheduled time therefore catches up as soon as it's back."""
    from croniter import croniter

    previous: datetime = croniter(cron, now).get_prev(datetime)
    return previous.date()


def run_due_export(
    db: DbSession, *, now: datetime, cron: str, directory: Path, keep_days: int
) -> Path | None:
    """The scheduled job: if the export for the latest scheduled time doesn't
    exist yet, write it and prune old ones. Returns the file written, or
    ``None`` when it already existed (nothing to do)."""
    day = due_export_day(cron, now)
    if (directory / export_filename(day)).exists():
        return None
    path = write_export_file(db, directory, day=day)
    prune_exports(directory, keep_days=keep_days, today=day)
    return path
