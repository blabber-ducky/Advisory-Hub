"""Status export: the CSV, the daily file, and — the point of it — restoring
a rebuilt deployment by importing it.

The restore test simulates the disaster properly: export, delete every
advisory and its history, re-create the advisories as a fresh ingest would
(status NEW, no comments), import the export, and compare.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete, func, select

from advisory_hub.core.models.enums import (
    SLA_HOURS,
    AckChannel,
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    Priority,
    Severity,
)
from advisory_hub.core.services import advisories as adv_svc
from advisory_hub.core.services import status_export as svc
from advisory_hub.core.services import tracker_import
from advisory_hub.core.services.audit import Actor

S = AdvisoryStatus


# ─── Pure scheduling / file handling ─────────────────────────────────────────


class TestSchedule:
    def test_before_the_daily_time_the_due_export_is_yesterdays(self) -> None:
        now = datetime(2026, 10, 4, 1, 59, tzinfo=UTC)
        assert svc.due_export_day("0 2 * * *", now) == date(2026, 10, 3)

    def test_after_the_daily_time_it_is_todays(self) -> None:
        now = datetime(2026, 10, 4, 2, 1, tzinfo=UTC)
        assert svc.due_export_day("0 2 * * *", now) == date(2026, 10, 4)


class TestFiles:
    def test_prune_keeps_recent_and_never_touches_other_files(self, tmp_path: Path) -> None:
        today = date(2026, 10, 4)
        for days_ago in (0, 29, 30, 31, 45):
            (tmp_path / svc.export_filename(today - timedelta(days=days_ago))).write_text("x")
        (tmp_path / "notes.csv").write_text("keep me")
        (tmp_path / "status-export-not-a-date.csv").write_text("keep me too")

        removed = svc.prune_exports(tmp_path, keep_days=30, today=today)

        assert sorted(p.name for p in removed) == sorted(
            [
                svc.export_filename(today - timedelta(days=31)),
                svc.export_filename(today - timedelta(days=45)),
            ]
        )
        assert (tmp_path / "notes.csv").exists()
        assert (tmp_path / "status-export-not-a-date.csv").exists()
        assert (tmp_path / svc.export_filename(today - timedelta(days=30))).exists()


# ─── Database-backed ─────────────────────────────────────────────────────────


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
def analyst(db):
    from advisory_hub.core.models.user import User

    user = User(email="analyst@example.invalid", display_name="Analyst", role="ANALYST")
    db.add(user)
    db.flush()
    return user


def _actor(user) -> Actor:
    return Actor(kind=ActorKind.USER, user_id=user.id, label=user.email)


def _advisory(db, source, ref: str, *, day: int = 0, title: str | None = None):
    from advisory_hub.core.models.advisory import Advisory

    received = datetime(2026, 8, 1, 12, 0, tzinfo=UTC) + timedelta(days=day)
    ack, resolve = SLA_HOURS[Priority.P2]
    a = Advisory(
        source_id=source.id,
        external_ref=ref,
        type=AdvisoryType.CVE_ADVISORY,
        title=title or f"Advisory {ref}",
        received_at=received,
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        severity=Severity.HIGH,
        priority=Priority.P2,
        status=S.NEW,
        ack_due_at=received + timedelta(hours=ack),
        resolution_due_at=received + timedelta(hours=resolve),
    )
    db.add(a)
    db.flush()
    return a


def _work_them(db, source, analyst):
    """A realistic mix: acknowledged then remediated; triaged with a plain
    comment; risk-accepted; untouched; and one without a number."""
    actor = _actor(analyst)
    a1 = _advisory(db, source, "DOH-1")
    adv_svc.change_status(
        db,
        a1.id,
        to_status=S.ACKNOWLEDGED,
        comment_body="Acked to DOH",
        actor=actor,
        ack_channel=AckChannel.EMAIL,
    )
    adv_svc.change_status(db, a1.id, to_status=S.TRIAGED, comment_body="Looked at it", actor=actor)
    adv_svc.change_status(db, a1.id, to_status=S.IN_PROGRESS, comment_body="Ticket 1", actor=actor)
    adv_svc.change_status(
        db, a1.id, to_status=S.REMEDIATED, comment_body="Patched\nall hosts", actor=actor
    )

    a2 = _advisory(db, source, "DOH-2", day=1)
    adv_svc.change_status(
        db, a2.id, to_status=S.TRIAGED, comment_body="Needs assessment", actor=actor
    )
    adv_svc.add_comment(db, a2.id, body="Owner: Network Team", actor=actor)

    a3 = _advisory(db, source, "DOH-3", day=2)
    adv_svc.change_status(db, a3.id, to_status=S.TRIAGED, comment_body="t", actor=actor)
    adv_svc.change_status(
        db, a3.id, to_status=S.RISK_ACCEPTED, comment_body="No fix exists", actor=actor
    )

    _advisory(db, source, "DOH-4", day=3)  # untouched

    no_ref = _advisory(db, source, "DOH-X", day=4)
    no_ref.external_ref = None
    db.flush()


@pytest.mark.integration
class TestExport:
    def test_one_row_per_numbered_advisory_with_status_and_history(
        self, db, source, analyst
    ) -> None:
        _work_them(db, source, analyst)
        entries = {e.ref: e for e in svc.export_entries(db, today=date(2026, 10, 4))}

        assert set(entries) == {"DOH-1", "DOH-2", "DOH-3", "DOH-4"}  # no-number one skipped
        assert entries["DOH-1"].status is S.REMEDIATED
        assert entries["DOH-1"].ack_channel is AckChannel.EMAIL
        assert entries["DOH-3"].ack_channel is None
        assert entries["DOH-1"].received == "2026-08-01"
        assert entries["DOH-1"].source == "Status export 2026-10-04"
        assert entries["DOH-1"].is_restore

        history = entries["DOH-1"].comment
        assert history.startswith("Restored from status export (2026-10-04):")
        assert "Acknowledged 20" in history and "via EMAIL" in history
        assert "analyst@example.invalid · status → REMEDIATED]" in history
        assert "Patched\n    all hosts" in history  # multi-line bodies kept, indented
        assert entries["DOH-4"].comment == ""  # nothing to restore

    def test_export_is_valid_import_csv(self, db, source, analyst) -> None:
        _work_them(db, source, analyst)
        text = svc.export_csv(db, today=date(2026, 10, 4))
        entries, problems = tracker_import.entries_from_upload(text.encode("utf-8-sig"), "x.csv")
        assert not problems
        assert len(entries) == 4


@pytest.mark.integration
@pytest.mark.usefixtures("_blob_root")
class TestRestore:
    def _rebuild(self, db, source) -> None:
        """Simulate the disaster: everything gone, then a fresh ingest."""
        from advisory_hub.core.models.advisory import Advisory, Comment, StatusChange

        db.execute(delete(StatusChange))
        db.execute(delete(Comment))
        db.execute(delete(Advisory))
        db.flush()
        for i, ref in enumerate(["DOH-1", "DOH-2", "DOH-3", "DOH-4"]):
            _advisory(db, source, ref, day=i)

    def test_restore_brings_back_status_acknowledgement_and_history(
        self, db, source, analyst
    ) -> None:
        from advisory_hub.core.models.advisory import Advisory, Comment

        _work_them(db, source, analyst)
        before = {e.ref: e.status for e in svc.export_entries(db)}
        export = svc.export_csv(db, today=date(2026, 10, 4)).encode("utf-8-sig")

        self._rebuild(db, source)
        preview = tracker_import.preview_import(db, file_bytes=export, filename="export.csv")
        assert not preview.plan.problems
        tracker_import.apply_import(db, blob_id=preview.blob_id, actor=_actor(analyst))

        restored = {a.external_ref: a for a in db.scalars(select(Advisory))}
        assert {ref: a.status for ref, a in restored.items()} == before
        a1 = restored["DOH-1"]
        assert a1.ack_channel is AckChannel.EMAIL and a1.acknowledged_at is not None
        bodies = db.scalars(select(Comment.body).where(Comment.advisory_id == a1.id)).all()
        assert any("Patched" in b and "Restored from status export" in b for b in bodies)

    def test_acknowledged_advisory_is_acknowledged_first(self, db, source, analyst) -> None:
        from advisory_hub.core.models.advisory import Advisory, StatusChange

        _work_them(db, source, analyst)
        export = svc.export_csv(db, today=date(2026, 10, 4)).encode("utf-8-sig")
        self._rebuild(db, source)
        preview = tracker_import.preview_import(db, file_bytes=export, filename="export.csv")
        tracker_import.apply_import(db, blob_id=preview.blob_id, actor=_actor(analyst))

        a1 = db.scalar(select(Advisory).where(Advisory.external_ref == "DOH-1"))
        steps = db.scalars(
            select(StatusChange.to_status)
            .where(StatusChange.advisory_id == a1.id)
            .order_by(StatusChange.created_at)
        ).all()
        assert steps == [S.ACKNOWLEDGED, S.TRIAGED, S.IN_PROGRESS, S.REMEDIATED]

    def test_importing_into_a_healthy_deployment_changes_nothing(self, db, source, analyst) -> None:
        from advisory_hub.core.models.advisory import Comment

        _work_them(db, source, analyst)
        comments_before = db.scalar(select(func.count()).select_from(Comment))
        export = svc.export_csv(db, today=date(2026, 10, 4)).encode("utf-8-sig")

        preview = tracker_import.preview_import(db, file_bytes=export, filename="export.csv")
        result = tracker_import.apply_import(db, blob_id=preview.blob_id, actor=_actor(analyst))

        assert (result.status_changes, result.comments_added) == (0, 0)
        assert db.scalar(select(func.count()).select_from(Comment)) == comments_before

    def test_reissues_are_told_apart_by_received_date(self, db, source, analyst) -> None:
        from advisory_hub.core.models.advisory import Advisory

        actor = _actor(analyst)
        first = _advisory(db, source, "DOH-9", day=0)
        reissue = _advisory(db, source, "DOH-9", day=5)
        adv_svc.change_status(
            db, first.id, to_status=S.NOT_APPLICABLE, comment_body="n/a", actor=actor
        )
        adv_svc.change_status(db, reissue.id, to_status=S.TRIAGED, comment_body="new", actor=actor)
        export = svc.export_csv(db, today=date(2026, 10, 4)).encode("utf-8-sig")

        from advisory_hub.core.models.advisory import Comment, StatusChange

        db.execute(delete(StatusChange))
        db.execute(delete(Comment))
        first.status = reissue.status = S.NEW
        db.flush()

        preview = tracker_import.preview_import(db, file_bytes=export, filename="export.csv")
        tracker_import.apply_import(db, blob_id=preview.blob_id, actor=actor)
        db.refresh(first)
        db.refresh(reissue)
        assert (first.status, reissue.status) == (S.NOT_APPLICABLE, S.TRIAGED)
        assert db.scalar(select(func.count()).select_from(Advisory)) == 2


@pytest.mark.integration
class TestDailyJob:
    def test_writes_once_then_does_nothing_until_the_next_day(
        self, db, source, analyst, tmp_path: Path
    ) -> None:
        _work_them(db, source, analyst)
        now = datetime(2026, 10, 4, 9, 0, tzinfo=UTC)
        kwargs = {"cron": "0 2 * * *", "directory": tmp_path, "keep_days": 30}

        first = svc.run_due_export(db, now=now, **kwargs)
        assert first == tmp_path / "status-export-2026-10-04.csv"
        assert first.read_bytes().startswith(b"\xef\xbb\xbfadvisory_ref,")
        assert svc.run_due_export(db, now=now + timedelta(hours=5), **kwargs) is None
        assert svc.run_due_export(db, now=now + timedelta(days=1), **kwargs) is not None
        assert not list(tmp_path.glob(".incoming-*"))  # atomic write left no temp file

    def test_catches_up_after_missing_the_scheduled_time(
        self, db, source, analyst, tmp_path: Path
    ) -> None:
        # Worker was down at 02:00; it starts at 15:00 and writes today's.
        path = svc.run_due_export(
            db,
            now=datetime(2026, 10, 4, 15, 0, tzinfo=UTC),
            cron="0 2 * * *",
            directory=tmp_path,
            keep_days=30,
        )
        assert path is not None and path.name == "status-export-2026-10-04.csv"


# ─── Web ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestWeb:
    def test_any_signed_in_user_can_export_and_it_is_audited(
        self, db, source, analyst, tmp_path, monkeypatch
    ) -> None:
        for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
            monkeypatch.setenv(var, str(tmp_path / var.lower()))
        monkeypatch.setenv("ENVIRONMENT", "test")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
        from fastapi.testclient import TestClient

        from advisory_hub.api.deps import SESSION_COOKIE, db_session, sign
        from advisory_hub.config import get_settings
        from advisory_hub.core.models.user import AuditLog, User
        from advisory_hub.core.services.auth import start_session
        from advisory_hub.main import create_app

        get_settings.cache_clear()
        _work_them(db, source, analyst)
        viewer = User(email="viewer@example.invalid", display_name="V", role="VIEWER")
        db.add(viewer)
        db.flush()
        session = start_session(db, viewer, ip_address="127.0.0.1", user_agent="t")
        db.flush()

        app = create_app()

        def _override():
            yield db

        app.dependency_overrides[db_session] = _override
        client = TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))
        client.cookies.set(SESSION_COOKIE, sign(str(session.id)))
        try:
            r = client.get("/status-export.csv")
        finally:
            get_settings.cache_clear()
        assert r.status_code == 200
        assert r.content.startswith(b"\xef\xbb\xbfadvisory_ref,")
        assert "DOH-1" in r.text
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "advisories.status_exported"))
        assert entry is not None and entry.detail == {"rows": 4}
