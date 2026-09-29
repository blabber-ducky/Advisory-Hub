"""Watcher, PDF sandbox, and end-to-end persistence."""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from advisory_hub.core.models.enums import ExtractionMethod
from advisory_hub.ingest.pdf import extract_pdf
from advisory_hub.ingest.watcher import Inbox


@pytest.fixture
def inbox(tmp_path: Path) -> Inbox:
    return Inbox(
        inbox=tmp_path / "inbox",
        processing=tmp_path / "processing",
        archive=tmp_path / "archive",
        failed=tmp_path / "failed",
        worker_id="test",
    )


def _drop(inbox: Inbox, name: str, data: bytes = b"x") -> Path:
    path = inbox.inbox / name
    path.write_bytes(data)
    return path


class TestInbox:
    def test_only_message_extensions_are_seen(self, inbox: Inbox) -> None:
        """A half-written `.tmp` must never be claimed."""
        _drop(inbox, "a.msg")
        _drop(inbox, "b.eml")
        _drop(inbox, "c.msg.tmp")
        _drop(inbox, "d.pdf")
        assert {p.name for p in inbox.pending()} == {"a.msg", "b.eml"}

    def test_claim_moves_the_file(self, inbox: Inbox) -> None:
        path = _drop(inbox, "a.msg")
        claimed = inbox.claim(path)
        assert claimed is not None
        assert claimed.parent == inbox.processing
        assert not path.exists()

    def test_claim_is_exclusive(self, inbox: Inbox) -> None:
        """Two workers must never process the same message."""
        path = _drop(inbox, "a.msg")
        first = inbox.claim(path)
        second = inbox.claim(path)
        assert first is not None
        assert second is None

    def test_orphans_are_recovered(self, inbox: Inbox) -> None:
        """Whatever a crashed worker left mid-flight must be reprocessed."""
        (inbox.processing / "stranded.msg").write_bytes(b"x")
        assert [p.name for p in inbox.recover_orphans()] == ["stranded.msg"]

    def test_archive_is_dated(self, inbox: Inbox) -> None:
        from datetime import date

        claimed = inbox.claim(_drop(inbox, "a.msg"))
        assert claimed is not None
        archived = inbox.archive_file(claimed)
        assert archived.parent.name == date.today().isoformat()
        assert archived.is_file()

    def test_failure_writes_a_sidecar(self, inbox: Inbox) -> None:
        claimed = inbox.claim(_drop(inbox, "a.msg"))
        assert claimed is not None
        failed = inbox.fail_file(claimed, {"error": "BOOM"})
        sidecar = failed.with_suffix(failed.suffix + ".error.json")
        assert failed.is_file()
        assert "BOOM" in sidecar.read_text()
        assert inbox.failed_count() == 1

    def test_nothing_is_ever_overwritten(self, inbox: Inbox) -> None:
        """Regulators resend; filenames repeat. Both copies must survive."""
        first = inbox.claim(_drop(inbox, "same.msg", b"one"))
        assert first is not None
        inbox.archive_file(first)
        second = inbox.claim(_drop(inbox, "same.msg", b"two"))
        assert second is not None
        archived = inbox.archive_file(second)
        assert archived.name != "same.msg"
        assert archived.read_bytes() == b"two"

    def test_claim_falls_back_when_inbox_and_processing_are_different_filesystems(
        self, inbox: Inbox, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: `INBOX_HOST_PATH` bind-mounts `inbox` to a real host
        folder while `processing` stays an internal Docker volume — a plain
        `os.rename` across that boundary raises `OSError(EXDEV)`, which was
        being swallowed as "another worker won", so nothing was ever
        claimed. Confirmed live: 135 real files sitting in the mounted
        inbox, 0 archived, no error logged, after INBOX_HOST_PATH was
        introduced."""
        import errno
        import os

        real_rename = os.rename

        def _rename_first_call_exdev(src: object, dst: object) -> None:
            monkeypatch.setattr(os, "rename", real_rename)
            raise OSError(errno.EXDEV, "Invalid cross-device link")

        monkeypatch.setattr(os, "rename", _rename_first_call_exdev)

        path = _drop(inbox, "a.msg")
        claimed = inbox.claim(path)

        assert claimed is not None
        assert claimed.parent == inbox.processing
        assert claimed.is_file()
        assert not path.exists()
        # No leftover staging file — the cross-device copy must clean up
        # after itself, not just leave a duplicate in inbox/.claiming/.
        assert not (inbox.inbox / ".claiming" / "test" / "a.msg").exists()

    def test_claim_is_still_exclusive_across_the_cross_device_fallback(self, inbox: Inbox) -> None:
        """`_claim_cross_device`'s own staging rename is same-filesystem
        (both under `inbox`), so it keeps the same win-or-lose-the-race
        guarantee as the plain-`os.rename` path — no need to fake EXDEV
        here, just exercise the fallback method directly."""
        path = _drop(inbox, "a.msg")
        first = inbox._claim_cross_device(path, inbox.processing / path.name)
        assert first is not None
        assert first.is_file()

        # A second worker racing on the same (already-moved) source file
        # finds nothing there — the normal `pending()`/`claim()` path
        # already guards this; this just confirms the fallback doesn't
        # leave the source claimable twice.
        assert not path.exists()

    def test_orphans_are_recovered_from_the_cross_device_staging_dir(self, inbox: Inbox) -> None:
        """A crash between the same-filesystem stage and the cross-device
        copy must not lose the file — recover_orphans() must find it in
        inbox/.claiming/<worker_id>/, not just processing/."""
        staging_dir = inbox.inbox / ".claiming" / inbox.worker_id
        staging_dir.mkdir(parents=True)
        (staging_dir / "stranded.msg").write_bytes(b"x")

        recovered = inbox.recover_orphans()

        assert [p.name for p in recovered] == ["stranded.msg"]
        assert recovered[0].parent == inbox.processing
        assert not (staging_dir / "stranded.msg").exists()


class TestPdfSandbox:
    """The sandbox must contain hostile input, not merely be documented."""

    def test_rejects_non_pdf(self) -> None:
        result = extract_pdf(b"this is not a pdf")
        assert result.method is ExtractionMethod.FAILED
        assert result.error is not None
        assert "NOT_A_PDF" in result.error

    def test_rejects_empty(self) -> None:
        assert extract_pdf(b"").method is ExtractionMethod.FAILED

    def test_enforces_the_size_limit(self) -> None:
        oversized = b"%PDF-1.7\n" + b"0" * 5000
        result = extract_pdf(oversized, max_bytes=1000)
        assert result.method is ExtractionMethod.FAILED
        assert result.error is not None
        assert "FILE_TOO_LARGE" in result.error

    def test_malformed_pdf_fails_cleanly(self) -> None:
        """A truncated PDF must produce a reason, not an exception."""
        result = extract_pdf(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n")
        assert result.method is ExtractionMethod.FAILED
        assert result.error

    def test_decompression_bomb_is_contained(self) -> None:
        """A stream that inflates enormously must not exhaust the worker."""
        payload = zlib.compress(b"A" * (80 * 1024 * 1024))
        bomb = (
            b"%PDF-1.7\n1 0 obj\n<< /Length "
            + str(len(payload)).encode()
            + b" /Filter /FlateDecode >>\nstream\n"
            + payload
            + b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n"
        )
        result = extract_pdf(bomb, timeout_seconds=20)
        # Must fail, and must do so quickly and without taking the process down.
        assert result.method is ExtractionMethod.FAILED

    def test_failure_never_raises(self) -> None:
        """Ingestion continues from the email even when the PDF is hostile."""
        for payload in (b"", b"nonsense", b"%PDF-1.7\ngarbage"):
            assert extract_pdf(payload).method is ExtractionMethod.FAILED


@pytest.mark.integration
class TestEndToEndPersistence:
    def test_ingest_creates_advisory_with_children(self, db, tmp_path: Path) -> None:
        from advisory_hub.core.models.advisory import Advisory
        from advisory_hub.core.services.ingestion import ingest_parsed_advisory
        from advisory_hub.core.services.sources import seed_default_sources
        from advisory_hub.core.storage.blobs import FilesystemBlobStore
        from advisory_hub.ingest.parser import parse_advisory

        seed_default_sources(db)
        message = _synthetic_message()
        parsed = parse_advisory(message, extract_pdfs=False)
        blobs = FilesystemBlobStore(tmp_path / "blobs")

        result = ingest_parsed_advisory(db, parsed, blobs)
        db.flush()

        assert result.created
        advisory = db.get(Advisory, result.advisory_id)
        assert advisory is not None
        assert advisory.external_ref == "DOH-2026550"
        assert {c.cve_id for c in advisory.cves} == {"CVE-2026-58319"}
        assert advisory.priority is not None

    def test_sla_clocks_match_the_regulator_table(self, db, tmp_path: Path) -> None:
        from advisory_hub.core.models.advisory import Advisory
        from advisory_hub.core.services.ingestion import ingest_parsed_advisory
        from advisory_hub.core.services.sources import seed_default_sources
        from advisory_hub.core.storage.blobs import FilesystemBlobStore
        from advisory_hub.ingest.parser import parse_advisory

        seed_default_sources(db)
        parsed = parse_advisory(_synthetic_message(), extract_pdfs=False)
        result = ingest_parsed_advisory(db, parsed, FilesystemBlobStore(tmp_path / "b"))
        db.flush()

        advisory = db.get(Advisory, result.advisory_id)
        assert advisory is not None
        assert advisory.ack_due_at and advisory.resolution_due_at
        ack_hours = (advisory.ack_due_at - advisory.received_at).total_seconds() / 3600
        res_hours = (advisory.resolution_due_at - advisory.received_at).total_seconds() / 3600
        assert (ack_hours, res_hours) == (8, 24)  # P1 / Critical

    def test_reingest_is_idempotent(self, db, tmp_path: Path) -> None:
        from advisory_hub.core.services.ingestion import ingest_parsed_advisory
        from advisory_hub.core.services.sources import seed_default_sources
        from advisory_hub.core.storage.blobs import FilesystemBlobStore
        from advisory_hub.ingest.parser import parse_advisory

        seed_default_sources(db)
        blobs = FilesystemBlobStore(tmp_path / "blobs")
        parsed = parse_advisory(_synthetic_message(), extract_pdfs=False)

        first = ingest_parsed_advisory(db, parsed, blobs)
        db.flush()
        second = ingest_parsed_advisory(db, parsed, blobs)
        db.flush()

        assert first.created is True
        assert second.created is False
        assert second.duplicate is True
        assert second.advisory_id == first.advisory_id

    def test_unknown_sender_is_flagged_not_dropped(self, db, tmp_path: Path) -> None:
        from advisory_hub.core.models.advisory import Advisory
        from advisory_hub.core.models.enums import FlagKind
        from advisory_hub.core.services.ingestion import ingest_parsed_advisory
        from advisory_hub.core.services.sources import seed_default_sources
        from advisory_hub.core.storage.blobs import FilesystemBlobStore
        from advisory_hub.ingest.parser import parse_advisory

        seed_default_sources(db)
        message = _synthetic_message(sender="Someone <attacker@example.invalid>")
        parsed = parse_advisory(message, extract_pdfs=False)
        result = ingest_parsed_advisory(db, parsed, FilesystemBlobStore(tmp_path / "b"))
        db.flush()

        advisory = db.get(Advisory, result.advisory_id)
        assert advisory is not None
        assert FlagKind.UNKNOWN_SENDER in {f.kind for f in advisory.flags}


def _synthetic_message(sender: str = "DoH Cyber Advisory <cyber.advisory@doh.gov.ae>"):
    """A message shaped like the corpus, built from scratch (no real data)."""
    import hashlib
    from datetime import UTC, datetime

    from advisory_hub.ingest.message import ParsedMessage, parse_body_fields

    body = (
        "Dear IS Stakeholder,\n\n"
        "Affected Product:\n\nApache Doris\n\n"
        "Reference:\n\nOpenwall\n\n"
        "Detected on:\n\n23-July-2026\n\n"
        "Type:\n\nVulnerability\n\n"
        "Risk level:\n\nCritical\n\n"
        "Description:\n\nCVE-2026-58319 affects Apache Doris.\n\n"
        "Action Required:\n\nApply the recommendations.\n"
    )
    raw = f"{sender}{body}".encode()
    return ParsedMessage(
        raw_bytes=raw,
        dedupe_hash=hashlib.sha256(raw).hexdigest(),
        subject="[EXTERNAL] Security Advisory :: DOH- 2026550 - Critical Flaw in Apache Doris",
        sender=sender,
        sender_email=sender.split("<")[-1].rstrip(">").lower(),
        recipients=None,
        sent_at=datetime(2026, 7, 23, 12, 0, tzinfo=UTC),
        message_id="<test@example.invalid>",
        body_text=body,
        attachments=[],
        fields=parse_body_fields(body),
    )
