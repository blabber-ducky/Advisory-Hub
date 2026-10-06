"""Duplicate gates at ingest.

Real corpus finding (2026-10-06): 321 message files, 186 distinct emails —
135 emails saved twice from Outlook. Every copy has different bytes (Outlook
writes per-save metadata into a .msg), so the byte hash alone let each
second copy in as a new advisory. Also in the corpus: the regulator re-sending
the same advisory (same number, same PDF, new Message-ID) — DOH-2026618,
DOH-2026545 — versus genuine re-issues under the same number with a new PDF —
DOH-2026599, DOH-2026591 — which must stay separate.
"""

from __future__ import annotations

import threading
import uuid
from email.message import EmailMessage
from pathlib import Path

import pytest
from sqlalchemy import func, select

DOH = "DoH Cyber Advisory <cyber.advisory@doh.gov.ae>"
PDF_A = b"%PDF-1.4\n% advisory A\n"
PDF_B = b"%PDF-1.4\n% advisory A, revised\n"


def _eml(
    *,
    ref: str = "DOH-2026545",
    message_id: str | None = None,
    pdf: bytes | None = PDF_A,
    sent: str = "Thu, 23 Jul 2026 07:47:16 +0400",
    saved_marker: str = "",
) -> bytes:
    msg = EmailMessage()
    msg["From"] = DOH
    msg["To"] = "soc@example.invalid"
    msg["Subject"] = f"[EXTERNAL] Security Advisory :: {ref} - FortiSandbox OS command injection"
    msg["Date"] = sent
    msg["Message-ID"] = message_id or f"<{uuid.uuid4().hex}@doh.example>"
    if saved_marker:
        # What a re-save changes: same email, different bytes.
        msg["X-Saved-Copy"] = saved_marker
    msg.set_content("Type:\n\nVulnerability\n\nRisk level:\n\nCritical\n\nDescription:\n\nx.\n")
    if pdf is not None:
        msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=f"{ref}.pdf")
    return msg.as_bytes()


@pytest.fixture
def ingest(db, tmp_path: Path):
    from advisory_hub.core.services.ingestion import ingest_parsed_advisory
    from advisory_hub.core.services.sources import seed_default_sources
    from advisory_hub.core.storage.blobs import FilesystemBlobStore
    from advisory_hub.ingest.message import parse_message
    from advisory_hub.ingest.parser import parse_advisory

    seed_default_sources(db)
    blobs = FilesystemBlobStore(tmp_path / "blobs")

    def _ingest(raw: bytes):
        path = tmp_path / f"{uuid.uuid4().hex}.eml"
        path.write_bytes(raw)
        parsed = parse_advisory(parse_message(path), extract_pdfs=False)
        result = ingest_parsed_advisory(db, parsed, blobs)
        db.flush()
        return result

    return _ingest


def _count(db) -> int:
    from advisory_hub.core.models.advisory import Advisory

    return db.scalar(select(func.count()).select_from(Advisory))


@pytest.mark.integration
class TestGates:
    def test_identical_bytes(self, db, ingest) -> None:
        raw = _eml()
        first, second = ingest(raw), ingest(raw)
        assert (first.created, second.duplicate, second.reason) == (True, True, "DUPLICATE_HASH")
        assert second.advisory_id == first.advisory_id

    def test_same_email_saved_twice(self, db, ingest) -> None:
        """The corpus case: same Message-ID, different bytes."""
        mid = f"<{uuid.uuid4().hex}@doh.example>"
        first = ingest(_eml(message_id=mid, saved_marker="1"))
        second = ingest(_eml(message_id=mid, saved_marker="2"))
        assert second.duplicate and second.reason == "DUPLICATE_MESSAGE_ID"
        assert second.advisory_id == first.advisory_id
        assert _count(db) == 1

    def test_regulator_resend_same_number_same_pdf(self, db, ingest) -> None:
        """DOH-2026545 / DOH-2026618: new Message-ID, identical PDF."""
        first = ingest(_eml(sent="Thu, 23 Jul 2026 07:47:16 +0400"))
        second = ingest(_eml(sent="Thu, 23 Jul 2026 08:06:58 +0400"))
        assert second.duplicate and second.reason == "DUPLICATE_CONTENT"
        assert second.advisory_id == first.advisory_id

    def test_reissue_with_a_new_pdf_is_kept(self, db, ingest) -> None:
        """DOH-2026599 / DOH-2026591: same number, revised PDF — separate."""
        first = ingest(_eml(pdf=PDF_A))
        second = ingest(_eml(pdf=PDF_B, sent="Fri, 24 Jul 2026 10:00:00 +0400"))
        assert first.created and second.created
        assert second.advisory_id != first.advisory_id

    def test_same_pdf_under_another_number_is_kept(self, db, ingest) -> None:
        first = ingest(_eml(ref="DOH-2026545"))
        second = ingest(_eml(ref="DOH-2026546"))
        assert first.created and second.created

    def test_same_number_without_pdfs_is_kept(self, db, ingest) -> None:
        """Nothing to prove it's the same advisory — keep it (re-issue linking flags it)."""
        first = ingest(_eml(pdf=None))
        second = ingest(_eml(pdf=None, sent="Fri, 24 Jul 2026 10:00:00 +0400"))
        assert first.created and second.created

    def test_duplicates_after_the_first_are_audited(self, db, ingest) -> None:
        from advisory_hub.core.models.user import AuditLog

        mid = f"<{uuid.uuid4().hex}@doh.example>"
        first = ingest(_eml(message_id=mid, saved_marker="1"))
        ingest(_eml(message_id=mid, saved_marker="2"))
        ingest(_eml(sent="Fri, 24 Jul 2026 10:00:00 +0400"))  # content re-send
        entries = db.scalars(
            select(AuditLog).where(
                AuditLog.action == "advisory.duplicate_received",
                AuditLog.entity_id == first.advisory_id,
            )
        ).all()
        assert sorted(e.detail["reason"] for e in entries) == [
            "DUPLICATE_CONTENT",
            "DUPLICATE_MESSAGE_ID",
        ]


@pytest.mark.integration
def test_two_copies_ingested_at_once_make_one_advisory(engine, truncate_all, tmp_path) -> None:
    """The upload button and the inbox poller can run concurrently."""
    from sqlalchemy.orm import sessionmaker

    from advisory_hub.core.models.advisory import Advisory
    from advisory_hub.core.services.ingestion import ingest_parsed_advisory
    from advisory_hub.core.services.sources import seed_default_sources
    from advisory_hub.core.storage.blobs import FilesystemBlobStore
    from advisory_hub.ingest.message import parse_message
    from advisory_hub.ingest.parser import parse_advisory

    truncate_all()
    make = sessionmaker(bind=engine, expire_on_commit=False)
    with make() as s, s.begin():
        seed_default_sources(s)
    blobs = FilesystemBlobStore(tmp_path / "blobs")
    mid = f"<{uuid.uuid4().hex}@doh.example>"
    parsed = []
    for marker in ("1", "2"):
        path = tmp_path / f"copy{marker}.eml"
        path.write_bytes(_eml(message_id=mid, saved_marker=marker))
        parsed.append(parse_advisory(parse_message(path), extract_pdfs=False))

    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def run(p) -> None:
        try:
            with make() as s, s.begin():
                barrier.wait()
                ingest_parsed_advisory(s, p, blobs)
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(p,)) for p in parsed]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    try:
        assert errors == []
        with make() as s:
            assert s.scalar(select(func.count()).select_from(Advisory)) == 1
    finally:
        truncate_all()


@pytest.mark.integration
def test_report_lists_duplicates_stored_before_the_gates(db, ingest, monkeypatch) -> None:
    from advisory_hub.core.services import ingestion

    real = ingestion.find_duplicate
    monkeypatch.setattr(ingestion, "find_duplicate", lambda db, parsed: None)  # pre-fix
    mid = f"<{uuid.uuid4().hex}@doh.example>"
    a1 = ingest(_eml(ref="DOH-2026510", message_id=mid, saved_marker="1")).advisory
    a2 = ingest(_eml(ref="DOH-2026510", message_id=mid, saved_marker="2")).advisory
    b1 = ingest(_eml(ref="DOH-2026545")).advisory
    b2 = ingest(_eml(ref="DOH-2026545", sent="Thu, 23 Jul 2026 08:06:58 +0400")).advisory
    ingest(_eml(ref="DOH-2026599", pdf=PDF_A))
    ingest(_eml(ref="DOH-2026599", pdf=PDF_B))  # genuine re-issue: not reported
    monkeypatch.setattr(ingestion, "find_duplicate", real)

    groups = [(g.reasons, [a.id for a in g.advisories]) for g in ingestion.existing_duplicates(db)]
    # Two saved copies also share the reference and PDF: both gates link them.
    assert ({"DUPLICATE_MESSAGE_ID", "DUPLICATE_CONTENT"}, [a1.id, a2.id]) in groups
    assert ({"DUPLICATE_CONTENT"}, [b1.id, b2.id]) in groups
    assert len(groups) == 2


@pytest.mark.integration
def test_report_joins_a_resend_whose_emails_were_each_saved_twice(db, ingest, monkeypatch) -> None:
    """The corpus shape for DOH-2026545: two sends × two saved copies = one advisory."""
    from advisory_hub.core.services import ingestion

    real = ingestion.find_duplicate
    monkeypatch.setattr(ingestion, "find_duplicate", lambda db, parsed: None)
    ids = []
    for sent in ("Thu, 23 Jul 2026 07:47:16 +0400", "Thu, 23 Jul 2026 08:06:58 +0400"):
        mid = f"<{uuid.uuid4().hex}@doh.example>"
        for copy in ("1", "2"):
            ids.append(ingest(_eml(message_id=mid, sent=sent, saved_marker=copy)).advisory.id)
    monkeypatch.setattr(ingestion, "find_duplicate", real)

    [group] = ingestion.existing_duplicates(db)
    assert group.reasons == {"DUPLICATE_MESSAGE_ID", "DUPLICATE_CONTENT"}
    assert sorted(a.id for a in group.advisories) == sorted(ids)
