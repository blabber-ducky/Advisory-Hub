"""`core.services.vt_lookup.enqueue_bulk_check()` — queues jobs, never
calls VirusTotal directly. Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from advisory_hub.core.models.advisory import Advisory, AdvisoryIoc, Source
from advisory_hub.core.models.enums import ActorKind, AdvisoryStatus, AdvisoryType, IocType
from advisory_hub.core.services import vt_lookup as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")


class _FakeJob:
    def __init__(self, job_id: str) -> None:
        self.id = job_id


class _FakeQueue:
    def __init__(self, name: str, connection: object) -> None:
        self.name = name
        self.enqueued: list[tuple[object, tuple[object, ...]]] = []

    def enqueue(self, func: object, *args: object) -> _FakeJob:
        self.enqueued.append((func, args))
        return _FakeJob(str(uuid.uuid4()))


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TRBQ", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def advisory(db, source) -> Advisory:
    adv = Advisory(
        source_id=source.id,
        external_ref="TEST-BULK-1",
        type=AdvisoryType.THREAT_LANDSCAPE,
        title="Test advisory",
        received_at=datetime(2026, 8, 1, tzinfo=UTC),
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        status=AdvisoryStatus.NEW,
    )
    db.add(adv)
    db.flush()
    return adv


@pytest.fixture
def domain_ioc(db, advisory) -> AdvisoryIoc:
    ioc = AdvisoryIoc(
        advisory_id=advisory.id,
        ioc_type=IocType.DOMAIN,
        value="evil.example.invalid",
        defanged_value="evil[.]example[.]invalid",
    )
    db.add(ioc)
    db.flush()
    return ioc


@pytest.fixture
def email_ioc(db, advisory) -> AdvisoryIoc:
    ioc = AdvisoryIoc(
        advisory_id=advisory.id,
        ioc_type=IocType.EMAIL,
        value="attacker@example.invalid",
        defanged_value="attacker[at]example[.]invalid",
    )
    db.add(ioc)
    db.flush()
    return ioc


def _patch_queue(monkeypatch: pytest.MonkeyPatch) -> _FakeQueue:
    fakes: list[_FakeQueue] = []

    def _make(name: str, connection: object) -> _FakeQueue:
        q = _FakeQueue(name, connection)
        fakes.append(q)
        return q

    import rq

    monkeypatch.setattr(rq, "Queue", _make)
    return fakes  # type: ignore[return-value]


class TestEnqueueBulkCheck:
    def test_supported_iocs_are_queued(self, db, domain_ioc, monkeypatch) -> None:
        fakes = _patch_queue(monkeypatch)
        result = svc.enqueue_bulk_check(db, [domain_ioc.id], actor=ACTOR)
        assert result.queued == [domain_ioc.id]
        assert result.skipped_unsupported == []
        assert result.skipped_not_found == []
        assert len(fakes[0].enqueued) == 1
        _func, args = fakes[0].enqueued[0]
        assert args == (str(domain_ioc.id),)

    def test_unsupported_ioc_is_skipped_not_queued(self, db, email_ioc, monkeypatch) -> None:
        fakes = _patch_queue(monkeypatch)
        result = svc.enqueue_bulk_check(db, [email_ioc.id], actor=ACTOR)
        assert result.queued == []
        assert result.skipped_unsupported == [email_ioc.id]
        assert fakes[0].enqueued == []

    def test_unknown_ioc_id_is_skipped_not_queued(self, db, monkeypatch) -> None:
        fakes = _patch_queue(monkeypatch)
        missing = uuid.uuid4()
        result = svc.enqueue_bulk_check(db, [missing], actor=ACTOR)
        assert result.queued == []
        assert result.skipped_not_found == [missing]
        assert fakes[0].enqueued == []

    def test_mixed_batch_partitions_correctly(self, db, domain_ioc, email_ioc, monkeypatch) -> None:
        fakes = _patch_queue(monkeypatch)
        missing = uuid.uuid4()
        result = svc.enqueue_bulk_check(db, [domain_ioc.id, email_ioc.id, missing], actor=ACTOR)
        assert result.queued == [domain_ioc.id]
        assert result.skipped_unsupported == [email_ioc.id]
        assert result.skipped_not_found == [missing]
        assert len(fakes[0].enqueued) == 1
