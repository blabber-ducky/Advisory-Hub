"""`core.services.iocs` — effective status derivation, listing, and the
per-IOC override. Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from advisory_hub.core.models.advisory import Advisory, AdvisoryIoc, Source
from advisory_hub.core.models.enums import (
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    IocRemediationStatus,
    IocType,
)
from advisory_hub.core.services import iocs as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TRIO", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


def _advisory(db, source, *, external_ref: str, status: AdvisoryStatus) -> Advisory:
    adv = Advisory(
        source_id=source.id,
        external_ref=external_ref,
        type=AdvisoryType.THREAT_LANDSCAPE,
        title="Test advisory",
        received_at=datetime(2026, 8, 1, tzinfo=UTC),
        dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
        parser_version="1",
        status=status,
    )
    db.add(adv)
    db.flush()
    return adv


def _ioc(db, advisory, *, remediation_status: IocRemediationStatus | None = None) -> AdvisoryIoc:
    ioc = AdvisoryIoc(
        advisory_id=advisory.id,
        ioc_type=IocType.DOMAIN,
        value=f"{uuid.uuid4().hex}.example.invalid",
        defanged_value="evil[.]example[.]invalid",
        remediation_status=remediation_status,
    )
    db.add(ioc)
    db.flush()
    return ioc


class TestEffectiveStatus:
    def test_no_override_follows_the_advisory(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-1", status=AdvisoryStatus.IN_PROGRESS)
        ioc = _ioc(db, adv)
        assert svc.effective_status(ioc, adv) == IocRemediationStatus.IN_PROGRESS

    def test_new_advisory_maps_to_due(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-2", status=AdvisoryStatus.NEW)
        ioc = _ioc(db, adv)
        assert svc.effective_status(ioc, adv) == IocRemediationStatus.DUE

    def test_awaiting_vendor_maps_to_blocked(self, db, source) -> None:
        adv = _advisory(
            db, source, external_ref="TEST-IOC-3", status=AdvisoryStatus.AWAITING_VENDOR
        )
        ioc = _ioc(db, adv)
        assert svc.effective_status(ioc, adv) == IocRemediationStatus.BLOCKED

    def test_closed_maps_to_resolved(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-4", status=AdvisoryStatus.CLOSED)
        ioc = _ioc(db, adv)
        assert svc.effective_status(ioc, adv) == IocRemediationStatus.RESOLVED

    def test_override_wins_over_the_advisory_status(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-5", status=AdvisoryStatus.IN_PROGRESS)
        ioc = _ioc(db, adv, remediation_status=IocRemediationStatus.BLOCKED)
        assert svc.effective_status(ioc, adv) == IocRemediationStatus.BLOCKED


class TestSetRemediationStatus:
    def test_sets_an_override(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-6", status=AdvisoryStatus.NEW)
        ioc = _ioc(db, adv)
        updated = svc.set_remediation_status(db, ioc.id, IocRemediationStatus.BLOCKED, actor=ACTOR)
        assert updated.remediation_status == IocRemediationStatus.BLOCKED

    def test_none_clears_the_override(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-7", status=AdvisoryStatus.NEW)
        ioc = _ioc(db, adv, remediation_status=IocRemediationStatus.RESOLVED)
        updated = svc.set_remediation_status(db, ioc.id, None, actor=ACTOR)
        assert updated.remediation_status is None
        assert svc.effective_status(updated, adv) == IocRemediationStatus.DUE

    def test_unknown_ioc_raises(self, db) -> None:
        with pytest.raises(svc.IocNotFoundError):
            svc.set_remediation_status(db, uuid.uuid4(), IocRemediationStatus.DUE, actor=ACTOR)


class TestListIocs:
    def test_lists_every_ioc_newest_advisory_first(self, db, source) -> None:
        older = _advisory(db, source, external_ref="TEST-IOC-OLD", status=AdvisoryStatus.NEW)
        older.received_at = datetime(2026, 7, 1, tzinfo=UTC)
        newer = _advisory(db, source, external_ref="TEST-IOC-NEW", status=AdvisoryStatus.NEW)
        newer.received_at = datetime(2026, 8, 1, tzinfo=UTC)
        db.flush()
        ioc_old = _ioc(db, older)
        ioc_new = _ioc(db, newer)

        result = svc.list_iocs(db)
        assert result.total == 2
        assert [i.id for i in result.items] == [ioc_new.id, ioc_old.id]

    def test_filters_by_ioc_type(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-TYPE", status=AdvisoryStatus.NEW)
        domain_ioc = _ioc(db, adv)
        ip_ioc = AdvisoryIoc(
            advisory_id=adv.id,
            ioc_type=IocType.IPV4,
            value="198.51.100.7",
            defanged_value="198[.]51[.]100[.]7",
        )
        db.add(ip_ioc)
        db.flush()

        result = svc.list_iocs(db, svc.IocFilters(ioc_type=[IocType.IPV4]))
        assert [i.id for i in result.items] == [ip_ioc.id]
        assert domain_ioc.id not in [i.id for i in result.items]

    def test_filters_by_effective_status(self, db, source) -> None:
        due_adv = _advisory(db, source, external_ref="TEST-IOC-DUE", status=AdvisoryStatus.NEW)
        resolved_adv = _advisory(
            db, source, external_ref="TEST-IOC-RESOLVED", status=AdvisoryStatus.CLOSED
        )
        due_ioc = _ioc(db, due_adv)
        resolved_ioc = _ioc(db, resolved_adv)

        result = svc.list_iocs(db, svc.IocFilters(status=[IocRemediationStatus.RESOLVED]))
        ids = [i.id for i in result.items]
        assert resolved_ioc.id in ids
        assert due_ioc.id not in ids

    def test_filter_by_status_includes_manual_overrides(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-OVERRIDE", status=AdvisoryStatus.NEW)
        overridden = _ioc(db, adv, remediation_status=IocRemediationStatus.BLOCKED)

        result = svc.list_iocs(db, svc.IocFilters(status=[IocRemediationStatus.BLOCKED]))
        assert [i.id for i in result.items] == [overridden.id]

    def test_search_filters_by_defanged_value(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-SEARCH", status=AdvisoryStatus.NEW)
        ioc = AdvisoryIoc(
            advisory_id=adv.id,
            ioc_type=IocType.DOMAIN,
            value="findme.example.invalid",
            defanged_value="findme[.]example[.]invalid",
        )
        db.add(ioc)
        db.flush()
        _ioc(db, adv)  # a second, non-matching IOC

        result = svc.list_iocs(db, svc.IocFilters(q="findme"))
        assert [i.id for i in result.items] == [ioc.id]

    def test_pagination(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-PAGE", status=AdvisoryStatus.NEW)
        for _ in range(5):
            _ioc(db, adv)

        page1 = svc.list_iocs(db, page=1, page_size=2)
        assert len(page1.items) == 2
        assert page1.total == 5
        assert page1.total_pages == 3
        assert page1.has_next
        assert not page1.has_prev

        page3 = svc.list_iocs(db, page=3, page_size=2)
        assert len(page3.items) == 1


class TestListAllIocs:
    def test_returns_every_matching_row_unpaginated(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-ALL", status=AdvisoryStatus.NEW)
        for _ in range(5):
            _ioc(db, adv)

        rows = svc.list_all_iocs(db)
        assert len(rows) == 5

    def test_respects_the_same_filters_as_list_iocs(self, db, source) -> None:
        due_adv = _advisory(db, source, external_ref="TEST-IOC-ALL-DUE", status=AdvisoryStatus.NEW)
        resolved_adv = _advisory(
            db, source, external_ref="TEST-IOC-ALL-RESOLVED", status=AdvisoryStatus.CLOSED
        )
        due_ioc = _ioc(db, due_adv)
        resolved_ioc = _ioc(db, resolved_adv)

        rows = svc.list_all_iocs(db, svc.IocFilters(status=[IocRemediationStatus.RESOLVED]))
        ids = [r.id for r in rows]
        assert resolved_ioc.id in ids
        assert due_ioc.id not in ids

    def test_no_filters_defaults_to_everything(self, db, source) -> None:
        adv = _advisory(db, source, external_ref="TEST-IOC-ALL-NONE", status=AdvisoryStatus.NEW)
        _ioc(db, adv)
        _ioc(db, adv)

        assert len(svc.list_all_iocs(db, None)) == 2
