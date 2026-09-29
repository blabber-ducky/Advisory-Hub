"""`core.services.vt_lookup.check_ioc()` — caching, staleness, error handling.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

import advisory_hub.core.services.vt_lookup as vt_lookup_module
from advisory_hub.core.models.advisory import Advisory, AdvisoryIoc, Source, VtLookup
from advisory_hub.core.models.enums import (
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    EnrichmentStatus,
    IocType,
)
from advisory_hub.core.services import vt_lookup as svc
from advisory_hub.core.services.audit import Actor
from advisory_hub.enrich.virustotal import (
    VtError,
    VtResult,
    VtUnauthorizedError,
    VtUnsupportedIocTypeError,
)

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")

MALICIOUS_RESULT = VtResult(
    malicious_count=15,
    suspicious_count=1,
    harmless_count=50,
    undetected_count=4,
    reputation=-30,
    last_analysis_at=datetime(2026, 8, 1, tzinfo=UTC),
    permalink="https://www.virustotal.com/gui/domain/evil.example.invalid",
)


class _FakeVtClient:
    """Stands in for `enrich.virustotal.VtClient` — returns a canned result
    or raises a canned exception, never makes a real HTTP call."""

    def __init__(self, result: VtResult | None = None, error: Exception | None = None) -> None:
        self._result = result
        self._error = error
        self.calls = 0

    def __enter__(self) -> _FakeVtClient:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def lookup(self, ioc_type: IocType, value: str) -> VtResult | None:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._result


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeVtClient) -> None:
    monkeypatch.setattr(vt_lookup_module, "VtClient", lambda **kwargs: fake)


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TRVT", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


@pytest.fixture
def advisory(db, source) -> Advisory:
    adv = Advisory(
        source_id=source.id,
        external_ref="TEST-VT-1",
        type=AdvisoryType.THREAT_LANDSCAPE,
        title="Test threat landscape advisory",
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


class TestCheckIoc:
    def test_ok_result_is_persisted(self, db, domain_ioc, monkeypatch) -> None:
        _patch_client(monkeypatch, _FakeVtClient(result=MALICIOUS_RESULT))
        lookup = svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert lookup.status == EnrichmentStatus.OK
        assert lookup.malicious_count == 15
        assert lookup.permalink == MALICIOUS_RESULT.permalink
        assert lookup.checked_at is not None

    def test_not_found_result_is_persisted(self, db, domain_ioc, monkeypatch) -> None:
        _patch_client(monkeypatch, _FakeVtClient(result=None))
        lookup = svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert lookup.status == EnrichmentStatus.NOT_FOUND
        assert lookup.malicious_count is None

    def test_transport_error_is_persisted_as_error_not_raised(
        self, db, domain_ioc, monkeypatch
    ) -> None:
        _patch_client(monkeypatch, _FakeVtClient(error=VtError("boom")))
        lookup = svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert lookup.status == EnrichmentStatus.ERROR
        assert lookup.error == "boom"

    def test_unauthorized_is_raised_not_persisted_as_a_cache_entry(
        self, db, domain_ioc, monkeypatch
    ) -> None:
        _patch_client(monkeypatch, _FakeVtClient(error=VtUnauthorizedError("bad key")))
        with pytest.raises(VtUnauthorizedError):
            svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert svc.get_cached_lookup(db, IocType.DOMAIN, domain_ioc.value) is None

    def test_unsupported_ioc_type_raises_before_any_client_call(
        self, db, email_ioc, monkeypatch
    ) -> None:
        fake = _FakeVtClient(result=MALICIOUS_RESULT)
        _patch_client(monkeypatch, fake)
        with pytest.raises(VtUnsupportedIocTypeError):
            svc.check_ioc(db, email_ioc.id, actor=ACTOR)
        assert fake.calls == 0

    def test_unknown_ioc_raises(self, db) -> None:
        with pytest.raises(svc.IocNotFoundError):
            svc.check_ioc(db, uuid.uuid4(), actor=ACTOR)

    def test_fresh_cached_ok_result_skips_the_network_call(
        self, db, domain_ioc, monkeypatch
    ) -> None:
        fake = _FakeVtClient(result=MALICIOUS_RESULT)
        _patch_client(monkeypatch, fake)
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert fake.calls == 1
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert fake.calls == 1  # not called again — served from cache

    def test_force_bypasses_the_cache(self, db, domain_ioc, monkeypatch) -> None:
        fake = _FakeVtClient(result=MALICIOUS_RESULT)
        _patch_client(monkeypatch, fake)
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR, force=True)
        assert fake.calls == 2

    def test_stale_cache_triggers_a_fresh_lookup(self, db, domain_ioc, monkeypatch) -> None:
        stale = VtLookup(
            ioc_type=IocType.DOMAIN,
            value=domain_ioc.value,
            status=EnrichmentStatus.OK,
            checked_at=datetime.now(UTC) - timedelta(hours=48),
            malicious_count=0,
        )
        db.add(stale)
        db.flush()

        fake = _FakeVtClient(result=MALICIOUS_RESULT)
        _patch_client(monkeypatch, fake)
        lookup = svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert fake.calls == 1
        assert lookup.malicious_count == 15

    def test_same_indicator_across_two_advisories_shares_one_cache_row(
        self, db, source, domain_ioc, monkeypatch
    ) -> None:
        other_advisory = Advisory(
            source_id=source.id,
            external_ref="TEST-VT-2",
            type=AdvisoryType.THREAT_LANDSCAPE,
            title="Second advisory citing the same indicator",
            received_at=datetime(2026, 8, 2, tzinfo=UTC),
            dedupe_hash=uuid.uuid4().hex.ljust(64, "0"),
            parser_version="1",
            status=AdvisoryStatus.NEW,
        )
        db.add(other_advisory)
        db.flush()
        other_ioc = AdvisoryIoc(
            advisory_id=other_advisory.id,
            ioc_type=IocType.DOMAIN,
            value=domain_ioc.value,
            defanged_value=domain_ioc.defanged_value,
        )
        db.add(other_ioc)
        db.flush()

        fake = _FakeVtClient(result=MALICIOUS_RESULT)
        _patch_client(monkeypatch, fake)
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR)
        assert fake.calls == 1
        second = svc.check_ioc(db, other_ioc.id, actor=ACTOR)
        assert fake.calls == 1  # served from the shared cache row
        assert second.malicious_count == 15


class TestCachedLookupsFor:
    def test_maps_advisory_ioc_id_to_the_shared_lookup_row(
        self, db, domain_ioc, monkeypatch
    ) -> None:
        _patch_client(monkeypatch, _FakeVtClient(result=MALICIOUS_RESULT))
        svc.check_ioc(db, domain_ioc.id, actor=ACTOR)

        by_ioc = svc.cached_lookups_for(db, [domain_ioc])
        assert domain_ioc.id in by_ioc
        assert by_ioc[domain_ioc.id].malicious_count == 15

    def test_ioc_never_checked_is_absent_from_the_map(self, db, email_ioc) -> None:
        assert svc.cached_lookups_for(db, [email_ioc]) == {}

    def test_empty_list_returns_empty_map(self, db) -> None:
        assert svc.cached_lookups_for(db, []) == {}
