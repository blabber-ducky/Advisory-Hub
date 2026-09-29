"""NVD client, CPE parsing, cache, and enrichment persistence.

Every test uses a mock transport — the suite must never depend on NVD being
reachable. Fixtures reproduce the live API's real response shape, including the
quirks that would otherwise produce junk (see `nvd.py` module docstring).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from advisory_hub.core.models.enums import EnrichmentStatus, Priority, Severity
from advisory_hub.enrich.cpe import normalise_component, parse_cpe
from advisory_hub.enrich.nvd import (
    MAX_ATTEMPTS,
    NvdClient,
    NvdError,
    RateLimiter,
    parse_nvd_cve,
)

# ─── Fixtures shaped like the live API ───────────────────────────────────────

LOG4SHELL = {
    "id": "CVE-2021-44228",
    "vulnStatus": "Analyzed",
    "published": "2021-12-10T10:15:09.143",  # note: no timezone
    "lastModified": "2025-04-03T01:03:51.193",
    "descriptions": [
        {
            "lang": "en",
            "value": "Apache Log4j2 JNDI features do not protect against attacker input.",
        },
        {"lang": "es", "value": "Las caracteristicas JNDI..."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                },
            },
            {
                "source": "secondary@example.invalid",
                "type": "Secondary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    "baseScore": 5.3,
                    "baseSeverity": "MEDIUM",
                },
            },
        ],
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M", "baseScore": 9.3},
            }
        ],
        # Real payloads carry this. It has no cvssData and a null score —
        # iterating metrics blindly produces junk rows.
        "ssvcV203": [{"source": "134c704f", "type": None, "options": []}],
    },
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.0",
                            "versionEndExcluding": "2.15.0",
                            "matchCriteriaId": "AAA",
                        },
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:siemens:firmware:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "2.7.0",
                            "matchCriteriaId": "BBB",
                        },
                    ],
                }
            ]
        },
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": True,  # negated nodes are skipped, not inverted
                    "cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*"}
                    ],
                }
            ]
        },
    ],
}


def _transport(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok_handler(payload: dict[str, Any]):
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return handle


def _fast_client(handler: Any) -> NvdClient:
    """A client with the rate limiter effectively disabled, for speed."""
    return NvdClient(
        api_key=None,
        client=_transport(handler),
        rate_limiter=RateLimiter(max_calls=10_000, window_seconds=0.001),
    )


# ─── CPE ─────────────────────────────────────────────────────────────────────


class TestCpe:
    def test_parses_application_cpe(self) -> None:
        cpe = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert cpe is not None
        assert (cpe.part, cpe.vendor, cpe.product, cpe.version) == (
            "a",
            "apache",
            "log4j",
            "2.14.1",
        )
        assert cpe.is_application

    def test_wildcard_version_is_none(self) -> None:
        cpe = parse_cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.version is None
        assert not cpe.has_explicit_version

    def test_operating_system_part(self) -> None:
        cpe = parse_cpe("cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.is_os
        assert cpe.product == "windows 10"  # underscores normalise to spaces

    def test_unescapes_literals(self) -> None:
        cpe = parse_cpe(r"cpe:2.3:a:vendor:product:4\.1:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.version == "4.1"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "not-a-cpe",
            "cpe:2.3:a:apache",  # too few components
            "cpe:2.2:a:apache:log4j:1.0",  # wrong CPE version
            "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",  # no vendor or product
        ],
    )
    def test_rejects_unparseable(self, bad: str) -> None:
        """A mis-parsed CPE yields a wrong inventory match — worse than none."""
        assert parse_cpe(bad) is None

    def test_normalisation_matches_inventory_side(self) -> None:
        assert normalise_component("Application_Server") == "application server"
        assert normalise_component("*") == ""


# ─── Response parsing ────────────────────────────────────────────────────────


class TestResponseParsing:
    def test_reads_core_fields(self) -> None:
        record = parse_nvd_cve(LOG4SHELL)
        assert record.cve_id == "CVE-2021-44228"
        assert record.description is not None
        assert record.description.startswith("Apache Log4j2")
        assert record.vuln_status == "Analyzed"

    def test_english_description_is_chosen(self) -> None:
        assert "Las caracteristicas" not in (parse_nvd_cve(LOG4SHELL).description or "")

    def test_timezone_naive_timestamps_become_utc(self) -> None:
        """NVD omits the offset; the values are UTC."""
        published = parse_nvd_cve(LOG4SHELL).published
        assert published is not None
        assert published.tzinfo is not None
        assert published.year == 2021

    def test_non_cvss_metrics_are_ignored(self) -> None:
        """`ssvcV203` has no cvssData — it must not become a metric row."""
        versions = {m.version for m in parse_nvd_cve(LOG4SHELL).metrics}
        assert versions == {"3.1", "2.0"}

    def test_primary_source_wins_over_secondary(self) -> None:
        v3 = parse_nvd_cve(LOG4SHELL).cvss_v3
        assert v3 is not None
        assert v3.score == Decimal("10.0")
        assert v3.is_primary

    def test_missing_v4_is_none(self) -> None:
        assert parse_nvd_cve(LOG4SHELL).cvss_v4 is None

    def test_cpe_matches_are_flattened(self) -> None:
        matches = parse_nvd_cve(LOG4SHELL).cpe_matches
        products = {m.cpe.product for m in matches}
        assert "log4j" in products

    def test_negated_nodes_are_skipped(self) -> None:
        """Negation is skipped rather than inverted — inverting would invent
        affected products that NVD never asserted."""
        assert "thing" not in {m.cpe.product for m in parse_nvd_cve(LOG4SHELL).cpe_matches}

    def test_version_range_bounds_are_captured(self) -> None:
        log4j = next(m for m in parse_nvd_cve(LOG4SHELL).cpe_matches if m.cpe.product == "log4j")
        assert log4j.version_start == "2.0"
        assert log4j.version_start_inclusive is True
        assert log4j.version_end == "2.15.0"
        assert log4j.version_end_inclusive is False  # versionEndExcluding

    def test_non_vulnerable_rows_are_kept_as_context(self) -> None:
        assert any(not m.vulnerable for m in parse_nvd_cve(LOG4SHELL).cpe_matches)

    def test_empty_payload_does_not_crash(self) -> None:
        record = parse_nvd_cve({})
        assert record.metrics == []
        assert record.cpe_matches == []

    def test_out_of_range_score_is_dropped(self) -> None:
        payload = {
            "id": "CVE-2026-1",
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"version": "3.1", "baseScore": 99.0, "vectorString": "x"}}
                ]
            },
        }
        assert parse_nvd_cve(payload).metrics[0].score is None


# ─── Client behaviour ────────────────────────────────────────────────────────


class TestClient:
    def test_fetch_returns_a_record(self) -> None:
        payload = {"vulnerabilities": [{"cve": LOG4SHELL}], "totalResults": 1}
        with _fast_client(_ok_handler(payload)) as client:
            record = client.fetch("CVE-2021-44228")
        assert record is not None
        assert record.cve_id == "CVE-2021-44228"

    def test_empty_result_is_not_found_not_an_error(self) -> None:
        payload = {"vulnerabilities": [], "totalResults": 0}
        with _fast_client(_ok_handler(payload)) as client:
            assert client.fetch("CVE-2099-9999") is None

    def test_404_is_not_found(self) -> None:
        with _fast_client(lambda r: httpx.Response(404)) as client:
            assert client.fetch("CVE-2099-9999") is None

    def test_transport_failure_raises_rather_than_reporting_not_found(self) -> None:
        """A network failure must not be recorded as 'NVD has no such CVE'."""

        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("network down")

        client = NvdClient(
            api_key=None,
            client=_transport(boom),
            rate_limiter=RateLimiter(10_000, 0.001),
        )
        # Backoff sleeps are real; keep attempts cheap by patching the sleep.
        import advisory_hub.enrich.nvd as nvd_module

        original = nvd_module.time.sleep
        nvd_module.time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            with pytest.raises(NvdError):
                client.fetch("CVE-2021-44228")
        finally:
            nvd_module.time.sleep = original  # type: ignore[assignment]
            client.close()

    def test_rate_limit_response_is_retried(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 3:
                return httpx.Response(403)
            return httpx.Response(200, json={"vulnerabilities": [{"cve": LOG4SHELL}]})

        import advisory_hub.enrich.nvd as nvd_module

        original = nvd_module.time.sleep
        nvd_module.time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            with _fast_client(handler) as client:
                record = client.fetch("CVE-2021-44228")
        finally:
            nvd_module.time.sleep = original  # type: ignore[assignment]

        assert record is not None
        assert calls["n"] == 3

    def test_api_key_is_sent_as_a_header(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(request.headers)
            return httpx.Response(200, json={"vulnerabilities": []})

        client = NvdClient(
            api_key="secret-key",
            client=_transport(handler),
            rate_limiter=RateLimiter(10_000, 0.001),
        )
        client.fetch("CVE-2021-44228")
        client.close()
        assert seen.get("apikey") == "secret-key"

    def test_key_raises_the_rate_limit(self) -> None:
        anonymous = NvdClient(
            api_key=None, client=_transport(lambda r: httpx.Response(200, json={}))
        )
        keyed = NvdClient(api_key="k", client=_transport(lambda r: httpx.Response(200, json={})))
        assert keyed.rate_limiter.max_calls > anonymous.rate_limiter.max_calls
        anonymous.close()
        keyed.close()

    def test_gives_up_after_max_attempts(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(503)

        import advisory_hub.enrich.nvd as nvd_module

        original = nvd_module.time.sleep
        nvd_module.time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            with _fast_client(handler) as client, pytest.raises(NvdError):
                client.fetch("CVE-2021-44228")
        finally:
            nvd_module.time.sleep = original  # type: ignore[assignment]
        assert calls["n"] == MAX_ATTEMPTS


class TestRateLimiter:
    def test_permits_up_to_the_limit_without_waiting(self) -> None:
        limiter = RateLimiter(max_calls=3, window_seconds=60)
        assert [limiter.acquire() for _ in range(3)] == [0.0, 0.0, 0.0]

    def test_blocks_once_the_window_is_full(self) -> None:
        limiter = RateLimiter(max_calls=2, window_seconds=0.3)
        limiter.acquire()
        limiter.acquire()
        assert limiter.acquire() > 0


# ─── Persistence ─────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestEnrichmentPersistence:
    def test_enrichment_populates_cvss_and_cpe(self, db, tmp_path) -> None:
        from advisory_hub.core.models.advisory import AdvisoryCve, CveCpe
        from advisory_hub.core.services.enrichment import enrich_pending

        advisory = _seed_advisory(db, tmp_path, cve="CVE-2021-44228")
        payload = {"vulnerabilities": [{"cve": LOG4SHELL}]}

        with _fast_client(_ok_handler(payload)) as client:
            report = enrich_pending(db, client=client, cache=_NoCache())
        db.flush()

        assert report.ok == 1
        row = db.scalar(select(AdvisoryCve).where(AdvisoryCve.advisory_id == advisory.id))
        assert row is not None
        assert row.enrichment_status == EnrichmentStatus.OK
        assert row.cvss_v3_score == Decimal("10.0")
        cpe_rows = db.scalars(select(CveCpe).where(CveCpe.cve_id == "CVE-2021-44228")).all()
        assert len(cpe_rows) > 0

    def test_missing_cve_is_recorded_as_not_found(self, db, tmp_path) -> None:
        from advisory_hub.core.models.advisory import AdvisoryCve
        from advisory_hub.core.services.enrichment import enrich_pending

        _seed_advisory(db, tmp_path, cve="CVE-2099-9999")
        with _fast_client(_ok_handler({"vulnerabilities": []})) as client:
            report = enrich_pending(db, client=client, cache=_NoCache())
        db.flush()

        assert report.not_found == 1
        row = db.scalars(select(AdvisoryCve)).first()
        assert row is not None
        assert row.enrichment_status == EnrichmentStatus.NOT_FOUND

    def test_transport_failure_is_error_not_not_found(self, db, tmp_path) -> None:
        """The distinction matters: ERROR is retried, NOT_FOUND is not."""
        from advisory_hub.core.models.advisory import AdvisoryCve
        from advisory_hub.core.services.enrichment import enrich_pending

        _seed_advisory(db, tmp_path, cve="CVE-2021-44228")

        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        import advisory_hub.enrich.nvd as nvd_module

        original = nvd_module.time.sleep
        nvd_module.time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            with _fast_client(boom) as client:
                report = enrich_pending(db, client=client, cache=_NoCache())
        finally:
            nvd_module.time.sleep = original  # type: ignore[assignment]
        db.flush()

        assert report.errors == 1
        row = db.scalars(select(AdvisoryCve)).first()
        assert row is not None
        assert row.enrichment_status == EnrichmentStatus.ERROR

    def test_offline_mode_skips_without_erroring(self, db, tmp_path, monkeypatch) -> None:
        """Air-gapped deployments degrade, never fail — D-004."""
        from advisory_hub.config import get_settings
        from advisory_hub.core.models.advisory import AdvisoryCve
        from advisory_hub.core.services.enrichment import enrich_pending

        _seed_advisory(db, tmp_path, cve="CVE-2021-44228")
        monkeypatch.setenv("NVD_ENABLED", "false")
        get_settings.cache_clear()
        try:
            report = enrich_pending(db, cache=_NoCache())
        finally:
            get_settings.cache_clear()
        db.flush()

        assert report.skipped == 1
        row = db.scalars(select(AdvisoryCve)).first()
        assert row is not None
        assert row.enrichment_status == EnrichmentStatus.SKIPPED_OFFLINE

    def test_severity_is_raised_but_never_lowered(self, db, tmp_path) -> None:
        """NVD may add information; it must not downgrade the regulator's
        Critical — see D-019."""
        from advisory_hub.core.services.enrichment import enrich_pending

        advisory = _seed_advisory(
            db, tmp_path, cve="CVE-2026-0001", severity=Severity.CRITICAL, priority=Priority.P1
        )
        low = {
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Minor issue."}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {"version": "3.1", "baseScore": 3.1, "vectorString": "v"},
                    }
                ]
            },
        }
        with _fast_client(_ok_handler({"vulnerabilities": [{"cve": low}]})) as client:
            enrich_pending(db, client=client, cache=_NoCache())
        db.flush()
        db.refresh(advisory)

        assert advisory.severity is Severity.CRITICAL
        assert advisory.priority is Priority.P1

    def test_severity_upgrade_moves_the_sla_clocks(self, db, tmp_path) -> None:
        from advisory_hub.core.services.enrichment import enrich_pending

        advisory = _seed_advisory(
            db, tmp_path, cve="CVE-2026-0002", severity=Severity.MEDIUM, priority=Priority.P3
        )
        assert advisory.ack_due_at is not None
        before = advisory.ack_due_at

        with _fast_client(
            _ok_handler({"vulnerabilities": [{"cve": {**LOG4SHELL, "id": "CVE-2026-0002"}}]})
        ) as client:
            enrich_pending(db, client=client, cache=_NoCache())
        db.flush()
        db.refresh(advisory)

        assert advisory.severity is Severity.CRITICAL
        assert advisory.priority is Priority.P1
        assert advisory.ack_due_at is not None
        assert advisory.ack_due_at < before  # P1's 8h is tighter than P3's 72h
        ack_hours = (advisory.ack_due_at - advisory.received_at).total_seconds() / 3600
        assert ack_hours == 8

    def test_limit_is_respected_and_work_resumes(self, db, tmp_path) -> None:
        """A rate-limited backfill runs in batches; each must pick up where the
        last stopped, or a 50-minute run could never be interrupted safely."""
        from advisory_hub.core.models.advisory import AdvisoryCve
        from advisory_hub.core.services.enrichment import enrich_pending

        for n in range(4):
            _seed_advisory(db, tmp_path, cve=f"CVE-2026-100{n}")
        payload = {"vulnerabilities": [{"cve": LOG4SHELL}]}

        with _fast_client(_ok_handler(payload)) as client:
            first = enrich_pending(db, client=client, cache=_NoCache(), limit=2)
        db.flush()
        assert first.ok == 2

        still_pending = db.scalars(
            select(AdvisoryCve).where(AdvisoryCve.enrichment_status == EnrichmentStatus.PENDING)
        ).all()
        assert len(still_pending) == 2

        with _fast_client(_ok_handler(payload)) as client:
            second = enrich_pending(db, client=client, cache=_NoCache(), limit=2)
        db.flush()
        assert second.ok == 2

        remaining = db.scalars(
            select(AdvisoryCve).where(AdvisoryCve.enrichment_status == EnrichmentStatus.PENDING)
        ).all()
        assert remaining == []

    def test_already_enriched_rows_are_not_refetched(self, db, tmp_path) -> None:
        """Freshness check: a second run must not burn rate-limit budget."""
        from advisory_hub.core.services.enrichment import enrich_pending

        _seed_advisory(db, tmp_path, cve="CVE-2021-44228")
        payload = {"vulnerabilities": [{"cve": LOG4SHELL}]}
        with _fast_client(_ok_handler(payload)) as client:
            enrich_pending(db, client=client, cache=_NoCache())
        db.flush()

        with _fast_client(_ok_handler(payload)) as client:
            second = enrich_pending(db, client=client, cache=_NoCache())
        assert second.attempted == 0

    def test_reenrichment_replaces_cpe_rows(self, db, tmp_path) -> None:
        """Keeps the table in step when NVD revises a configuration."""
        from advisory_hub.core.models.advisory import CveCpe
        from advisory_hub.core.services.enrichment import enrich_pending

        _seed_advisory(db, tmp_path, cve="CVE-2021-44228")
        payload = {"vulnerabilities": [{"cve": LOG4SHELL}]}
        for _ in range(2):
            with _fast_client(_ok_handler(payload)) as client:
                enrich_pending(db, client=client, cache=_NoCache(), force=True)
            db.flush()

        rows = db.scalars(select(CveCpe).where(CveCpe.cve_id == "CVE-2021-44228")).all()
        assert len(rows) == 2, "re-enrichment must replace, not accumulate"


class _NoCache:
    """Cache stub — keeps tests off Redis and makes every call a live fetch."""

    def get(self, cve_id: str) -> object:
        from advisory_hub.enrich.cache import MISS

        return MISS

    def put(self, cve_id: str, record: object) -> None:
        return None


def _seed_advisory(
    db: Any,
    tmp_path: Any,
    *,
    cve: str,
    severity: Severity = Severity.HIGH,
    priority: Priority = Priority.P2,
) -> Any:
    from datetime import UTC, datetime, timedelta

    from advisory_hub.core.models.advisory import Advisory, AdvisoryCve, Source
    from advisory_hub.core.models.enums import SLA_HOURS, AdvisoryType

    source = db.scalar(select(Source).where(Source.short_code == "TEST"))
    if source is None:
        source = Source(
            name="Test Source", short_code="TEST", sender_patterns=["t@example.invalid"]
        )
        db.add(source)
        db.flush()

    received = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    ack_hours, resolve_hours = SLA_HOURS[priority]
    advisory = Advisory(
        source_id=source.id,
        external_ref=f"TEST-{cve[-4:]}",
        type=AdvisoryType.CVE_ADVISORY,
        title=f"Test advisory for {cve}",
        received_at=received,
        dedupe_hash=cve.ljust(64, "0")[:64].replace("-", "0").lower(),
        parser_version="1",
        severity=severity,
        priority=priority,
        ack_due_at=received + timedelta(hours=ack_hours),
        resolution_due_at=received + timedelta(hours=resolve_hours),
    )
    db.add(advisory)
    db.flush()
    db.add(
        AdvisoryCve(
            advisory_id=advisory.id,
            cve_id=cve,
            found_in=["PDF"],
            enrichment_status=EnrichmentStatus.PENDING,
        )
    )
    db.flush()
    return advisory
