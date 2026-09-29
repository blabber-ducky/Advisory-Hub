"""Unit tests for `core.services.advisories` — the tracker/dashboard read paths.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from advisory_hub.core.models.advisory import (
    Advisory,
    AdvisoryFlag,
    AdvisoryIoc,
    Comment,
    Source,
    StatusChange,
)
from advisory_hub.core.models.enums import (
    SLA_HOURS,
    AckChannel,
    ActorKind,
    AdvisoryStatus,
    AdvisoryType,
    FlagKind,
    IocType,
    Priority,
    Severity,
)
from advisory_hub.core.models.user import AuditLog, User
from advisory_hub.core.services import advisories as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration


@pytest.fixture
def source(db) -> Source:
    src = Source(name="Test Regulator", short_code="TR", sender_patterns=["t@example.invalid"])
    db.add(src)
    db.flush()
    return src


def _make_advisory(
    db: Any,
    source: Source,
    *,
    ref: str,
    title: str = "Test advisory",
    type: AdvisoryType = AdvisoryType.CVE_ADVISORY,
    severity: Severity = Severity.HIGH,
    priority: Priority = Priority.P2,
    status: AdvisoryStatus = AdvisoryStatus.NEW,
    received_at: datetime | None = None,
    acknowledged_at: datetime | None = None,
) -> Advisory:
    received = received_at or datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    ack_hours, resolve_hours = SLA_HOURS[priority]
    advisory = Advisory(
        source_id=source.id,
        external_ref=ref,
        type=type,
        title=title,
        received_at=received,
        dedupe_hash=ref.ljust(64, "0").lower(),
        parser_version="1",
        severity=severity,
        priority=priority,
        status=status,
        ack_due_at=received + timedelta(hours=ack_hours),
        resolution_due_at=received + timedelta(hours=resolve_hours),
        acknowledged_at=acknowledged_at,
    )
    db.add(advisory)
    db.flush()
    return advisory


class TestListAdvisories:
    def test_returns_all_when_no_filters(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1")
        _make_advisory(db, source, ref="A-2")
        result = svc.list_advisories(db)
        assert result.total == 2
        assert len(result.items) == 2

    def test_filters_by_status(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        _make_advisory(db, source, ref="A-2", status=AdvisoryStatus.CLOSED)
        result = svc.list_advisories(db, svc.AdvisoryFilters(status=[AdvisoryStatus.CLOSED]))
        assert result.total == 1
        assert result.items[0].external_ref == "A-2"

    def test_open_only_excludes_terminal_statuses(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        _make_advisory(db, source, ref="A-2", status=AdvisoryStatus.CLOSED)
        _make_advisory(db, source, ref="A-3", status=AdvisoryStatus.RISK_ACCEPTED)
        result = svc.list_advisories(db, svc.AdvisoryFilters(open_only=True))
        assert result.total == 1
        assert result.items[0].external_ref == "A-1"

    def test_unacknowledged_only(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1", acknowledged_at=None)
        _make_advisory(db, source, ref="A-2", acknowledged_at=datetime.now(UTC))
        result = svc.list_advisories(db, svc.AdvisoryFilters(unacknowledged_only=True))
        assert result.total == 1
        assert result.items[0].external_ref == "A-1"

    def test_pagination(self, db, source: Source) -> None:
        for i in range(5):
            _make_advisory(db, source, ref=f"A-{i}")
        result = svc.list_advisories(db, page=1, page_size=2)
        assert result.total == 5
        assert len(result.items) == 2
        assert result.total_pages == 3
        assert result.has_next
        assert not result.has_prev

    def test_page_size_is_capped(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1")
        result = svc.list_advisories(db, page_size=10_000)
        assert result.page_size == svc.MAX_PAGE_SIZE

    def test_search_matches_external_ref(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="DOH-2026551", title="A SharePoint RCE")
        _make_advisory(db, source, ref="DOH-2026999", title="Unrelated advisory")
        result = svc.list_advisories(db, svc.AdvisoryFilters(q="2026551"))
        assert result.total == 1
        assert result.items[0].external_ref == "DOH-2026551"


class TestGetAdvisory:
    def test_returns_none_for_unknown_id(self, db) -> None:
        import uuid

        assert svc.get_advisory(db, uuid.uuid4()) is None

    def test_eager_loads_children(self, db, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1")
        loaded = svc.get_advisory(db, advisory.id)
        assert loaded is not None
        # Accessing these must not trigger a lazy-load outside the session.
        assert loaded.cves == []
        assert loaded.iocs == []
        assert loaded.products == []


class TestComments:
    def test_last_comments_for_picks_the_newest_per_advisory(self, db, source: Source) -> None:
        a1 = _make_advisory(db, source, ref="A-1")
        a2 = _make_advisory(db, source, ref="A-2")
        db.add_all(
            [
                Comment(
                    advisory_id=a1.id,
                    body="first",
                    created_at=datetime(2026, 8, 1, tzinfo=UTC),
                ),
                Comment(
                    advisory_id=a1.id,
                    body="second, newer",
                    created_at=datetime(2026, 8, 2, tzinfo=UTC),
                ),
                Comment(
                    advisory_id=a2.id,
                    body="only one",
                    created_at=datetime(2026, 8, 1, tzinfo=UTC),
                ),
            ]
        )
        db.flush()

        result = svc.last_comments_for(db, [a1.id, a2.id])
        assert result[a1.id].body == "second, newer"
        assert result[a2.id].body == "only one"

    def test_empty_id_list_returns_empty_dict(self, db) -> None:
        assert svc.last_comments_for(db, []) == {}


class TestDashboardStats:
    def test_counts_open_and_unacknowledged(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW, acknowledged_at=None)
        _make_advisory(
            db,
            source,
            ref="A-2",
            status=AdvisoryStatus.CLOSED,
            acknowledged_at=datetime.now(UTC),
        )
        stats = svc.dashboard_stats(db)
        assert stats.total_open == 1
        assert stats.unacknowledged == 1

    def test_ack_overdue_counts_past_due_unacked(self, db, source: Source) -> None:
        _make_advisory(
            db,
            source,
            ref="A-1",
            received_at=datetime(2020, 1, 1, tzinfo=UTC),
            acknowledged_at=None,
        )
        stats = svc.dashboard_stats(db)
        assert stats.ack_overdue == 1

    def test_flagged_for_review_counts_distinct_advisories(self, db, source: Source) -> None:
        a1 = _make_advisory(db, source, ref="A-1")
        db.add(AdvisoryFlag(advisory_id=a1.id, kind=FlagKind.LOW_TYPE_CONFIDENCE, detail={}))
        db.flush()
        stats = svc.dashboard_stats(db)
        assert stats.flagged_for_review == 1

    def test_by_status_groups_correctly(self, db, source: Source) -> None:
        _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        _make_advisory(db, source, ref="A-2", status=AdvisoryStatus.NEW)
        _make_advisory(db, source, ref="A-3", status=AdvisoryStatus.CLOSED)
        stats = svc.dashboard_stats(db)
        assert stats.by_status[AdvisoryStatus.NEW.value] == 2
        assert stats.by_status[AdvisoryStatus.CLOSED.value] == 1


class TestSourcesForFilter:
    def test_only_active_sources_returned(self, db, source: Source) -> None:
        inactive = Source(
            name="Retired",
            short_code="OLD",
            sender_patterns=["old@example.invalid"],
            is_active=False,
        )
        db.add(inactive)
        db.flush()
        result = svc.sources_for_filter(db)
        assert source in result
        assert inactive not in result


def _add_iocs(db: Any, advisory: Advisory, *types: IocType) -> None:
    """One IOC per entry — pass a type twice to give an advisory two of it."""
    for index, ioc_type in enumerate(types):
        value = f"{advisory.external_ref}-{ioc_type.value}-{index}"
        db.add(
            AdvisoryIoc(
                advisory_id=advisory.id,
                ioc_type=ioc_type,
                value=value,
                defanged_value=value,
            )
        )
    db.flush()


class TestIocBreakdownsFor:
    def test_empty_ids_returns_empty(self, db) -> None:
        assert svc.ioc_breakdowns_for(db, []) == {}

    def test_advisory_without_iocs_is_absent_not_zero_filled(self, db, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1")
        assert svc.ioc_breakdowns_for(db, [advisory.id]) == {}

    def test_counts_per_type(self, db, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1")
        _add_iocs(db, advisory, IocType.SHA256, IocType.SHA256, IocType.DOMAIN)
        breakdown = svc.ioc_breakdowns_for(db, [advisory.id])[advisory.id]
        assert breakdown.counts == {IocType.SHA256: 2, IocType.DOMAIN: 1}
        assert breakdown.total == 3
        assert breakdown.type_count == 2

    def test_by_count_orders_most_numerous_first(self, db, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1")
        _add_iocs(db, advisory, IocType.DOMAIN, IocType.SHA256, IocType.SHA256, IocType.IPV4)
        breakdown = svc.ioc_breakdowns_for(db, [advisory.id])[advisory.id]
        # SHA256 leads on count; DOMAIN before IPV4 breaks the 1-1 tie
        # alphabetically, so chip order is stable across renders.
        assert breakdown.by_count == [(IocType.SHA256, 2), (IocType.DOMAIN, 1), (IocType.IPV4, 1)]

    def test_batches_multiple_advisories_without_crosstalk(self, db, source: Source) -> None:
        a1 = _make_advisory(db, source, ref="A-1")
        a2 = _make_advisory(db, source, ref="A-2")
        _add_iocs(db, a1, IocType.URL)
        _add_iocs(db, a2, IocType.MD5, IocType.EMAIL)
        breakdowns = svc.ioc_breakdowns_for(db, [a1.id, a2.id])
        assert breakdowns[a1.id].counts == {IocType.URL: 1}
        assert breakdowns[a2.id].counts == {IocType.MD5: 1, IocType.EMAIL: 1}


class TestSortByIocs:
    """`ioc_type_count` ranks by how many *kinds* of indicator an advisory
    carries, `ioc_count` by how many indicators — deliberately different
    orderings, so both are exercised against the same fixture."""

    @pytest.fixture
    def corpus(self, db, source: Source) -> dict[str, Advisory]:
        # many-iocs: 5 indicators but only 2 kinds.
        # many-types: 3 indicators across 3 kinds.
        # no-iocs: none at all — must still be listed, and sort as zero.
        many_iocs = _make_advisory(db, source, ref="many-iocs")
        many_types = _make_advisory(db, source, ref="many-types")
        none = _make_advisory(db, source, ref="no-iocs")
        _add_iocs(
            db,
            many_iocs,
            IocType.SHA256,
            IocType.SHA256,
            IocType.SHA256,
            IocType.SHA256,
            IocType.DOMAIN,
        )
        _add_iocs(db, many_types, IocType.IPV4, IocType.DOMAIN, IocType.REGISTRY_KEY)
        return {"many_iocs": many_iocs, "many_types": many_types, "none": none}

    def _refs(self, db, sort: str) -> list[str]:
        return [a.external_ref for a in svc.list_advisories(db, sort=sort).items]

    def test_most_ioc_types_first(self, db, corpus) -> None:
        assert self._refs(db, "-ioc_type_count") == ["many-types", "many-iocs", "no-iocs"]

    def test_most_iocs_first_ranks_differently(self, db, corpus) -> None:
        assert self._refs(db, "-ioc_count") == ["many-iocs", "many-types", "no-iocs"]

    def test_fewest_first_puts_ioc_free_advisories_at_the_top(self, db, corpus) -> None:
        assert self._refs(db, "ioc_type_count")[0] == "no-iocs"
        assert self._refs(db, "ioc_count")[0] == "no-iocs"

    def test_join_does_not_duplicate_or_drop_rows(self, db, corpus) -> None:
        # A LEFT JOIN against an ungrouped advisory_ioc would fan an advisory
        # out to one row per indicator; an inner join would drop `no-iocs`.
        result = svc.list_advisories(db, sort="-ioc_count")
        assert result.total == 3
        assert len(result.items) == 3

    def test_ties_fall_back_to_recency(self, db, source: Source) -> None:
        aug1 = datetime(2026, 8, 1, tzinfo=UTC)
        aug5 = datetime(2026, 8, 5, tzinfo=UTC)
        older = _make_advisory(db, source, ref="older", received_at=aug1)
        newer = _make_advisory(db, source, ref="newer", received_at=aug5)
        _add_iocs(db, older, IocType.DOMAIN)
        _add_iocs(db, newer, IocType.IPV4)
        assert self._refs(db, "-ioc_type_count") == ["newer", "older"]

    def test_sort_respects_filters(self, db, corpus, source: Source) -> None:
        result = svc.list_advisories(
            db,
            svc.AdvisoryFilters(q="many-types"),
            sort="-ioc_type_count",
        )
        assert [a.external_ref for a in result.items] == ["many-types"]


class TestNormaliseSort:
    def test_known_key_passes_through(self) -> None:
        assert svc.normalise_sort("-ioc_type_count") == "-ioc_type_count"

    @pytest.mark.parametrize("raw", [None, "", "nonsense", "received_at; DROP TABLE advisory"])
    def test_unknown_key_falls_back_to_default(self, raw: str | None) -> None:
        assert svc.normalise_sort(raw) == svc.DEFAULT_SORT

    def test_every_offered_option_is_accepted(self) -> None:
        for key, _label in svc.SORT_OPTIONS:
            assert svc.normalise_sort(key) == key


class TestChildCountsFor:
    def test_empty_ids_returns_empty(self, db) -> None:
        assert svc.child_counts_for(db, []) == {}

    def test_zero_filled_for_advisories_with_no_children(self, db, source: Source) -> None:
        advisory = _make_advisory(db, source, ref="A-1")
        counts = svc.child_counts_for(db, [advisory.id])
        assert counts[advisory.id] == {"cves": 0, "iocs": 0}


@pytest.fixture
def analyst(db) -> User:
    user = User(email="analyst@example.invalid", display_name="Test Analyst", role="ANALYST")
    db.add(user)
    db.flush()
    return user


def _actor(user: User) -> Actor:
    return Actor(kind=ActorKind.USER, user_id=user.id, label=user.display_name)


class TestChangeStatus:
    def test_happy_path_updates_status_and_writes_trail(
        self, db, source: Source, analyst: User
    ) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)

        result = svc.change_status(
            db,
            advisory.id,
            to_status=AdvisoryStatus.TRIAGED,
            comment_body="Confirmed relevant to our estate.",
            actor=_actor(analyst),
        )

        assert advisory.status == AdvisoryStatus.TRIAGED
        assert result.from_status == AdvisoryStatus.NEW
        assert result.to_status == AdvisoryStatus.TRIAGED
        assert result.actor_id == analyst.id

        comment = db.get(Comment, result.comment_id)
        assert comment is not None
        assert comment.body == "Confirmed relevant to our estate."
        assert comment.is_status_change is True

        audit = db.scalar(select(AuditLog).where(AuditLog.action == "advisory.status_changed"))
        assert audit is not None
        assert audit.entity_id == advisory.id
        assert audit.detail["from"] == "NEW"
        assert audit.detail["to"] == "TRIAGED"

    def test_blank_comment_is_rejected(self, db, source: Source, analyst: User) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        with pytest.raises(svc.MissingCommentError):
            svc.change_status(
                db,
                advisory.id,
                to_status=AdvisoryStatus.TRIAGED,
                comment_body="   ",
                actor=_actor(analyst),
            )
        assert advisory.status == AdvisoryStatus.NEW

    def test_illegal_transition_is_rejected(self, db, source: Source, analyst: User) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        with pytest.raises(svc.InvalidStatusTransitionError):
            svc.change_status(
                db,
                advisory.id,
                to_status=AdvisoryStatus.CLOSED,
                comment_body="Skipping ahead.",
                actor=_actor(analyst),
            )
        assert advisory.status == AdvisoryStatus.NEW

    def test_acknowledging_without_a_channel_is_rejected(
        self, db, source: Source, analyst: User
    ) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        with pytest.raises(svc.MissingAckChannelError):
            svc.change_status(
                db,
                advisory.id,
                to_status=AdvisoryStatus.ACKNOWLEDGED,
                comment_body="Acknowledged via email.",
                actor=_actor(analyst),
            )
        assert advisory.acknowledged_at is None

    def test_acknowledging_records_the_ack_clock(self, db, source: Source, analyst: User) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        svc.change_status(
            db,
            advisory.id,
            to_status=AdvisoryStatus.ACKNOWLEDGED,
            comment_body="Acknowledged via email to the regulator.",
            actor=_actor(analyst),
            ack_channel=AckChannel.EMAIL,
        )
        assert advisory.status == AdvisoryStatus.ACKNOWLEDGED
        assert advisory.acknowledged_at is not None
        assert advisory.acknowledged_by_id == analyst.id
        assert advisory.ack_channel == AckChannel.EMAIL

    def test_unknown_advisory_raises(self, db, analyst: User) -> None:
        import uuid

        with pytest.raises(svc.AdvisoryNotFoundError):
            svc.change_status(
                db,
                uuid.uuid4(),
                to_status=AdvisoryStatus.TRIAGED,
                comment_body="doesn't matter",
                actor=_actor(analyst),
            )

    def test_closed_can_be_reopened_to_triaged(self, db, source: Source, analyst: User) -> None:
        """Regulators re-issue advisories — nothing is a dead end. See D-020."""
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.CLOSED)
        svc.change_status(
            db,
            advisory.id,
            to_status=AdvisoryStatus.TRIAGED,
            comment_body="Re-issued by the regulator; reopening.",
            actor=_actor(analyst),
        )
        assert advisory.status == AdvisoryStatus.TRIAGED

    def test_status_history_reflects_the_change(self, db, source: Source, analyst: User) -> None:
        advisory = _make_advisory(db, source, ref="A-1", status=AdvisoryStatus.NEW)
        svc.change_status(
            db,
            advisory.id,
            to_status=AdvisoryStatus.TRIAGED,
            comment_body="Confirmed relevant.",
            actor=_actor(analyst),
        )
        history = svc.get_status_history(db, advisory.id)
        assert len(history) == 1
        assert isinstance(history[0], StatusChange)
        assert history[0].to_status == AdvisoryStatus.TRIAGED


class TestNextStatuses:
    def test_new_can_move_to_acknowledged_triaged_or_not_applicable(self) -> None:
        assert svc.next_statuses(AdvisoryStatus.NEW) == [
            AdvisoryStatus.ACKNOWLEDGED,
            AdvisoryStatus.NOT_APPLICABLE,
            AdvisoryStatus.TRIAGED,
        ]

    def test_closed_can_only_reopen_to_triaged(self) -> None:
        assert svc.next_statuses(AdvisoryStatus.CLOSED) == [AdvisoryStatus.TRIAGED]
