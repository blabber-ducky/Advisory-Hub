"""Password hashing, API tokens, roles, and the SLA/transition tables."""

from __future__ import annotations

import pytest

from advisory_hub.core.models.enums import (
    ALLOWED_TRANSITIONS,
    SEVERITY_TO_PRIORITY,
    SLA_HOURS,
    AdvisoryStatus,
    Priority,
    Role,
    Severity,
)
from advisory_hub.core.security.passwords import (
    hash_password,
    needs_rehash,
    verify_password,
)
from advisory_hub.core.security.tokens import (
    Scope,
    mint_token,
    split_token,
    validate_scopes,
    verify_token,
)


class TestPasswords:
    def test_roundtrip(self) -> None:
        h = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", h) is True
        assert verify_password("wrong", h) is False

    def test_salted(self) -> None:
        assert hash_password("same") != hash_password("same")

    def test_absent_hash_is_false_not_an_error(self) -> None:
        """Missing accounts must fail like wrong passwords, not differently."""
        assert verify_password("anything", None) is False
        assert verify_password("anything", "") is False

    def test_current_hashes_do_not_need_rehash(self) -> None:
        assert needs_rehash(hash_password("x" * 16)) is False

    def test_malformed_hash_needs_rehash(self) -> None:
        assert needs_rehash("not-an-argon2-hash") is True


class TestApiTokens:
    def test_mint_and_verify(self) -> None:
        minted = mint_token()
        assert minted.plaintext.startswith("ah_")
        assert minted.prefix in minted.plaintext
        assert verify_token(minted.plaintext, minted.token_hash) is True

    def test_secret_is_not_recoverable_from_hash(self) -> None:
        minted = mint_token()
        assert minted.plaintext not in minted.token_hash

    def test_wrong_token_rejected(self) -> None:
        a, b = mint_token(), mint_token()
        assert verify_token(a.plaintext, b.token_hash) is False

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "nope",
            "ah_only",
            "wrong_abcdef01_secret",
            "ah__emptyprefix",
            "ah_abcdef01_",
            "ah_short_secret",  # prefix wrong length
            "ah_ZZZZZZZZ_secret",  # prefix outside the hex alphabet
        ],
    )
    def test_malformed_tokens_rejected(self, bad: str) -> None:
        assert split_token(bad) is None

    def test_every_minted_token_round_trips(self) -> None:
        """Regression: a `_` in the prefix used to break `split_token`, minting
        tokens that could never authenticate — roughly 1 in 8. See tokens.py."""
        for _ in range(500):
            minted = mint_token()
            parts = split_token(minted.plaintext)
            assert parts is not None, f"unparseable token: {minted.plaintext}"
            assert parts[0] == minted.prefix

    def test_prefix_never_contains_the_separator(self) -> None:
        for _ in range(500):
            assert "_" not in mint_token().prefix

    def test_secret_may_contain_the_separator(self) -> None:
        """The secret is the remainder after maxsplit=2, so `_` there is fine."""
        parts = split_token("ah_abcdef01_secret_with_underscores")
        assert parts is not None
        assert parts[0] == "abcdef01"

    def test_unknown_scopes_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unknown scope"):
            validate_scopes(["advisories:read", "advisories:delete-everything"])

    def test_scopes_deduped_and_sorted(self) -> None:
        got = validate_scopes([Scope.STATS_READ, Scope.ADVISORIES_READ, Scope.ADVISORIES_READ])
        assert got == [Scope.ADVISORIES_READ, Scope.STATS_READ]


class TestRoles:
    def test_hierarchy(self) -> None:
        assert Role.ADMIN.satisfies(Role.ANALYST)
        assert Role.ADMIN.satisfies(Role.VIEWER)
        assert Role.ANALYST.satisfies(Role.VIEWER)

    def test_no_upward_escalation(self) -> None:
        assert not Role.VIEWER.satisfies(Role.ANALYST)
        assert not Role.ANALYST.satisfies(Role.ADMIN)


class TestSlaTable:
    """The regulator's SLA, embedded in all 135 corpus emails — see D-018."""

    def test_matches_the_regulator_table(self) -> None:
        assert SLA_HOURS[Priority.P1] == (8, 24)
        assert SLA_HOURS[Priority.P2] == (16, 48)
        assert SLA_HOURS[Priority.P3] == (72, 120)
        assert SLA_HOURS[Priority.P4] == (72, 120)

    def test_every_severity_maps_to_a_priority(self) -> None:
        for severity in Severity:
            assert SEVERITY_TO_PRIORITY[severity] in Priority

    def test_critical_is_p1(self) -> None:
        assert SEVERITY_TO_PRIORITY[Severity.CRITICAL] is Priority.P1

    def test_ack_deadline_always_precedes_resolution(self) -> None:
        for priority, (ack, resolve) in SLA_HOURS.items():
            assert ack < resolve, f"{priority}: ack {ack}h must precede resolve {resolve}h"


class TestStatusTransitions:
    def test_every_status_has_an_entry(self) -> None:
        assert set(ALLOWED_TRANSITIONS) == set(AdvisoryStatus)

    def test_no_transition_targets_new(self) -> None:
        """NEW is only ever the ingestion starting state."""
        for targets in ALLOWED_TRANSITIONS.values():
            assert AdvisoryStatus.NEW not in targets

    def test_closed_is_reopenable(self) -> None:
        """Regulators re-issue advisories — nothing is a dead end."""
        assert ALLOWED_TRANSITIONS[AdvisoryStatus.CLOSED]

    def test_acknowledged_is_reachable_from_new(self) -> None:
        assert AdvisoryStatus.ACKNOWLEDGED in ALLOWED_TRANSITIONS[AdvisoryStatus.NEW]

    def test_no_status_transitions_to_itself(self) -> None:
        for status, targets in ALLOWED_TRANSITIONS.items():
            assert status not in targets

    def test_all_targets_are_valid_statuses(self) -> None:
        for targets in ALLOWED_TRANSITIONS.values():
            for target in targets:
                assert isinstance(target, AdvisoryStatus)
