"""SSRF guard — allowlist, scheme, and non-routable address rejection."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from advisory_hub.core.security.ssrf import SsrfBlockedError, validate_outbound_url


@pytest.fixture(autouse=True)
def _allowlist(monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "dc.internal.example, graph.microsoft.com")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _resolves_to(*ips: str):
    """Mock socket.getaddrinfo to resolve any hostname to the given IPs."""
    return patch(
        "advisory_hub.core.security.ssrf.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443)) for ip in ips],
    )


class TestSchemeAndAllowlist:
    def test_non_https_is_rejected(self) -> None:
        with pytest.raises(SsrfBlockedError, match="only https"):
            validate_outbound_url("http://dc.internal.example")

    def test_no_hostname_is_rejected(self) -> None:
        with pytest.raises(SsrfBlockedError, match="no hostname"):
            validate_outbound_url("https:///path")

    def test_host_not_on_allowlist_is_rejected(self) -> None:
        with pytest.raises(SsrfBlockedError, match="not in OUTBOUND_ALLOWLIST"):
            validate_outbound_url("https://not-allowed.example.com")

    def test_allowlist_is_case_insensitive(self) -> None:
        with _resolves_to("1.1.1.1"):
            validate_outbound_url("https://DC.INTERNAL.EXAMPLE")

    def test_dns_failure_is_reported_cleanly(self) -> None:
        with (
            patch(
                "advisory_hub.core.security.ssrf.socket.getaddrinfo",
                side_effect=OSError("nodename nor servname provided"),
            ),
            pytest.raises(SsrfBlockedError, match="DNS resolution failed"),
        ):
            validate_outbound_url("https://dc.internal.example")


class TestNonRoutableAddresses:
    def test_public_address_passes(self) -> None:
        with _resolves_to("1.1.1.1"):
            validate_outbound_url("https://dc.internal.example")

    def test_loopback_is_blocked(self) -> None:
        with _resolves_to("127.0.0.1"), pytest.raises(SsrfBlockedError, match="non-routable"):
            validate_outbound_url("https://dc.internal.example")

    def test_link_local_is_blocked(self) -> None:
        with _resolves_to("169.254.1.1"), pytest.raises(SsrfBlockedError, match="non-routable"):
            validate_outbound_url("https://dc.internal.example")

    def test_private_range_is_blocked(self) -> None:
        with _resolves_to("10.0.0.5"), pytest.raises(SsrfBlockedError, match="non-routable"):
            validate_outbound_url("https://dc.internal.example")

    def test_cloud_metadata_ip_is_blocked_explicitly(self) -> None:
        """169.254.169.254 is link-local too, but this is the specific,
        named case CLAUDE.md §2.3 calls out — verify the dedicated message."""
        with (
            _resolves_to("169.254.169.254"),
            pytest.raises(SsrfBlockedError, match="cloud metadata"),
        ):
            validate_outbound_url("https://dc.internal.example")

    def test_multicast_is_blocked(self) -> None:
        with _resolves_to("224.0.0.1"), pytest.raises(SsrfBlockedError, match="non-routable"):
            validate_outbound_url("https://dc.internal.example")

    def test_one_bad_address_among_several_blocks_the_whole_host(self) -> None:
        """A hostname that resolves to both a public and a private address
        (round-robin, split DNS) must not be treated as safe."""
        with (
            _resolves_to("1.1.1.1", "10.0.0.5"),
            pytest.raises(SsrfBlockedError, match="non-routable"),
        ):
            validate_outbound_url("https://dc.internal.example")
