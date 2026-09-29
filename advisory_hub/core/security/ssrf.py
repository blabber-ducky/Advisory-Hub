"""SSRF guard for inventory-integration outbound calls.

Inventory-source URLs are user-supplied — CLAUDE.md §2.3 says to assume SSRF
is being attempted. `validate_outbound_url()` is called both when a source's
config is saved (catches the obvious case early) and before every actual
outbound request an adapter makes (Phase 2c) — DNS can rebind between the two
moments, so config-time validation alone isn't enough. Adapters must also
construct their HTTP client with `follow_redirects=False` (see
`enrich/nvd.py` for the existing precedent) since a redirect to a blocked
host would otherwise bypass this entirely.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from ...config import settings


class SsrfBlockedError(Exception):
    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"Blocked outbound URL {url!r}: {reason}")
        self.url = url
        self.reason = reason


#: Cloud instance-metadata endpoints, blocked outright regardless of
#: allowlist — an allowlisted hostname that DNS-rebinds to one of these must
#: still be blocked.
_BLOCKED_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / DigitalOcean instance metadata
        "fd00:ec2::254",  # AWS IMDSv2, IPv6
    }
)


def validate_outbound_url(url: str) -> None:
    """Raise `SsrfBlockedError` unless `url` is `https`, its host is on
    `OUTBOUND_ALLOWLIST`, and every address it resolves to is public and
    routable."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SsrfBlockedError(url, "only https is permitted")

    host = parsed.hostname
    if not host:
        raise SsrfBlockedError(url, "no hostname")

    if host.lower() not in settings.allowlisted_hosts:
        raise SsrfBlockedError(url, f"{host} is not in OUTBOUND_ALLOWLIST")

    try:
        addrinfo = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise SsrfBlockedError(url, f"DNS resolution failed: {exc}") from exc

    for _family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.compressed in _BLOCKED_METADATA_IPS:
            raise SsrfBlockedError(url, f"{host} resolves to a cloud metadata address ({ip})")
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_private
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise SsrfBlockedError(url, f"{host} resolves to a non-routable address ({ip})")
