"""VirusTotal API v3 client — on-demand IOC reputation checks.

Unlike NVD (Phase 1b), this is never an automatic background sweep: an
analyst clicks "Check on VirusTotal" for one specific indicator, and only
that indicator is looked up. That keeps it well inside VT's public-tier
rate limit (4 requests/minute, 500/day) without needing the scheduling
machinery NVD's continuous backfill needed.

**Not every `IocType` is checkable.** VT's REST API only has dedicated
lookup endpoints for IPs, domains, URLs, and file hashes — not emails,
filenames, file paths, registry keys, mutexes, or user agents. Those are
reported as unsupported at the service layer, not silently guessed at
(CLAUDE.md §2.2).

**No SSRF concern here**, unlike the inventory API adapters (Phase 2c): the
destination host is always the fixed, trusted `www.virustotal.com` — only
the IOC *value* (untrusted, attacker-controlled content from a parsed
email) travels as a query parameter for VT's own database lookup. We never
fetch or resolve the IOC ourselves.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from ..config import settings
from ..core.models.enums import IocType
from ..logging import get_logger
from .nvd import RateLimiter

log = get_logger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
USER_AGENT = "advisory-hub/0.1 (internal security advisory portal)"

#: VT's public-tier documented limit is 4 requests/minute. One below it,
#: same margin-of-safety reasoning as NVD's limiter.
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_CALLS = 3

REQUEST_TIMEOUT_SECONDS = 20.0

#: (path segment, GUI permalink segment) per lookup-capable IOC type.
_ENDPOINT_BY_TYPE: dict[IocType, tuple[str, str]] = {
    IocType.IPV4: ("ip_addresses", "ip-address"),
    IocType.IPV6: ("ip_addresses", "ip-address"),
    IocType.DOMAIN: ("domains", "domain"),
    IocType.URL: ("urls", "url"),
    IocType.MD5: ("files", "file"),
    IocType.SHA1: ("files", "file"),
    IocType.SHA256: ("files", "file"),
}


class VtError(Exception):
    """Transport or protocol failure. Never fatal to the advisory view."""


class VtRateLimitedError(VtError):
    pass


class VtUnauthorizedError(VtError):
    """The configured API key was rejected."""


class VtUnsupportedIocTypeError(Exception):
    def __init__(self, ioc_type: IocType) -> None:
        super().__init__(f"VirusTotal has no lookup endpoint for {ioc_type.value}")
        self.ioc_type = ioc_type


@dataclass(frozen=True, slots=True)
class VtResult:
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    reputation: int | None
    last_analysis_at: datetime | None
    permalink: str


def is_supported(ioc_type: IocType) -> bool:
    return ioc_type in _ENDPOINT_BY_TYPE


def _object_id(ioc_type: IocType, value: str) -> str:
    """VT's REST path segment for a given indicator.

    Hashes are used as-is. URLs use VT's documented SHA256-of-URL scheme
    for the v3 API object ID (its own historical base64 scheme is v2-only).
    IPs and domains are used as-is.
    """
    if ioc_type is IocType.URL:
        return hashlib.sha256(value.encode()).hexdigest()
    return value


class VtClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.vt_api_key
        self.rate_limiter = rate_limiter or RateLimiter(RATE_LIMIT_CALLS, RATE_LIMIT_WINDOW_SECONDS)
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> VtClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=REQUEST_TIMEOUT_SECONDS,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=False,
            )
        return self._client

    def lookup(self, ioc_type: IocType, value: str) -> VtResult | None:
        """Look up one indicator. ``None`` means VT has never seen it —
        a legitimate, common outcome, not an error.

        Raises ``VtError``/``VtUnauthorizedError``/``VtRateLimitedError``
        for transport failures, so the caller can record ``ERROR`` rather
        than silently reporting "clean".
        """
        if not self.api_key:
            raise VtUnauthorizedError("VT_API_KEY is not configured")

        if ioc_type not in _ENDPOINT_BY_TYPE:
            raise VtUnsupportedIocTypeError(ioc_type)
        segment, permalink_segment = _ENDPOINT_BY_TYPE[ioc_type]

        object_id = _object_id(ioc_type, value)
        self.rate_limiter.acquire()

        try:
            response = self.client.get(
                f"{VT_BASE_URL}/{segment}/{object_id}", headers={"x-apikey": self.api_key}
            )
        except httpx.HTTPError as exc:
            raise VtError(f"VirusTotal unreachable: {type(exc).__name__}: {exc}") from exc

        if response.status_code == 404:
            return None
        if response.status_code == 401:
            raise VtUnauthorizedError("VirusTotal rejected the configured API key")
        if response.status_code == 429:
            raise VtRateLimitedError("VirusTotal rate limit exceeded")
        if response.status_code != 200:
            raise VtError(f"Unexpected HTTP {response.status_code} from VirusTotal")

        try:
            payload = response.json()
        except ValueError as exc:
            raise VtError("Malformed JSON from VirusTotal") from exc

        return _parse_result(payload, permalink_segment, object_id)


def _parse_result(payload: dict[str, Any], permalink_segment: str, object_id: str) -> VtResult:
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    last_analysis_ts = attributes.get("last_analysis_date")
    return VtResult(
        malicious_count=int(stats.get("malicious") or 0),
        suspicious_count=int(stats.get("suspicious") or 0),
        harmless_count=int(stats.get("harmless") or 0),
        undetected_count=int(stats.get("undetected") or 0),
        reputation=attributes.get("reputation"),
        last_analysis_at=(
            datetime.fromtimestamp(last_analysis_ts, tz=UTC) if last_analysis_ts else None
        ),
        permalink=f"https://www.virustotal.com/gui/{permalink_segment}/{object_id}",
    )
