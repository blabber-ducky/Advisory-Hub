"""NVD API 2.0 client.

Rate-limited, backed off, and cached. Enrichment is **optional** by design: any
failure is recorded on the CVE row and the advisory stays fully usable from
parsed content alone (D-004).

Response quirks this client handles, confirmed against the live API:

- ``metrics`` contains non-CVSS entries (``ssvcV203``) with no ``cvssData`` and
  a null score. Only ``cvssMetricV*`` keys are read.
- Several metrics may share a version; ``type: "Primary"`` from ``nvd@nist.gov``
  is preferred over secondary sources.
- ``published`` / ``lastModified`` carry **no timezone**; they are UTC.
"""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from ..config import settings
from ..logging import get_logger
from .cpe import Cpe, parse_cpe

log = get_logger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HOST = "services.nvd.nist.gov"
USER_AGENT = "advisory-hub/0.1 (internal security advisory portal)"

#: NVD's documented limits: 5 requests / 30s anonymous, 50 / 30s with a key.
#: Deliberately one below each, so a clock skew doesn't earn a 403.
RATE_LIMIT_WINDOW_SECONDS = 30.0
RATE_LIMIT_ANONYMOUS = 4
RATE_LIMIT_WITH_KEY = 45

MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 2.0
REQUEST_TIMEOUT_SECONDS = 30.0


class NvdError(Exception):
    """Transport or protocol failure. Never fatal to ingestion."""


class NvdRateLimitedError(NvdError):
    """NVD returns 403 for rate-limit violations, not only 429."""


@dataclass(frozen=True, slots=True)
class CvssMetric:
    version: str
    score: Decimal | None
    vector: str | None
    severity: str | None
    source: str | None
    is_primary: bool


@dataclass(frozen=True, slots=True)
class CpeMatch:
    cpe: Cpe
    vulnerable: bool
    version_start: str | None
    version_start_inclusive: bool
    version_end: str | None
    version_end_inclusive: bool


@dataclass(slots=True)
class NvdRecord:
    cve_id: str
    description: str | None = None
    published: datetime | None = None
    last_modified: datetime | None = None
    vuln_status: str | None = None
    metrics: list[CvssMetric] = field(default_factory=list)
    cpe_matches: list[CpeMatch] = field(default_factory=list)

    def best(self, version_prefix: str) -> CvssMetric | None:
        """Preferred metric for a CVSS major version, primary sources first."""
        candidates = [m for m in self.metrics if m.version.startswith(version_prefix)]
        if not candidates:
            return None
        candidates.sort(key=lambda m: (not m.is_primary, m.source != "nvd@nist.gov"))
        return candidates[0]

    @property
    def cvss_v3(self) -> CvssMetric | None:
        return self.best("3")

    @property
    def cvss_v4(self) -> CvssMetric | None:
        return self.best("4")


class RateLimiter:
    """Sliding-window limiter shared by every caller in this process."""

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a slot is free. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.window]
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return waited
                sleep_for = self.window - (now - self._calls[0]) + 0.05
            time.sleep(max(sleep_for, 0.05))
            waited += max(sleep_for, 0.05)


class NvdClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.nvd_api_key
        limit = RATE_LIMIT_WITH_KEY if self.api_key else RATE_LIMIT_ANONYMOUS
        self.rate_limiter = rate_limiter or RateLimiter(limit, RATE_LIMIT_WINDOW_SECONDS)
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> NvdClient:
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
                follow_redirects=False,  # a redirect off the NVD host is not followed
            )
        return self._client

    def fetch(self, cve_id: str) -> NvdRecord | None:
        """Fetch one CVE. ``None`` means NVD has no such record.

        Raises ``NvdError`` for transport failures so the caller can record
        ``ERROR`` and retry later, rather than marking the CVE as not-found.
        """
        headers = {"apiKey": self.api_key} if self.api_key else {}
        last_error: Exception | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            waited = self.rate_limiter.acquire()
            if waited > 1:
                log.debug("nvd.rate_limit_wait", seconds=round(waited, 1), cve_id=cve_id)
            try:
                response = self.client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
            except httpx.HTTPError as exc:
                last_error = exc
                self._sleep_backoff(attempt, cve_id, reason=type(exc).__name__)
                continue

            if response.status_code == 404:
                return None
            if response.status_code in (403, 429):
                # NVD returns 403 for rate-limit violations, not just 429.
                last_error = NvdRateLimitedError(f"HTTP {response.status_code}")
                self._sleep_backoff(
                    attempt,
                    cve_id,
                    reason=str(response.status_code),
                    retry_after=response.headers.get("retry-after"),
                )
                continue
            if response.status_code >= 500:
                last_error = NvdError(f"HTTP {response.status_code}")
                self._sleep_backoff(attempt, cve_id, reason=str(response.status_code))
                continue
            if response.status_code != 200:
                raise NvdError(f"Unexpected HTTP {response.status_code} for {cve_id}")

            try:
                payload = response.json()
            except ValueError as exc:
                raise NvdError(f"Malformed JSON for {cve_id}") from exc

            vulnerabilities = payload.get("vulnerabilities") or []
            if not vulnerabilities:
                return None
            return parse_nvd_cve(vulnerabilities[0].get("cve") or {})

        raise NvdError(f"NVD unreachable for {cve_id} after {MAX_ATTEMPTS} attempts: {last_error}")

    def _sleep_backoff(
        self, attempt: int, cve_id: str, *, reason: str, retry_after: str | None = None
    ) -> None:
        if attempt >= MAX_ATTEMPTS:
            return
        delay = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
        if retry_after:
            # Honour Retry-After when it asks for longer than our backoff.
            with contextlib.suppress(ValueError):
                delay = max(delay, float(retry_after))
        log.warning("nvd.retry", cve_id=cve_id, attempt=attempt, reason=reason, delay=delay)
        time.sleep(delay)


# ─── Response parsing ────────────────────────────────────────────────────────


def parse_nvd_cve(cve: dict[str, Any]) -> NvdRecord:
    record = NvdRecord(cve_id=str(cve.get("id", "")).upper())
    record.vuln_status = cve.get("vulnStatus")
    record.published = _parse_timestamp(cve.get("published"))
    record.last_modified = _parse_timestamp(cve.get("lastModified"))

    for description in cve.get("descriptions") or []:
        if description.get("lang") == "en" and description.get("value"):
            record.description = str(description["value"]).strip()
            break

    record.metrics = _parse_metrics(cve.get("metrics") or {})
    record.cpe_matches = _parse_configurations(cve.get("configurations") or [])
    return record


def _parse_metrics(metrics: dict[str, Any]) -> list[CvssMetric]:
    """Read only the CVSS metric families.

    ``metrics`` also carries decision-point data such as ``ssvcV203``, which has
    no ``cvssData`` and a null score — iterating blindly yields junk rows.
    """
    out: list[CvssMetric] = []
    for key, entries in metrics.items():
        if not key.startswith("cvssMetric") or not isinstance(entries, list):
            continue
        for entry in entries:
            data = entry.get("cvssData") or {}
            version = str(data.get("version") or "")
            if not version:
                continue
            out.append(
                CvssMetric(
                    version=version,
                    score=_to_decimal(data.get("baseScore")),
                    vector=data.get("vectorString") or None,
                    severity=(data.get("baseSeverity") or entry.get("baseSeverity") or None),
                    source=entry.get("source"),
                    is_primary=entry.get("type") == "Primary",
                )
            )
    return out


def _parse_configurations(configurations: list[dict[str, Any]]) -> list[CpeMatch]:
    """Flatten configuration nodes into CPE matches.

    Node ``operator``/``negate`` express AND/OR logic between CPEs. We keep the
    flat list: it is the right input for "does this product/version appear in
    our estate", and the boolean structure is not something an inventory scan
    can meaningfully evaluate. Negated nodes are skipped rather than inverted.
    """
    out: list[CpeMatch] = []
    seen: set[tuple[str, str | None, str | None]] = set()

    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                cpe = parse_cpe(match.get("criteria", ""))
                if cpe is None:
                    continue
                start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                key = (cpe.uri, start, end)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    CpeMatch(
                        cpe=cpe,
                        vulnerable=bool(match.get("vulnerable", True)),
                        version_start=start,
                        version_start_inclusive="versionStartIncluding" in match,
                        version_end=end,
                        version_end_inclusive="versionEndIncluding" in match,
                    )
                )
    return out


def _parse_timestamp(value: object) -> datetime | None:
    """NVD timestamps are UTC but carry no offset."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _to_decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return score if Decimal("0") <= score <= Decimal("10") else None
