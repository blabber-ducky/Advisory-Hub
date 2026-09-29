"""Redis cache for NVD responses.

Cuts repeat lookups across advisories — the corpus has 479 CVE rows for 404
distinct CVEs, and vendor roll-ups repeat heavily month to month. Redis being
unavailable degrades to no caching, never to an error.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import asdict
from datetime import datetime
from decimal import Decimal
from typing import Any

from ..config import settings
from ..logging import get_logger
from .cpe import Cpe
from .nvd import CpeMatch, CvssMetric, NvdRecord

log = get_logger(__name__)

KEY_PREFIX = "nvd:cve:"
TTL_FOUND_SECONDS = 24 * 60 * 60
#: Shorter, because "not found" is usually "not published yet".
TTL_MISSING_SECONDS = 60 * 60
_MISSING = "__missing__"


class NvdCache:
    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client
        self._checked = redis_client is not None

    @property
    def redis(self) -> Any | None:
        if not self._checked:
            self._checked = True
            try:
                import redis

                client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
                client.ping()
                self._redis = client
            except Exception as exc:  # redis absent or unreachable
                log.warning("nvd_cache.unavailable", error=str(exc)[:120])
                self._redis = None
        return self._redis

    def get(self, cve_id: str) -> NvdRecord | object | None:
        """Return a record, ``None`` for a cached miss, or ``MISS`` if unknown."""
        client = self.redis
        if client is None:
            return MISS
        try:
            raw = client.get(f"{KEY_PREFIX}{cve_id}")
        except Exception:
            return MISS
        if raw is None:
            return MISS
        text = raw.decode() if isinstance(raw, bytes) else str(raw)
        if text == _MISSING:
            return None
        try:
            return _decode(json.loads(text))
        except (ValueError, KeyError, TypeError):
            return MISS

    def put(self, cve_id: str, record: NvdRecord | None) -> None:
        client = self.redis
        if client is None:
            return
        try:
            if record is None:
                client.setex(f"{KEY_PREFIX}{cve_id}", TTL_MISSING_SECONDS, _MISSING)
            else:
                client.setex(
                    f"{KEY_PREFIX}{cve_id}",
                    TTL_FOUND_SECONDS,
                    json.dumps(_encode(record), default=str),
                )
        except Exception as exc:
            log.debug("nvd_cache.put_failed", cve_id=cve_id, error=str(exc)[:120])

    def invalidate(self, cve_id: str) -> None:
        client = self.redis
        if client is not None:
            # Cache eviction is best-effort; a failure here is not worth
            # surfacing, and the entry expires on its own TTL regardless.
            with contextlib.suppress(Exception):
                client.delete(f"{KEY_PREFIX}{cve_id}")


class _Miss:
    """Sentinel: nothing cached, as distinct from a cached 'not found'."""

    def __repr__(self) -> str:
        return "MISS"

    def __bool__(self) -> bool:
        return False


MISS = _Miss()


def _encode(record: NvdRecord) -> dict[str, Any]:
    return {
        "cve_id": record.cve_id,
        "description": record.description,
        "published": record.published.isoformat() if record.published else None,
        "last_modified": record.last_modified.isoformat() if record.last_modified else None,
        "vuln_status": record.vuln_status,
        "metrics": [
            {**asdict(m), "score": str(m.score) if m.score is not None else None}
            for m in record.metrics
        ],
        "cpe_matches": [
            {
                "cpe": asdict(m.cpe),
                "vulnerable": m.vulnerable,
                "version_start": m.version_start,
                "version_start_inclusive": m.version_start_inclusive,
                "version_end": m.version_end,
                "version_end_inclusive": m.version_end_inclusive,
            }
            for m in record.cpe_matches
        ],
    }


def _decode(payload: dict[str, Any]) -> NvdRecord:
    return NvdRecord(
        cve_id=payload["cve_id"],
        description=payload.get("description"),
        published=_dt(payload.get("published")),
        last_modified=_dt(payload.get("last_modified")),
        vuln_status=payload.get("vuln_status"),
        metrics=[
            CvssMetric(
                version=m["version"],
                score=Decimal(m["score"]) if m.get("score") is not None else None,
                vector=m.get("vector"),
                severity=m.get("severity"),
                source=m.get("source"),
                is_primary=bool(m.get("is_primary")),
            )
            for m in payload.get("metrics", [])
        ],
        cpe_matches=[
            CpeMatch(
                cpe=Cpe(**m["cpe"]),
                vulnerable=bool(m.get("vulnerable", True)),
                version_start=m.get("version_start"),
                version_start_inclusive=bool(m.get("version_start_inclusive")),
                version_end=m.get("version_end"),
                version_end_inclusive=bool(m.get("version_end_inclusive")),
            )
            for m in payload.get("cpe_matches", [])
        ],
    )


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
