"""RQ job definitions.

Jobs are plain importable functions — RQ pickles the function reference
and its arguments, not a live Python object, and by default forks a fresh
process per job. Anything that needs to persist *across* job executions —
like a rate limit for a batch of queued VirusTotal checks — cannot live in
an in-memory object (it would reset on every job); it has to live in
Redis, the one thing every job execution actually shares.
"""

from __future__ import annotations

import time
import uuid

from ..config import settings
from ..core.models.enums import ActorKind
from ..core.services import vt_lookup
from ..core.services.audit import Actor
from ..db import session_scope
from ..enrich.virustotal import RATE_LIMIT_CALLS, RATE_LIMIT_WINDOW_SECONDS
from ..logging import get_logger

log = get_logger(__name__)

_VT_RATE_LIMIT_KEY = "vt:queue:rate_limit"
_POLL_SECONDS = 2.0


def _acquire_vt_slot() -> None:
    """Blocks, retrying, until a Redis-backed rate-limit slot is free.

    A sliding window implemented as a Redis sorted set: each acquired slot
    is a member scored by its acquisition time; entries older than the
    window are pruned before counting. Reuses the same
    `RATE_LIMIT_CALLS`/`RATE_LIMIT_WINDOW_SECONDS` the interactive
    single-check path uses, so a bulk queue and a one-off click never
    together exceed the free-tier limit — they don't currently share
    accounting with each other, but both stay under the same conservative
    per-window cap independently.
    """
    import redis

    client = redis.Redis.from_url(settings.redis_url)
    while True:
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        pipe = client.pipeline()
        pipe.zremrangebyscore(_VT_RATE_LIMIT_KEY, 0, window_start)
        pipe.zcard(_VT_RATE_LIMIT_KEY)
        _, count = pipe.execute()
        if count < RATE_LIMIT_CALLS:
            client.zadd(_VT_RATE_LIMIT_KEY, {str(uuid.uuid4()): now})
            client.expire(_VT_RATE_LIMIT_KEY, int(RATE_LIMIT_WINDOW_SECONDS) + 5)
            return
        time.sleep(_POLL_SECONDS)


def check_ioc_job(ioc_id: str) -> None:
    """RQ entrypoint for one queued VirusTotal check.

    Blocks internally on `_acquire_vt_slot()` before calling out — RQ's
    default worker processes one job at a time, so a blocked job naturally
    delays every job queued after it, pacing a whole bulk selection out at
    the same rate a single interactive click already respects. Any error
    (including a disabled/unconfigured integration) is logged and
    swallowed, not re-raised — one indicator's failure must not stop the
    rest of a bulk batch, and `vt_lookup.check_ioc()` already persists its
    own ERROR-state result for genuine transport failures.
    """
    _acquire_vt_slot()
    with session_scope() as db:
        actor = Actor(kind=ActorKind.SYSTEM, label="vt_bulk_check")
        try:
            vt_lookup.check_ioc(db, uuid.UUID(ioc_id), actor=actor)
        except Exception:
            log.exception("vt_bulk_check.job_failed", ioc_id=ioc_id)
