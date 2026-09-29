"""Worker entrypoint.

Phase 0: an RQ worker with no jobs registered yet. Phase 1 adds the inbox
watcher, the parse pipeline, and NVD enrichment.
"""

from __future__ import annotations

import signal
import sys
from types import FrameType

from ..config import settings
from ..logging import configure_logging, get_logger

log = get_logger(__name__)

#: "vt_check" carries bulk VirusTotal lookup jobs (`worker.jobs.check_ioc_job`)
#: queued from the IOC tab's multi-select action — see docs/decisions.md D-034.
QUEUES = ("ingest", "enrich", "inventory", "scan", "vt_check", "default")

ENRICH_POLL_SECONDS = 300
ENRICH_BATCH_SIZE = 100


def main() -> int:
    configure_logging(settings.log_level, settings.log_format)

    for path in settings.data_paths():
        path.mkdir(parents=True, exist_ok=True)

    def _shutdown(signum: int, _frame: FrameType | None) -> None:
        log.info("worker.shutdown", signal=signal.Signals(signum).name)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        from redis import Redis
        from rq import Queue, Worker
    except ImportError:  # pragma: no cover
        log.error("worker.missing_dependencies")
        return 1

    connection = Redis.from_url(settings.redis_url)
    queues = [Queue(name, connection=connection) for name in QUEUES]
    log.info(
        "worker.starting",
        queues=list(QUEUES),
        inbox=str(settings.inbox_path),
        poll_seconds=settings.inbox_poll_seconds,
    )

    _preload_poller_dependencies()
    _start_inbox_poller()
    _start_enrichment_poller()
    _start_inventory_sync_poller()

    worker = Worker(queues, connection=connection)
    worker.work(with_scheduler=True)
    return 0


def _preload_poller_dependencies() -> None:
    """Import everything the poller threads use, once, on the main thread.

    The pollers start together; when each thread did the *first* import of
    ``core.models`` itself, the imports raced ("cannot import name ... from
    partially initialized module") and the inbox and inventory-sync threads
    died at start-up while the worker kept reporting healthy. After this,
    the imports inside each ``_loop`` are just cache lookups.
    """
    import croniter  # noqa: F401

    from ..core.models import base, enums  # noqa: F401
    from ..core.services import audit, enrichment, inventory  # noqa: F401
    from ..db import session_scope  # noqa: F401
    from ..ingest import pipeline  # noqa: F401
    from ..inventory import api_client  # noqa: F401


def _start_inbox_poller() -> None:
    """Poll the inbox on a background thread.

    Deliberately not an RQ job: the watcher *produces* work, so making it a
    queued job would need something else to enqueue it. A thread inside the
    worker keeps the deployment to one process, and the atomic-claim rename
    means running several workers is still safe.
    """
    import threading
    import time

    def _loop() -> None:
        while True:
            try:
                # Inside the try: a failed import is logged and retried
                # next cycle instead of silently ending the thread.
                from ..ingest.pipeline import process_inbox

                process_inbox()
            except Exception:
                log.exception("inbox.poll_failed")
            time.sleep(settings.inbox_poll_seconds)

    thread = threading.Thread(target=_loop, name="inbox-poller", daemon=True)
    thread.start()


def _start_enrichment_poller() -> None:
    """Sweep for CVEs needing NVD enrichment.

    Runs on its own cadence, well clear of NVD's rate limit: at the corpus rate
    of ~77 new CVEs/week, a five-minute sweep is far more headroom than needed.
    Kept off the ingestion path so a slow or unreachable NVD never delays an
    advisory appearing in the tracker.
    """
    import threading
    import time

    def _loop() -> None:
        while True:
            try:
                from ..core.services.enrichment import enrich_pending
                from ..db import session_scope

                # No `settings.nvd_enabled` gate here — `enrich_pending()`
                # resolves enabled/disabled itself via
                # `core.services.system_integrations`, which may have been
                # turned on/off from the admin panel since this process
                # started. Gating here too would make an admin-panel
                # "enable" silently ineffective until a restart.
                with session_scope() as db:
                    report = enrich_pending(db, limit=ENRICH_BATCH_SIZE)
                if report.attempted:
                    log.info(
                        "enrichment.batch",
                        ok=report.ok,
                        not_found=report.not_found,
                        errors=report.errors,
                        cpe_rows=report.cpe_rows,
                    )
            except Exception:
                log.exception("enrichment.sweep_failed")
            time.sleep(ENRICH_POLL_SECONDS)

    thread = threading.Thread(target=_loop, name="enrichment-poller", daemon=True)
    thread.start()


def _start_inventory_sync_poller() -> None:
    """Sweep active API-kind sources for a due `schedule_cron`.

    A source with no `schedule_cron` is never auto-synced — "Sync now" stays
    manual-only for it. Each due source gets its own transaction, so one
    source's failure can't roll back another's, or block the sweep.
    """
    import threading
    import time

    def _loop() -> None:
        while True:
            try:
                from croniter import croniter

                from ..core.models.base import utcnow
                from ..core.models.enums import ActorKind
                from ..core.services import inventory as inv_svc
                from ..core.services.audit import Actor
                from ..db import session_scope
                from ..inventory.api_client import ApiAdapterError

                with session_scope() as db:
                    due_source_ids = []
                    for source in inv_svc.list_sources(db, active_only=True):
                        if not source.schedule_cron or source.kind not in inv_svc.API_KINDS:
                            continue
                        base = source.last_sync_at or source.created_at
                        try:
                            next_fire = croniter(source.schedule_cron, base).get_next(
                                ret_type=type(base)
                            )
                        except (ValueError, KeyError):
                            log.warning(
                                "inventory_sync.bad_cron",
                                source_id=str(source.id),
                                cron=source.schedule_cron,
                            )
                            continue
                        if next_fire <= utcnow():
                            due_source_ids.append(source.id)

                for source_id in due_source_ids:
                    with session_scope() as sync_db:
                        try:
                            inv_svc.sync_source(
                                sync_db,
                                source_id,
                                actor=Actor(kind=ActorKind.SYSTEM, label="scheduler"),
                            )
                        except ApiAdapterError:
                            # sync_source() already recorded the failure —
                            # let session_scope() commit that write.
                            log.warning("inventory_sync.scheduled_failed", source_id=str(source_id))
                        else:
                            log.info("inventory_sync.scheduled_ok", source_id=str(source_id))
            except Exception:
                log.exception("inventory_sync.sweep_failed")
            time.sleep(settings.inventory_sync_poll_seconds)

    thread = threading.Thread(target=_loop, name="inventory-sync-poller", daemon=True)
    thread.start()


if __name__ == "__main__":
    raise SystemExit(main())
