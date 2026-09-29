"""`/api/v1` scan endpoints — thin adapter over `core.services.scan`, Phase 2e.

**Runs synchronously, unlike the design doc's `202 Accepted` sketch** — there
is no background job queue behind `run_scan()` (see its module docstring);
matching against every real snapshot this project has scanned completes in
well under a second, so a synchronous `200` with the finished result is
honest about what actually happens, not a simplification hiding behind a
misleading status code. Revisit if a real deployment's inventory size makes
that no longer true.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DbSession

from ...core.models.inventory import ScanRun
from ...core.security.tokens import Scope
from ...core.services import inventory as inventory_svc
from ...core.services import scan as svc
from ...core.services.auth import Principal
from ..deps import client_ip, db_session, require_scope
from ..schemas import (
    ScanCoverageGapOut,
    ScanMatchOut,
    ScanRunOut,
    ScanRunSummaryOut,
    ScanTriggerRequest,
)

router = APIRouter(prefix="/api/v1", tags=["scans"])


def _scan_run_out(db: DbSession, scan_run: ScanRun) -> ScanRunOut:
    gaps = svc.coverage_gaps(db, scan_run)
    return ScanRunOut(
        id=scan_run.id,
        advisory_id=scan_run.advisory_id,
        snapshot_ids=scan_run.snapshot_ids,
        status=scan_run.status,
        started_at=scan_run.started_at,
        finished_at=scan_run.finished_at,
        match_count=scan_run.match_count,
        affected_device_count=scan_run.affected_device_count,
        error=scan_run.error,
        matches=[ScanMatchOut.model_validate(m) for m in scan_run.matches],
        coverage_gaps=[ScanCoverageGapOut(vendor=v, product=p) for v, p in gaps],
    )


@router.post("/advisories/{advisory_id}/scan", response_model=ScanRunOut)
def trigger_scan(
    advisory_id: uuid.UUID,
    body: ScanTriggerRequest,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.SCAN_RUN)),
) -> ScanRunOut:
    snapshot_ids = body.snapshot_ids or [
        snap.id for snap in inventory_svc.latest_snapshots(db, active_only=True)
    ]
    scan_run = svc.run_scan(
        db, advisory_id, snapshot_ids, actor=principal.to_actor(client_ip(request))
    )
    db.commit()
    return _scan_run_out(db, scan_run)


@router.get("/scans/{scan_run_id}", response_model=ScanRunOut)
def get_scan(
    scan_run_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.SCAN_RUN)),
) -> ScanRunOut:
    scan_run = svc.get_scan_run(db, scan_run_id)
    if scan_run is None:
        raise svc.ScanRunNotFoundError(scan_run_id)
    return _scan_run_out(db, scan_run)


@router.get("/advisories/{advisory_id}/scans", response_model=list[ScanRunSummaryOut])
def list_scans(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.SCAN_RUN)),
) -> list[ScanRunSummaryOut]:
    return [ScanRunSummaryOut.model_validate(run) for run in svc.scan_history(db, advisory_id)]
