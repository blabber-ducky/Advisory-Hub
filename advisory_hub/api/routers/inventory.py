"""`/api/v1/inventory/sources` — thin adapter over `core.services.inventory`.

Source CRUD, "Test connection", and CSV preview/commit (2b). API sync (2c)
and scans (2e) are separate, later routers.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session as DbSession

from ...core.models.inventory import InventorySource
from ...core.security.tokens import Scope
from ...core.services import inventory as svc
from ...core.services.auth import Principal
from ...inventory.api_client import ApiAdapterError
from ..deps import client_ip, db_session, require_scope
from ..schemas import (
    ConnectionTestOut,
    CsvCommitRequest,
    CsvPreviewOut,
    InventorySnapshotOut,
    InventorySourceCreate,
    InventorySourceOut,
    InventorySourcePatch,
    ParsedRowOut,
    RowErrorOut,
    SyncHistoryEntryOut,
)

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


def _source_out(source: InventorySource) -> InventorySourceOut:
    return InventorySourceOut(
        id=source.id,
        name=source.name,
        kind=source.kind,
        mode=source.mode,
        config=source.config,
        has_credential=source.credential_id is not None,
        schedule_cron=source.schedule_cron,
        is_active=source.is_active,
        last_sync_at=source.last_sync_at,
        last_sync_status=source.last_sync_status,
        last_sync_error=source.last_sync_error,
        created_at=source.created_at,
    )


@router.get("/sources", response_model=list[InventorySourceOut])
def list_sources(
    active_only: bool = False,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.INVENTORY_READ)),
) -> list[InventorySourceOut]:
    return [_source_out(s) for s in svc.list_sources(db, active_only=active_only)]


@router.post("/sources", response_model=InventorySourceOut, status_code=201)
def create_source(
    body: InventorySourceCreate,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> InventorySourceOut:
    source = svc.create_source(
        db,
        name=body.name,
        kind=body.kind,
        config=body.config,
        credential=body.credential,
        credential_auth_type=body.credential_auth_type,
        schedule_cron=body.schedule_cron,
        actor=principal.to_actor(client_ip(request)),
    )
    db.commit()
    return _source_out(source)


@router.get("/sources/{source_id}", response_model=InventorySourceOut)
def get_source(
    source_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.INVENTORY_READ)),
) -> InventorySourceOut:
    source = svc.get_source(db, source_id)
    if source is None:
        raise svc.SourceNotFoundError(source_id)
    return _source_out(source)


@router.patch("/sources/{source_id}", response_model=InventorySourceOut)
def patch_source(
    source_id: uuid.UUID,
    body: InventorySourcePatch,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> InventorySourceOut:
    fields = body.model_dump(exclude_unset=True)
    source = svc.update_source(
        db,
        source_id,
        config=fields.get("config", svc.UNSET),
        credential=fields.get("credential", svc.UNSET),
        credential_auth_type=fields.get("credential_auth_type", svc.UNSET),
        schedule_cron=fields.get("schedule_cron", svc.UNSET),
        is_active=fields.get("is_active", svc.UNSET),
        actor=principal.to_actor(client_ip(request)),
    )
    db.commit()
    return _source_out(source)


@router.post("/sources/{source_id}/test", response_model=ConnectionTestOut)
def test_connection(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> ConnectionTestOut:
    result = svc.test_connection(db, source_id, actor=principal.to_actor(client_ip(request)))
    db.commit()
    return ConnectionTestOut(ok=result.ok, message=result.message)


@router.post("/sources/{source_id}/sync", response_model=InventorySnapshotOut, status_code=201)
def sync_source(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> InventorySnapshotOut:
    try:
        snapshot = svc.sync_source(db, source_id, actor=principal.to_actor(client_ip(request)))
    except ApiAdapterError as exc:
        # sync_source() already recorded the failure (source.last_sync_*,
        # an audit entry) before raising — that write must still be
        # committed, or the failure itself silently vanishes.
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return InventorySnapshotOut.model_validate(snapshot)


@router.get("/sources/{source_id}/history", response_model=list[SyncHistoryEntryOut])
def get_sync_history(
    source_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.INVENTORY_READ)),
) -> list[SyncHistoryEntryOut]:
    return [
        SyncHistoryEntryOut(
            action=entry.action,
            actor_label=entry.actor_label,
            detail=entry.detail,
            created_at=entry.created_at,
        )
        for entry in svc.sync_history(db, source_id)
    ]


@router.post("/sources/{source_id}/csv/preview", response_model=CsvPreviewOut)
async def preview_csv(
    source_id: uuid.UUID,
    file: UploadFile = File(...),
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> CsvPreviewOut:
    data = await file.read()
    preview = svc.preview_csv(
        db, source_id, file_bytes=data, filename=file.filename or "upload.csv"
    )
    db.commit()
    return CsvPreviewOut(
        blob_id=preview.blob_id,
        headers=preview.headers,
        mapping=preview.mapping,
        preview_rows=[ParsedRowOut.model_validate(r) for r in preview.preview_rows],
        errors=[RowErrorOut.model_validate(e) for e in preview.errors],
        total_rows=preview.total_rows,
        matched_row_count=preview.matched_row_count,
    )


@router.post(
    "/sources/{source_id}/csv/commit", response_model=InventorySnapshotOut, status_code=201
)
def commit_csv(
    source_id: uuid.UUID,
    body: CsvCommitRequest,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.INVENTORY_WRITE)),
) -> InventorySnapshotOut:
    snapshot = svc.commit_csv_snapshot(
        db,
        source_id,
        blob_id=body.blob_id,
        mapping=body.mapping,
        actor=principal.to_actor(client_ip(request)),
    )
    db.commit()
    return InventorySnapshotOut.model_validate(snapshot)
