"""`/api/v1/sources` — read-only. Regulator/source CRUD is Phase 2a scope
(the inventory-sources tab), not this pass; `Source` here is the small,
mostly-static table of email senders (DOH, …), seeded via the CLI.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from ...core.security.tokens import Scope
from ...core.services import sources as svc
from ...core.services.auth import Principal
from ..deps import db_session, require_scope
from ..schemas import SourceOut

router = APIRouter(prefix="/api/v1", tags=["sources"])


@router.get("/sources", response_model=list[SourceOut])
def list_sources(
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> list[SourceOut]:
    return [SourceOut.model_validate(s) for s in svc.list_sources(db)]


@router.get("/sources/{source_id}", response_model=SourceOut)
def get_source(
    source_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> SourceOut:
    source = svc.get_source(db, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    return SourceOut.model_validate(source)
