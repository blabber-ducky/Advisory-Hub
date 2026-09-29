"""`/api/v1` IOC endpoints — thin adapter over `core.services.vt_lookup`.

Only the VirusTotal check lives here so far; IOCs themselves are read as
part of `GET /advisories/{id}` (`AdvisoryDetail.iocs`). The raw IOC value
never crosses this API — callers pass an `AdvisoryIoc` id, never a value,
matching the same defanging discipline the web UI follows (CLAUDE.md §2.3).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DbSession

from ...core.security.tokens import Scope
from ...core.services import vt_lookup as svc
from ...core.services.auth import Principal
from ..deps import client_ip, db_session, require_scope
from ..schemas import VtCheckRequest, VtLookupOut

router = APIRouter(prefix="/api/v1", tags=["iocs"])


@router.post("/iocs/{ioc_id}/check-vt", response_model=VtLookupOut)
def check_ioc_vt(
    ioc_id: uuid.UUID,
    body: VtCheckRequest,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.VT_CHECK)),
) -> VtLookupOut:
    lookup = svc.check_ioc(
        db, ioc_id, actor=principal.to_actor(client_ip(request)), force=body.force
    )
    db.commit()
    return VtLookupOut.model_validate(lookup)
