"""`/api/v1/advisories` — thin adapter over `core.services.advisories`.

No business logic here. Every rule (mandatory comment, transition legality,
role/scope checks) lives in `core/` and raises a typed exception on failure;
`api/problems.py` turns those into RFC 9457 responses, so routes below don't
need try/except.

Deliberately not carried over from the design doc for this pass: `has_cve`,
`cve_id`, and `received_after`/`received_before` filters, and `GET
/advisories/{id}/attachments/raw` for the original email. `AdvisoryFilters`
doesn't support them yet — same filter set as the web tracker. Extending it
is a small, separate follow-up, not bundled into this phase.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ...core.models.advisory import AdvisoryAttachment, Blob, Comment, StatusChange
from ...core.models.enums import AdvisoryStatus, AdvisoryType, Severity
from ...core.security.tokens import Scope
from ...core.services import advisories as svc
from ...core.services.auth import Principal
from ...core.storage.blobs import FilesystemBlobStore
from ..deps import client_ip, db_session, require_scope
from ..schemas import (
    AdvisoryDetail,
    AdvisoryPage,
    AdvisoryPatch,
    AdvisorySummary,
    CommentCreate,
    CommentOut,
    RelatedAdvisoryOut,
    StatusChangeOut,
    StatusChangeRequest,
)

router = APIRouter(prefix="/api/v1", tags=["advisories"])


def _filters_from_query(
    status_: list[AdvisoryStatus] | None = Query(None, alias="status"),
    type_: list[AdvisoryType] | None = Query(None, alias="type"),
    severity: list[Severity] | None = Query(None),
    source_id: uuid.UUID | None = Query(None),
    assignee_id: uuid.UUID | None = Query(None),
    q: str | None = Query(None, description="Full-text search"),
    open_only: bool = Query(False),
    unacknowledged_only: bool = Query(False),
) -> svc.AdvisoryFilters:
    return svc.AdvisoryFilters(
        status=status_ or [],
        type=type_ or [],
        severity=severity or [],
        source_id=source_id,
        assignee_id=assignee_id,
        q=q,
        open_only=open_only,
        unacknowledged_only=unacknowledged_only,
    )


@router.get("/advisories", response_model=AdvisoryPage)
def list_advisories(
    filters: svc.AdvisoryFilters = Depends(_filters_from_query),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> AdvisoryPage:
    page = svc.list_advisories_cursor(db, filters, cursor=cursor, limit=limit)
    return AdvisoryPage(
        items=[AdvisorySummary.model_validate(a) for a in page.items],
        next_cursor=page.next_cursor,
    )


@router.get("/advisories/{advisory_id}", response_model=AdvisoryDetail)
def get_advisory(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> AdvisoryDetail:
    advisory = svc.get_advisory(db, advisory_id)
    if advisory is None:
        raise svc.AdvisoryNotFoundError(advisory_id)
    return AdvisoryDetail.model_validate(advisory)


@router.patch("/advisories/{advisory_id}", response_model=AdvisoryDetail)
def patch_advisory(
    advisory_id: uuid.UUID,
    body: AdvisoryPatch,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.ADVISORIES_WRITE)),
) -> AdvisoryDetail:
    fields = body.model_dump(exclude_unset=True)
    advisory = svc.update_advisory(
        db,
        advisory_id,
        assignee_id=fields.get("assignee_id", svc.UNSET),
        type=fields.get("type", svc.UNSET),
        severity=fields.get("severity", svc.UNSET),
        actor=principal.to_actor(client_ip(request)),
    )
    db.commit()
    return AdvisoryDetail.model_validate(advisory)


@router.post("/advisories/{advisory_id}/status", response_model=StatusChangeOut)
def change_status(
    advisory_id: uuid.UUID,
    body: StatusChangeRequest,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.ADVISORIES_WRITE)),
) -> StatusChangeOut:
    result = svc.change_status(
        db,
        advisory_id,
        to_status=body.to_status,
        comment_body=body.comment,
        actor=principal.to_actor(client_ip(request)),
        ack_channel=body.ack_channel,
    )
    db.commit()
    return _status_change_out(result)


@router.get("/advisories/{advisory_id}/comments", response_model=list[CommentOut])
def list_comments(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> list[CommentOut]:
    return [_comment_out(c) for c in svc.get_comments(db, advisory_id)]


@router.post("/advisories/{advisory_id}/comments", response_model=CommentOut, status_code=201)
def create_comment(
    advisory_id: uuid.UUID,
    body: CommentCreate,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(require_scope(Scope.ADVISORIES_WRITE)),
) -> CommentOut:
    comment = svc.add_comment(
        db, advisory_id, body=body.body, actor=principal.to_actor(client_ip(request))
    )
    db.commit()
    return _comment_out(comment)


@router.get("/advisories/{advisory_id}/history", response_model=list[StatusChangeOut])
def get_history(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> list[StatusChangeOut]:
    return [_status_change_out(sc) for sc in svc.get_status_history(db, advisory_id)]


@router.get("/advisories/{advisory_id}/related", response_model=list[RelatedAdvisoryOut])
def get_related(
    advisory_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> list[RelatedAdvisoryOut]:
    return [
        RelatedAdvisoryOut(kind=rel.kind, advisory=AdvisorySummary.model_validate(other))
        for rel, other in svc.get_related_advisories(db, advisory_id)
    ]


@router.get("/advisories/{advisory_id}/attachments/{attachment_id}/download")
def download_attachment(
    advisory_id: uuid.UUID,
    attachment_id: uuid.UUID,
    db: DbSession = Depends(db_session),
    _principal: Principal = Depends(require_scope(Scope.ADVISORIES_READ)),
) -> StreamingResponse:
    attachment = db.get(AdvisoryAttachment, attachment_id)
    if attachment is None or attachment.advisory_id != advisory_id:
        raise HTTPException(status_code=404, detail="Attachment not found")
    blob = db.get(Blob, attachment.blob_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="Blob not found")
    store = FilesystemBlobStore(settings.blob_root)
    handle = store.open(blob.sha256)
    return StreamingResponse(
        handle,
        media_type=attachment.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{attachment.filename}"'},
    )


def _comment_out(comment: Comment) -> CommentOut:
    return CommentOut(
        id=comment.id,
        author_display_name=comment.author.display_name if comment.author else None,
        body=comment.body,
        is_status_change=comment.is_status_change,
        created_at=comment.created_at,
    )


def _status_change_out(sc: StatusChange) -> StatusChangeOut:
    return StatusChangeOut(
        id=sc.id,
        from_status=sc.from_status,
        to_status=sc.to_status,
        actor_display_name=sc.actor.display_name if sc.actor else None,
        comment=_comment_out(sc.comment),
        created_at=sc.created_at,
    )
