"""Inventory sources tab — Phase 2a.

Managing sources (create/edit/test-connection) requires ADMIN, matching
docs/architecture.md §6's role table ("Admin: Analyst + manage users,
sources, inventory integrations, API tokens"). Everyone who can reach the
tab can read it.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..api.deps import current_principal, db_session
from ..core.models.enums import CredentialAuthType, InventorySourceKind, Role, SyncStatus
from ..core.services import inventory as svc
from ..core.services.auth import PermissionDeniedError, Principal
from ..inventory import csv_parser
from ..inventory.api_client import ApiAdapterError
from ..inventory.csv_parser import MAPPING_FIELDS

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _require_web_principal(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return principal


@router.get("/inventory", response_class=HTMLResponse)
def index(
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    context = {
        "request": request,
        "principal": principal,
        "title": "Inventory",
        "active_nav": "inventory",
        "sources": svc.list_sources(db),
        "kinds": list(InventorySourceKind),
        "auth_types": list(CredentialAuthType),
        "can_manage": principal.user is not None and principal.user.role.satisfies(Role.ADMIN),
    }
    return templates.TemplateResponse(request, "inventory_index.html", context)


@router.post("/inventory/sources", response_class=HTMLResponse)
def create_source(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    base_url: str = Form(""),
    credential_auth_type: str = Form(""),
    api_key: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    schedule_cron: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    try:
        principal.require_role(Role.ADMIN)
        parsed_kind = InventorySourceKind(kind)
        config: dict[str, object] = {"base_url": base_url.strip()} if base_url.strip() else {}
        credential, auth_type = _credential_from_form(
            credential_auth_type, api_key, client_id, client_secret, username, password
        )
        svc.create_source(
            db,
            name=name,
            kind=parsed_kind,
            config=config,
            credential=credential,
            credential_auth_type=auth_type,
            schedule_cron=schedule_cron.strip() or None,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except (svc.InvalidSourceConfigError, svc.DuplicateSourceNameError, ValueError) as exc:
        db.rollback()
        return _index_with_error(request, db, principal, str(exc))

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/inventory"
    return response


@router.get("/inventory/sources/{source_id}/detail", response_class=HTMLResponse)
def source_detail(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    source = svc.get_source(db, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Inventory source not found")
    context = {
        "source": source,
        "history": svc.sync_history(db, source_id),
        "can_manage": principal.user is not None and principal.user.role.satisfies(Role.ADMIN),
    }
    return templates.TemplateResponse(request, "_inventory_detail.html", context)


@router.post("/inventory/sources/{source_id}/toggle", response_class=HTMLResponse)
def toggle_active(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    try:
        principal.require_role(Role.ADMIN)
        source = svc.get_source(db, source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Inventory source not found")
        svc.update_source(
            db,
            source_id,
            is_active=not source.is_active,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/inventory"
    return response


@router.post("/inventory/sources/{source_id}/test", response_class=HTMLResponse)
def test_connection(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    try:
        principal.require_role(Role.ADMIN)
        result = svc.test_connection(
            db, source_id, actor=principal.to_actor(request.client.host if request.client else None)
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.SourceNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Inventory source not found") from None

    context = {"result": result}
    return templates.TemplateResponse(request, "_inventory_test_result.html", context)


@router.post("/inventory/sources/{source_id}/sync", response_class=HTMLResponse)
def sync_source(
    source_id: uuid.UUID,
    request: Request,
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    try:
        principal.require_role(Role.ADMIN)
        snapshot = svc.sync_source(
            db, source_id, actor=principal.to_actor(request.client.host if request.client else None)
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.SourceNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Inventory source not found") from None
    except svc.InvalidSourceConfigError as exc:
        db.rollback()
        return templates.TemplateResponse(
            request, "_inventory_sync_result.html", {"error": str(exc)}
        )
    except ApiAdapterError as exc:
        # sync_source() already recorded the failure before raising — that
        # write must still be committed, or the failure itself vanishes.
        db.commit()
        return templates.TemplateResponse(
            request, "_inventory_sync_result.html", {"error": str(exc)}
        )

    source = svc.get_source(db, source_id)
    partial = source is not None and source.last_sync_status == SyncStatus.PARTIAL
    context = {"snapshot": snapshot, "partial": partial}
    return templates.TemplateResponse(request, "_inventory_sync_result.html", context)


@router.post("/inventory/sources/{source_id}/csv/preview", response_class=HTMLResponse)
async def preview_csv(
    source_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> HTMLResponse:
    try:
        principal.require_role(Role.ADMIN)
        data = await file.read()
        preview = svc.preview_csv(
            db, source_id, file_bytes=data, filename=file.filename or "upload.csv"
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.SourceNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Inventory source not found") from None
    except (
        svc.InvalidSourceConfigError,
        svc.CsvTooLargeError,
        csv_parser.CsvTooLargeError,
    ) as exc:
        db.rollback()
        context = {"source_id": source_id, "upload_error": str(exc)}
        return templates.TemplateResponse(request, "_inventory_csv_preview.html", context)

    context = {
        "source_id": source_id,
        "preview": preview,
        "mapping_fields": MAPPING_FIELDS,
    }
    return templates.TemplateResponse(request, "_inventory_csv_preview.html", context)


@router.post("/inventory/sources/{source_id}/csv/commit", response_class=HTMLResponse)
def commit_csv(
    source_id: uuid.UUID,
    request: Request,
    blob_id: uuid.UUID = Form(...),
    mapping_product: str = Form(""),
    mapping_vendor: str = Form(""),
    mapping_version: str = Form(""),
    mapping_device_count: str = Form(""),
    mapping_os_indicator: str = Form(""),
    mapping_os_name: str = Form(""),
    mapping_os_version: str = Form(""),
    db: DbSession = Depends(db_session),
    principal: Principal = Depends(_require_web_principal),
) -> Response:
    mapping: dict[str, str | None] = {
        "product": mapping_product or None,
        "vendor": mapping_vendor or None,
        "version": mapping_version or None,
        "device_count": mapping_device_count or None,
        "os_indicator": mapping_os_indicator or None,
        "os_name": mapping_os_name or None,
        "os_version": mapping_os_version or None,
    }
    try:
        principal.require_role(Role.ADMIN)
        svc.commit_csv_snapshot(
            db,
            source_id,
            blob_id=blob_id,
            mapping=mapping,
            actor=principal.to_actor(request.client.host if request.client else None),
        )
        db.commit()
    except PermissionDeniedError:
        db.rollback()
        raise HTTPException(status_code=403, detail="Insufficient role") from None
    except svc.SourceNotFoundError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Inventory source not found") from None
    except svc.CsvBlobNotFoundError:
        db.rollback()
        raise HTTPException(
            status_code=404, detail="Uploaded CSV not found — preview again"
        ) from None
    except (svc.InvalidSourceConfigError, csv_parser.CsvTooLargeError) as exc:
        db.rollback()
        context = {"source_id": source_id, "commit_error": str(exc)}
        return templates.TemplateResponse(request, "_inventory_csv_preview.html", context)

    response = Response(status_code=200)
    response.headers["HX-Redirect"] = "/inventory"
    return response


def _credential_from_form(
    auth_type: str, api_key: str, client_id: str, client_secret: str, username: str, password: str
) -> tuple[dict[str, str] | None, CredentialAuthType | None]:
    if not auth_type:
        return None, None
    parsed = CredentialAuthType(auth_type)
    if parsed is CredentialAuthType.API_KEY:
        if not api_key.strip():
            return None, None
        return {"api_key": api_key.strip()}, parsed
    if parsed is CredentialAuthType.OAUTH_CLIENT_CREDENTIALS:
        if not client_id.strip() or not client_secret.strip():
            return None, None
        return {"client_id": client_id.strip(), "client_secret": client_secret.strip()}, parsed
    if not username.strip() or not password.strip():
        return None, None
    return {"username": username.strip(), "password": password.strip()}, parsed


def _index_with_error(
    request: Request, db: DbSession, principal: Principal, message: str
) -> HTMLResponse:
    context = {
        "request": request,
        "principal": principal,
        "title": "Inventory",
        "active_nav": "inventory",
        "sources": svc.list_sources(db),
        "kinds": list(InventorySourceKind),
        "auth_types": list(CredentialAuthType),
        "can_manage": principal.user is not None and principal.user.role.satisfies(Role.ADMIN),
        "form_error": message,
    }
    return templates.TemplateResponse(request, "inventory_index.html", context)
