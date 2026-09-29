"""RFC 9457 problem-details error responses for `/api/v1`.

Domain exceptions raised by `core/` services are translated here, in one
place, so every route in `api/routers/advisories.py` can just call a service
and let an unhandled domain exception become the correct HTTP response — no
per-route try/except boilerplate. Web routes (`web/`) are untouched: the
handlers below only engage for paths under `/api/`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler as default_http_exception_handler
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..core.services.advisories import (
    AdvisoryNotFoundError,
    InvalidCursorError,
    InvalidStatusTransitionError,
    MissingAckChannelError,
    MissingCommentError,
)
from ..core.services.auth import AuthError, PermissionDeniedError
from ..core.services.inventory import (
    CsvBlobNotFoundError,
    CsvTooLargeError,
    DuplicateSourceNameError,
    InvalidSourceConfigError,
    SourceNotFoundError,
)
from ..core.services.scan import AdvisoryNotFoundError as ScanAdvisoryNotFoundError
from ..core.services.scan import ScanRunNotFoundError, SnapshotNotFoundError
from ..core.services.vt_lookup import (
    IocNotFoundError,
    VtDisabledError,
    VtUnauthorizedError,
    VtUnsupportedIocTypeError,
)
from ..inventory.csv_parser import CsvTooLargeError as CsvRowLimitError
from ..inventory.csv_parser import MissingMappingError

PROBLEM_BASE = "https://advisory-hub/errors"


def problem(
    status_code: int,
    slug: str,
    title: str,
    detail: str | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    body: dict[str, Any] = {"type": f"{PROBLEM_BASE}/{slug}", "title": title, "status": status_code}
    if detail is not None:
        body["detail"] = detail
    body.update(extra)
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type="application/problem+json",
        headers=headers,
    )


def register_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(AdvisoryNotFoundError)
    async def _not_found(request: Request, exc: AdvisoryNotFoundError) -> JSONResponse:
        return problem(404, "advisory-not-found", "Advisory not found", str(exc))

    @app.exception_handler(InvalidStatusTransitionError)
    async def _invalid_transition(
        request: Request, exc: InvalidStatusTransitionError
    ) -> JSONResponse:
        from ..core.models.enums import ALLOWED_TRANSITIONS

        allowed = sorted(s.value for s in ALLOWED_TRANSITIONS.get(exc.from_status, frozenset()))
        return problem(
            409,
            "invalid-transition",
            "Invalid status transition",
            str(exc),
            allowed=allowed,
        )

    @app.exception_handler(MissingCommentError)
    async def _missing_comment(request: Request, exc: MissingCommentError) -> JSONResponse:
        return problem(
            422,
            "comment-required",
            "A comment is required for every status change",
            str(exc),
        )

    @app.exception_handler(MissingAckChannelError)
    async def _missing_ack_channel(request: Request, exc: MissingAckChannelError) -> JSONResponse:
        return problem(
            422,
            "ack-channel-required",
            "An acknowledgement channel is required when acknowledging",
            str(exc),
        )

    @app.exception_handler(InvalidCursorError)
    async def _invalid_cursor(request: Request, exc: InvalidCursorError) -> JSONResponse:
        return problem(400, "invalid-cursor", "Invalid pagination cursor", str(exc))

    @app.exception_handler(SourceNotFoundError)
    async def _source_not_found(request: Request, exc: SourceNotFoundError) -> JSONResponse:
        return problem(404, "source-not-found", "Inventory source not found", str(exc))

    @app.exception_handler(DuplicateSourceNameError)
    async def _duplicate_source_name(
        request: Request, exc: DuplicateSourceNameError
    ) -> JSONResponse:
        return problem(
            409, "duplicate-source-name", "Inventory source name already in use", str(exc)
        )

    @app.exception_handler(InvalidSourceConfigError)
    async def _invalid_source_config(
        request: Request, exc: InvalidSourceConfigError
    ) -> JSONResponse:
        return problem(
            422, "invalid-source-config", "Invalid inventory source configuration", str(exc)
        )

    @app.exception_handler(CsvBlobNotFoundError)
    async def _csv_blob_not_found(request: Request, exc: CsvBlobNotFoundError) -> JSONResponse:
        return problem(404, "csv-blob-not-found", "Uploaded CSV not found", str(exc))

    @app.exception_handler(CsvTooLargeError)
    async def _csv_too_large(request: Request, exc: CsvTooLargeError) -> JSONResponse:
        return problem(413, "csv-too-large", "CSV upload exceeds the size limit", str(exc))

    @app.exception_handler(CsvRowLimitError)
    async def _csv_row_limit(request: Request, exc: CsvRowLimitError) -> JSONResponse:
        return problem(413, "csv-too-large", "CSV upload exceeds the row limit", str(exc))

    @app.exception_handler(MissingMappingError)
    async def _missing_csv_mapping(request: Request, exc: MissingMappingError) -> JSONResponse:
        return problem(422, "invalid-source-config", "CSV column mapping incomplete", str(exc))

    @app.exception_handler(ScanAdvisoryNotFoundError)
    async def _scan_advisory_not_found(
        request: Request, exc: ScanAdvisoryNotFoundError
    ) -> JSONResponse:
        # A distinct exception class from advisories.AdvisoryNotFoundError
        # (core.services.scan defines its own) — FastAPI matches handlers by
        # exact type, so this needs its own registration; reusing the
        # advisories-module class would have collapsed two different
        # "not found" meanings into one type for no benefit.
        return problem(404, "advisory-not-found", "Advisory not found", str(exc))

    @app.exception_handler(SnapshotNotFoundError)
    async def _snapshot_not_found(request: Request, exc: SnapshotNotFoundError) -> JSONResponse:
        return problem(404, "snapshot-not-found", "Inventory snapshot not found", str(exc))

    @app.exception_handler(ScanRunNotFoundError)
    async def _scan_run_not_found(request: Request, exc: ScanRunNotFoundError) -> JSONResponse:
        return problem(404, "scan-run-not-found", "Scan run not found", str(exc))

    @app.exception_handler(IocNotFoundError)
    async def _ioc_not_found(request: Request, exc: IocNotFoundError) -> JSONResponse:
        return problem(404, "ioc-not-found", "IOC not found", str(exc))

    @app.exception_handler(VtUnsupportedIocTypeError)
    async def _vt_unsupported_type(
        request: Request, exc: VtUnsupportedIocTypeError
    ) -> JSONResponse:
        return problem(
            422, "vt-unsupported-ioc-type", "VirusTotal has no lookup for this IOC type", str(exc)
        )

    @app.exception_handler(VtUnauthorizedError)
    async def _vt_unauthorized(request: Request, exc: VtUnauthorizedError) -> JSONResponse:
        return problem(
            502,
            "vt-not-configured",
            "VirusTotal is not configured or rejected the API key",
            str(exc),
        )

    @app.exception_handler(VtDisabledError)
    async def _vt_disabled(request: Request, exc: VtDisabledError) -> JSONResponse:
        return problem(503, "vt-disabled", "VirusTotal is disabled", str(exc))

    @app.exception_handler(PermissionDeniedError)
    async def _permission_denied(request: Request, exc: PermissionDeniedError) -> JSONResponse:
        return problem(403, "insufficient-scope", "Insufficient permissions", str(exc))

    @app.exception_handler(AuthError)
    async def _auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return problem(401, "unauthenticated", "Authentication failed", str(exc))

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> Any:
        if not request.url.path.startswith("/api/"):
            # Web routes rely on FastAPI's default handling — notably the
            # 303-with-Location redirect trick in web/tracker.py — untouched.
            return await default_http_exception_handler(request, exc)
        slug = {
            401: "unauthenticated",
            403: "forbidden",
            404: "not-found",
            502: "upstream-sync-failed",
        }.get(exc.status_code, "error")
        title = str(exc.detail) if exc.detail else "Error"
        return problem(exc.status_code, slug, title, headers=exc.headers)
