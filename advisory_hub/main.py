"""FastAPI application factory."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .api.problems import register_problem_handlers
from .api.routers import advisories as api_advisories
from .api.routers import health
from .api.routers import inventory as api_inventory
from .api.routers import iocs as api_iocs
from .api.routers import scans as api_scans
from .api.routers import sources as api_sources
from .config import INSECURE_SECRET_KEYS, settings
from .logging import configure_logging, get_logger, request_id_var
from .web import admin as web_admin
from .web import affected_software as web_affected_software
from .web import inventory as web_inventory
from .web import iocs as web_iocs
from .web import routes as web_routes
from .web import tracker as web_tracker
from .web import tracker_import as web_tracker_import

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(settings.log_level, settings.log_format)

    # Refuse to start in production with a placeholder signing key. Failing
    # loudly here beats issuing forgeable session cookies.
    if settings.is_production and settings.secret_key in INSECURE_SECRET_KEYS:
        raise RuntimeError(
            "SECRET_KEY is unset or still the placeholder value. "
            'Generate one: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    for path in settings.data_paths():
        path.mkdir(parents=True, exist_ok=True)

    log.info(
        "app.startup",
        environment=settings.environment,
        blob_root=str(settings.blob_root),
        nvd_enabled=settings.nvd_enabled,
    )
    yield
    log.info("app.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Advisory Hub",
        version="0.1.0",
        description=(
            "Security-advisory tracking, statistics, and remediation portal. "
            "All business logic lives in core/ services; this API is a thin adapter."
        ),
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "request.failed", method=request.method, path=request.url.path, request_id=rid
            )
            request_id_var.reset(token)
            return JSONResponse(
                status_code=500,
                content={
                    "type": "https://advisory-hub/errors/internal",
                    "title": "Internal server error",
                    "status": 500,
                    "request_id": rid,
                },
            )
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        # Health probes are noisy and uninteresting at INFO.
        if not request.url.path.startswith("/health"):
            log.info(
                "request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
            )
        response.headers["x-request-id"] = rid
        request_id_var.reset(token)
        return response

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    register_problem_handlers(app)

    app.include_router(health.router)
    app.include_router(web_routes.router)
    app.include_router(web_tracker.router)
    app.include_router(web_tracker_import.router)
    app.include_router(web_inventory.router)
    app.include_router(web_affected_software.router)
    app.include_router(web_iocs.router)
    app.include_router(web_admin.router)
    app.include_router(api_advisories.router)
    app.include_router(api_sources.router)
    app.include_router(api_inventory.router)
    app.include_router(api_scans.router)
    app.include_router(api_iocs.router)
    return app


app = create_app()
