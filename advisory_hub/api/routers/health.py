"""Health endpoints.

Checks are reported individually. A single boolean would hide exactly the
failures worth alerting on — see docs/operations.md §6.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from ...config import settings
from ...core.storage.blobs import FilesystemBlobStore
from ...db import check_database

router = APIRouter(tags=["health"])


class HealthCheck(BaseModel):
    database: bool
    redis: bool
    blob_volume: bool
    inbox: bool


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    checks: HealthCheck


@router.get("/health", response_model=HealthResponse)
def health(response: Response) -> HealthResponse:
    checks = HealthCheck(
        database=check_database(),
        redis=_check_redis(),
        blob_volume=FilesystemBlobStore(settings.blob_root).healthcheck(),
        inbox=settings.inbox_path.is_dir(),
    )
    ok = all(checks.model_dump().values())
    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if ok else "degraded",
        version="0.1.0",
        environment=settings.environment,
        checks=checks,
    )


@router.get("/health/live", status_code=status.HTTP_204_NO_CONTENT)
def liveness() -> Response:
    """Process is up. Deliberately checks nothing external."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _check_redis() -> bool:
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        return bool(client.ping())
    except Exception:
        return False
