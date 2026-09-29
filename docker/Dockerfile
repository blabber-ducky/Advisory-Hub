# syntax=docker/dockerfile:1
FROM python:3.13-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libpq for psycopg; the rest are pdfplumber/extract-msg runtime needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer — cached until pyproject.toml changes.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -e ".[dev]" 2>/dev/null || pip install --no-cache-dir \
      "fastapi>=0.115" "uvicorn[standard]>=0.32" "sqlalchemy>=2.0.36" "alembic>=1.14" \
      "psycopg[binary]>=3.2" "pydantic>=2.10" "pydantic-settings>=2.7" "argon2-cffi>=23.1" \
      "structlog>=24.4" "jinja2>=3.1" "python-multipart>=0.0.20" "itsdangerous>=2.2" \
      "redis>=5.2" "rq>=2.0" "httpx>=0.28" "extract-msg>=0.52" "pdfplumber>=0.11"

COPY advisory_hub ./advisory_hub
COPY migrations ./migrations
COPY alembic.ini ./

# Run as a non-root user: this process parses hostile PDFs.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/blobs /data/inbox /data/processing /data/archive /data/failed \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health/live || exit 1

CMD ["uvicorn", "advisory_hub.main:app", "--host", "0.0.0.0", "--port", "8000"]
