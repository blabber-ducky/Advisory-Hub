# Advisory Hub

Internal portal for tracking regulatory security advisories end-to-end: ingest the
emails your regulators send, parse them (body **and** PDF attachments), track
remediation status with an enforced audit trail, and — from Phase 2 — scan your
endpoint inventory to answer "are we actually affected?"

**Status:** Phases 0–2 complete (ingestion, enrichment, tracker, REST API,
inventory sources and scanning), plus VirusTotal IOC checks, the IOC and
Affected Software tabs, an admin panel and a production compose file.
Phase 3 (MCP server, reporting) is next. See [docs/roadmap.md](docs/roadmap.md)
and the progress log in [CLAUDE.md](CLAUDE.md) §4.

---

## What it does

| Capability | Phase / status |
|---|---|
| Watch a folder for `.eml`/`.msg` dropped by Power Automate | 1 |
| Parse email headers, body, and PDF attachments; extract CVEs, IOCs, products | 1 |
| Classify advisories (CVE / security bulletin / threat landscape) | 1 |
| Tracker + dashboard: Source, Type, Title, Description, Status, Last comment | 1 |
| Expandable advisory detail with full parsed content and original attachments | 1 |
| Status changes that **require** a comment, recorded as an immutable audit trail | 1 |
| NVD enrichment (CVSS, CPE product/version ranges) | 1 |
| REST API (OpenAPI) + scoped API tokens | 1 |
| Inventory sources: CSV upload (Desktop Central, Lansweeper, Azure) | 2 |
| Inventory sources: API integration (Desktop Central, Azure ARM, MS Graph) | 2 |
| "Scan inventory" from an advisory, with results shown inline | 2 |
| IOC tab (remediation status, CSV export) and rate-limited bulk VirusTotal checks | Added |
| Affected Software tab: every product match across the estate | Added |
| Admin panel: NVD / VirusTotal keys without a restart | Added |
| Mediclinic light/dark theme, production compose file | Added |
| MCP server for external dashboards and agent integrations | 3 |
| Stats/reporting endpoints, SLA tracking, exports | 3 |
| Import the manual spreadsheet tracker (statuses + comments), with preview | Added |
| Status export (CSV, on demand + daily backup) that re-imports to restore a lost deployment | Added |
| HTTPS served by the app itself — your certificate, or a self-signed one generated on first start | Added |

## Documentation

Start here, in order:

| Doc | What's in it |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System design, components, request flows, security model |
| [docs/data-model.md](docs/data-model.md) | Every table, column, and relationship |
| [docs/ingestion.md](docs/ingestion.md) | The email → PDF → structured advisory pipeline |
| [docs/inventory-matching.md](docs/inventory-matching.md) | How "is this CVE in our estate?" is actually answered |
| [docs/api-and-mcp.md](docs/api-and-mcp.md) | REST surface, auth, and the MCP server design |
| [docs/roadmap.md](docs/roadmap.md) | Phased delivery plan with acceptance criteria |
| [docs/decisions.md](docs/decisions.md) | Settled technical decisions and why |
| [docs/deployment.md](docs/deployment.md) | **Production install, upgrade, rollback** with `docker-compose.prod.yml` |
| [docs/operations.md](docs/operations.md) | Config reference, backup, runbooks, image publishing |

[CLAUDE.md](CLAUDE.md) holds standing instructions and the running progress log.

## Stack

Python 3.13+ · FastAPI · PostgreSQL 16 · SQLAlchemy 2 + Alembic · Jinja2 + HTMX
(hand-written CSS, no framework) · Redis + RQ for background work · Docker
Compose. No Node toolchain required. HTTPS is served by the app itself
(own or generated self-signed certificate) or by your WAF / reverse proxy.

## Quick start (development)

```bash
cp .env.example .env
# Set SECRET_KEY — compose refuses to start without it:
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env

docker compose up -d
docker compose exec app alembic upgrade head
docker compose exec app python -m advisory_hub.cli create-admin
open http://localhost:8080
```

All data — database, blobs, inbox, archive — lives in `./data/` beside the
compose file (git-ignored), in every setup, dev and production.

`docker-compose.override.yml` is applied automatically and adds development
conveniences (builds from the working tree, published database port, live
reload, console logs).

### Production

Use **`docker-compose.prod.yml`** and follow
[docs/deployment.md](docs/deployment.md). It pulls the pinned image CI
publishes to Docker Hub (`advisory-hub`), serves HTTPS itself or sits
behind your WAF / reverse proxy, keeps the database and queue off the
network, runs migrations automatically, and refuses to start with any
required value unset.

```bash
cp .env.production.example .env        # fill in every CHANGE_ME
docker compose pull && docker compose up -d
```

### Working on it locally

```bash
make venv          # virtualenv + dependencies
make up testdb     # postgres + redis, then create the test database
make migrate       # apply migrations
make check         # lint + types + tests (what CI runs)
make serve         # uvicorn with reload
```

`make help` lists every target.

## Status

**Phase 0 complete** — scaffold, schema, auth, blob storage, audit trail, CI.
82 tests passing; `ruff` and `mypy --strict` clean. Phase 1 (ingestion and the
tracker UI) is next; see [docs/roadmap.md](docs/roadmap.md).
