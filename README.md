# Advisory Hub

Internal portal for tracking regulatory security advisories end-to-end: ingest the
emails your regulators send, parse them (body **and** PDF attachments), track
remediation status with an enforced audit trail, and — from Phase 2 — scan your
endpoint inventory to answer "are we actually affected?"

**Status:** planning complete, implementation not started. See
[docs/roadmap.md](docs/roadmap.md).

---

## What it does

| Capability | Phase |
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
| MCP server for external dashboards and agent integrations | 3 |
| Stats/reporting endpoints, SLA tracking, exports | 3 |

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
| [docs/operations.md](docs/operations.md) | Deploy, backup, config reference, runbooks |

[CLAUDE.md](CLAUDE.md) holds standing instructions and the running progress log.

## Stack

Python 3.14 · FastAPI · PostgreSQL 16 · SQLAlchemy 2 + Alembic · Jinja2 + HTMX +
Tailwind · Redis + RQ for background work · Docker Compose. No Node toolchain
required.

## Quick start

```bash
cp .env.example .env
# Set SECRET_KEY — compose refuses to start without it:
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env

docker compose up -d
docker compose exec app alembic upgrade head
docker compose exec app python -m advisory_hub.cli create-admin
open http://localhost:8080
```

`docker-compose.override.yml` is applied automatically and adds development
conveniences (published database port, live reload, console logs). For a
production-shaped run, use `docker compose -f docker-compose.yml up -d`.

For a real deployment, serve it over **HTTPS**: install your certificate with
`scripts/https-setup.sh install …` and restart — see
[docs/operations.md §7](docs/operations.md#7-https).

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
