# REST API and MCP server

Both are thin adapters over `core/` services. Neither contains business logic.
This is what guarantees that the mandatory-comment rule, transition validation,
and authorisation behave identically no matter which door you come in through.

```
      web/ (HTMX)        api/ (REST)        mcp/ (MCP tools)
           │                  │                    │
           └──────────────────┴────────────────────┘
                              ▼
                     core/services/*        ← rules live here, only here
                              ▼
                    PostgreSQL · blobs
```

---

## Part 1 — REST API

### Conventions

- Base path `/api/v1`. OpenAPI 3.1 served at `/api/openapi.json`, Swagger UI at
  `/api/docs`.
- Cursor pagination: `?limit=50&cursor=…` → `{ "items": [...], "next_cursor": … }`.
- Errors are RFC 9457 problem details.
- All timestamps RFC 3339 UTC.
- Breaking changes require `/api/v2`. Additive changes do not.

### Authentication

| Caller | Mechanism |
|---|---|
| Browser UI | Session cookie, `HttpOnly` `Secure` `SameSite=Lax`, CSRF token on writes |
| Integrations | `Authorization: Bearer ah_<prefix>_<secret>` |

Tokens are scoped; each endpoint declares the scope it needs.

| Scope | Grants |
|---|---|
| `advisories:read` | Read advisories, comments, history |
| `advisories:write` | Change status, add comments |
| `inventory:read` | Read inventory sources and snapshots |
| `inventory:write` | Create/update sources, trigger syncs, upload CSV |
| `scan:run` | Start scans and read results |
| `stats:read` | Read aggregate statistics |
| `vt:check` | Trigger a VirusTotal IOC check and read the result |

### Endpoints

**Advisories**

| Method | Path | Scope | Notes |
|---|---|---|---|
| `GET` | `/advisories` | `advisories:read` | Filters: `status`, `type`, `source_id`, `severity`, `assignee_id`, `received_after/before`, `q` (full-text), `has_cve`, `cve_id` |
| `GET` | `/advisories/{id}` | `advisories:read` | Full detail incl. CVEs, IOCs, products, attachments |
| `PATCH` | `/advisories/{id}` | `advisories:write` | Assignee, type override, severity override only. **Status is not settable here.** |
| `POST` | `/advisories/{id}/status` | `advisories:write` | The only way to change status |
| `GET` | `/advisories/{id}/comments` | `advisories:read` | |
| `POST` | `/advisories/{id}/comments` | `advisories:write` | Free comment, no status change |
| `GET` | `/advisories/{id}/history` | `advisories:read` | Status changes with their comments |
| `GET` | `/advisories/{id}/attachments/{aid}/download` | `advisories:read` | Streams the original blob |

Status change — the enforced shape:

```http
POST /api/v1/advisories/{id}/status
{ "to_status": "IN_PROGRESS", "comment": "Patch scheduled for change CR-4471." }
```

```jsonc
// 422 — comment omitted or blank
{
  "type": "https://advisory-hub/errors/comment-required",
  "title": "A comment is required when changing status",
  "status": 422,
  "detail": "Field 'comment' must be a non-empty string."
}

// 409 — illegal transition
{
  "type": "https://advisory-hub/errors/invalid-transition",
  "title": "Invalid status transition",
  "status": 409,
  "detail": "Cannot move from CLOSED to REMEDIATED. Reopen to TRIAGED first.",
  "allowed": ["TRIAGED"]
}
```

**Sources, inventory, scans, stats**

| Method | Path | Scope |
|---|---|---|
| `GET`/`POST` | `/sources`, `/sources/{id}` | `advisories:read` / admin |
| `GET`/`POST` | `/inventory/sources` | `inventory:read` / `inventory:write` |
| `POST` | `/inventory/sources/{id}/test` | `inventory:write` — read-only connectivity check |
| `POST` | `/inventory/sources/{id}/sync` | `inventory:write` |
| `POST` | `/inventory/sources/{id}/upload` | `inventory:write` — multipart CSV |
| `GET` | `/inventory/snapshots` | `inventory:read` |
| `GET` | `/inventory/search?vendor=&product=&version=` | `inventory:read` — ad-hoc lookup |
| `POST` | `/advisories/{id}/scan` | `scan:run` → **`200`, synchronous** (see "As built" below, not the `202` originally sketched here) |
| `GET` | `/scans/{run_id}` | `scan:run` — status and results |
| `GET` | `/advisories/{id}/scans` | `scan:run` — scan history for one advisory, newest first (added beyond the original sketch) |
| `POST` | `/iocs/{ioc_id}/check-vt` | `vt:check` — VirusTotal reputation check, `{"force": bool}` body |
| `GET` | `/stats/overview` | `stats:read` — counts by status, type, severity, source |
| `GET` | `/stats/aging` | `stats:read` — open advisories by age bucket |
| `GET` | `/stats/mttr` | `stats:read` — `NEW`→`REMEDIATED` median/p90, by severity |
| `GET` | `/stats/exposure` | `stats:read` — endpoints affected, from latest scans |
| `GET` | `/stats/timeseries?metric=&interval=` | `stats:read` — for external dashboards |

`integration_credential` values are **never** present in any response body.

### As built (2026-08-21) — advisory/comment/status/source endpoints only

Phase 1e implemented the advisory-facing slice of this design; sources,
inventory, scans, and stats above are still design-only (later phases).

### As built (2026-08-22) — scans (Phase 2e)

`POST /advisories/{id}/scan`, `GET /scans/{run_id}`,
`GET /advisories/{id}/scans` (`api/routers/scans.py`) are implemented,
plus the equivalent web UI (the "Scan inventory" panel on the advisory
detail page, `web/tracker.py` + `_scan_panel.html`).

- **Runs synchronously, returning `200` with the finished result — not the
  `202`-plus-poll sketched above.** There is no background job queue
  behind `core.services.scan.run_scan()` (see its module docstring);
  matching against every real snapshot this project has scanned completes
  in well under a second, the same reasoning that already applies to the
  inventory "Sync now" button. `POST /advisories/{id}/scan`'s body is
  `{"snapshot_ids": [...]}`; an empty/omitted list defaults to every active
  source's current latest snapshot.
- **The response carries `coverage_gaps`** — `(vendor, product)` pairs the
  advisory's CVEs affect that no scanned candidate matched on vendor+product
  at all, distinct from "present, not in the vulnerable range". Computed on
  demand (`core.services.scan.coverage_gaps()`), not persisted — no schema
  change needed for it. See docs/inventory-matching.md §5.
- A distinct exception class collision was caught while wiring this up:
  `core.services.scan.AdvisoryNotFoundError` is a **different class** from
  `core.services.advisories.AdvisoryNotFoundError`, despite the identical
  name — `api/problems.py`'s handler registry matches by exact type, so the
  existing advisories handler would silently not have fired for a scan
  route's 404. Registered a separate handler for the scan module's version
  rather than merging the two types, which would have collapsed two
  different "not found" meanings into one for no benefit.

### As built (2026-08-22) — VirusTotal IOC checks

`POST /iocs/{ioc_id}/check-vt` (`api/routers/iocs.py`) is implemented, plus
the equivalent web UI (a "check"/"recheck" action per indicator in the
advisory detail page's IOC table). This was not in the original design doc
at all — added on request, following the same `core/`-services-plus-thin-
adapter shape as everything else.

- **Callers pass an `AdvisoryIoc` id, never a raw value.** The route looks
  the value up server-side and never returns it in the response body —
  `VtLookupOut` has no `value` field, matching `IocOut`'s existing
  defanging discipline (CLAUDE.md §2.3). `permalink` legitimately embeds
  the value inside VirusTotal's own report URL, which is intentional and
  safe (a trusted domain, not the indicator itself).
- **Analyst-triggered, never an automatic sweep** — unlike NVD enrichment.
  VT's public tier is 4 requests/minute; a background sweep across every
  IOC in the corpus (227 in the real one) would exhaust it in under a
  minute for no benefit nobody asked for. See docs/decisions.md D-030.
- **Results are cached globally by `(ioc_type, value)`**, not per
  `advisory_ioc` row — the same indicator often cited across several
  advisories shares one check, both to respect the rate limit and to give
  every advisory citing it a consistent answer.
- **Not every `IocType` is checkable.** VT has no lookup endpoint for
  emails, filenames, file paths, registry keys, mutexes, or user agents —
  `POST /iocs/{id}/check-vt` returns `422` for those, and the UI shows
  "—" instead of a check button, rather than attempting a lookup VT can't
  answer.
- **A distinct exception class matters here too**: `VtUnauthorizedError`
  (missing/rejected `VT_API_KEY`) is deliberately *not* caught by the
  broader transport-failure handler in `core.services.vt_lookup.check_ioc()`
  — a real bug caught by a test, not by inspection: `VtUnauthorizedError`
  subclasses `VtError`, so an early version of the `except (VtError, ...)`
  clause silently swallowed it too, persisting a misleading `ERROR` cache
  row for what was actually a configuration problem, not a per-lookup
  failure. Fixed by excluding it with its own `except` clause first.

- **Filters implemented**: `status`, `type`, `severity`, `source_id`,
  `assignee_id`, `q`, `open_only`, `unacknowledged_only` — the same set
  `core.services.advisories.AdvisoryFilters` already supports for the web
  tracker. **Not yet implemented**: `has_cve`, `cve_id`,
  `received_after`/`received_before`. Adding them means extending
  `AdvisoryFilters` itself (shared by both the web UI and the API), not a
  router-only change — a deliberate, tracked deferral, not an oversight.
- **`GET /advisories/{id}/attachments/{aid}/download`** exists exactly as
  designed. **`GET /advisories/{id}/attachments/raw`** (the original email)
  does not yet — only the web UI has it (`web/tracker.py`). Same reasoning:
  small, separate follow-up.
- **`GET`/`POST /sources`, `/sources/{id}`**: only `GET` is implemented.
  `Source` here is the small, mostly-static table of regulator email senders
  (seeded via the `seed-sources` CLI command) — not the Phase 2 inventory
  sources tab this design doc's table groups it near. `POST /sources` is
  deferred to Phase 2a alongside that tab's CRUD work, where it belongs
  either way.
- **Errors are RFC 9457 problem+json for every path under `/api/`** — see
  `api/problems.py`. Domain exceptions raised by `core.services.advisories`
  (`AdvisoryNotFoundError`, `InvalidStatusTransitionError`,
  `MissingCommentError`, `MissingAckChannelError`, `InvalidCursorError`) are
  translated centrally via FastAPI exception handlers, so routers never
  need a try/except — an unhandled domain exception *is* the correct
  response. Plain `HTTPException`s raised directly in a router (e.g. a
  missing attachment) get the same treatment via a generic handler, but only
  for `/api/` paths — the web UI's `HTTPException(303, ...)` login-redirect
  trick in `web/tracker.py` is untouched.
- **Pagination is cursor-based (keyset on `received_at, id`)**, exactly as
  designed — `?limit=&cursor=` → `{"items": [...], "next_cursor": ...}`. The
  web tracker's page-number pagination is unaffected; they're independent
  code paths (`list_advisories` vs. `list_advisories_cursor`).
- **A real authorization gap was found and fixed while wiring the first
  scope-gated route**: `Principal.require_scope()` let any logged-in
  *session* user through a scope check unconditionally, regardless of role —
  a VIEWER could pass an `advisories:write` check. Only API tokens were
  actually being scope-checked. See `core/security/tokens.py:SCOPE_MIN_ROLE`
  and the regression tests in `tests/test_auth_integration.py`.

---

## Part 2 — MCP server

### Purpose

Let dashboards, notebooks, and agent workflows query and act on advisory data
without reimplementing the REST client or, worse, reaching into the database.

### Implementation

Built on the **official `mcp` Python package** (the Model Context Protocol SDK),
running as a separate process in the same image. Two transports:

| Transport | For |
|---|---|
| stdio | Local tools and desktop MCP clients |
| Streamable HTTP | Networked clients; served at `/mcp` behind the same auth |

> Note for future work: this is an MCP **server**. Anthropic's `claude-api` skill
> covers the client side (calling Claude, and consuming MCP servers from the
> Messages API) — different package, don't conflate them. If we later add
> LLM-assisted classification, the model to target is `claude-opus-5`.

Authentication reuses API tokens and their scopes verbatim. An MCP client with a
`advisories:read`-only token cannot change status, and the failure comes from
the same service code that guards the REST route.

### Tools

Read tools:

| Tool | Args | Returns |
|---|---|---|
| `list_advisories` | `status?`, `type?`, `source?`, `severity?`, `since?`, `limit?` | Summary rows |
| `get_advisory` | `advisory_id` | Full detail: CVEs, IOCs, products, comments, history |
| `search_advisories` | `query`, `limit?` | Full-text results with snippets |
| `get_advisory_stats` | `group_by` (`status`/`type`/`source`/`severity`/`month`) | Aggregates |
| `list_inventory_sources` | — | Sources with sync status and freshness |
| `search_inventory` | `vendor?`, `product?`, `version?` | Matching inventory rows with counts |
| `get_scan_results` | `scan_run_id` \| `advisory_id` | Grouped matches with confidence + rationale |

Write tools (require the matching scope):

| Tool | Args | Notes |
|---|---|---|
| `add_comment` | `advisory_id`, `body` | |
| `change_advisory_status` | `advisory_id`, `to_status`, `comment` | `comment` is **required** in the tool schema, and re-validated in the service |
| `scan_inventory` | `advisory_id`, `source_ids?` | Returns a run id; poll with `get_scan_results` |

### Design rules for the MCP layer

1. **Every tool is a call into a `core/` service.** No queries, no rules, no
   validation logic in `mcp/`.
2. **`comment` is a required schema field on `change_advisory_status`** — the
   constraint is visible to the model, not just enforced on rejection.
3. **IOCs are returned defanged**, same as the UI. An agent should not be handed
   a live URL.
4. **Confidence and rationale travel with every scan result.** A consumer must be
   able to distinguish `CONFIRMED` from `POSSIBLE`.
5. **Everything is audit-logged with `actor_kind = MCP`** and the token identity,
   so MCP-driven changes are as traceable as UI ones.
6. **Read tools cap and paginate.** A tool that can return 50k rows will, and
   will blow up someone's context.

### Phasing

The MCP server lands in Phase 3, but the constraint that makes it a small job —
services holding all logic — is enforced from Phase 1. If that rule ever slips,
the MCP server stops being a thin adapter and becomes a second implementation.
