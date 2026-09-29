# Roadmap

Phases are sequenced so something usable exists as early as possible. Each phase
ends with stated acceptance criteria — "done" is demonstrable, not asserted.

Effort estimates assume one developer working with an AI assistant and are
calendar-week ranges, not commitments.

---

## Phase 0 — Foundation ✅ COMPLETE (2026-08-20)

Nothing user-visible; everything after depends on it.

- [x] Repo scaffold matching the layout in `CLAUDE.md` §3
- [x] `docker-compose.yml`: `app`, `worker`, `postgres`, `redis`; volumes for
      `/data/inbox`, `/data/blobs`, `/data/archive`, `/data/failed`
- [x] `docker-compose.override.yml` for development (published ports, reload)
- [x] FastAPI app skeleton, per-check health endpoint, structured JSON logging
      with per-request `request_id`
- [x] SQLAlchemy 2 models + first Alembic migration — **full Phase-1 schema**
      (18 tables) so Phase 1 is pipeline work, not schema work
- [x] `audit_log` append-only enforced by a database trigger, not just grants
- [x] Blob store abstraction (content-addressed, atomic, streaming, 0440)
- [x] Auth: users, roles, sessions, Argon2id, scoped API tokens — behind the
      `AuthProvider` interface
- [x] Admin CLI: `create-admin`, `create-token`, `list-users`, `check`
- [x] `ruff` + `mypy --strict` + `pytest` wired into CI, plus migration
      reversibility and model-drift checks
- [x] `Makefile` for the common developer loop
- [x] `.env.example` documenting every variable

**Done when:** `docker compose up` gives a running app, an admin user can be
created via CLI and log in, and CI is green. — **Verified end-to-end:** 82 tests
passing, lint and types clean, container builds, migration applies, admin logs
in, audit trail records it.

---

## Phase 1 — Advisory tracking (MVP) (~3–4 weeks)

The thing the user actually asked for first. Delivers standalone value with no
inventory features at all.

### 1a. Ingestion ✅ COMPLETE (2026-08-20)
- [x] Inbox watcher with atomic claim and crash recovery
- [x] `.msg` (primary) and `.eml` parsing; attachment extraction to blobs,
      discarding inline signature images
- [x] Sandboxed PDF text + table extraction in a resource-capped subprocess
- [x] Section-scoped extractors: CVE, CVSS, IOC (refang/defang), ATT&CK,
      threat actor, product/version, reference URLs
- [x] CSV/XLSX IOC sidecar parsing (defusedxml — untrusted attachment XML)
- [x] Structural classifier with calibrated confidence and review flagging
- [x] Cross-validation: ref mismatch, severity mismatch, unknown sender
- [x] Two-clock SLA computation (D-018)
- [x] Re-issue linking by title fingerprint (D-020)
- [x] Sender → source resolution; `UNKNOWN` fallback, flagged
- [x] Idempotent dedupe on content hash
- [x] `failed/` handling with `.error.json` sidecars
- [x] `reparse` CLI command, preserving all analyst-owned fields
- [x] CLI: `ingest`, `watch`, `reparse`, `seed-sources`

**Verified against the real corpus:** 135/135 parsed and persisted, 0 failures,
0 PDF extraction failures, ~0.19s per advisory. 404 distinct CVEs, 227 IOCs,
253 product claims. Re-ingest yields 135 duplicates and no new rows.

### 1b. Enrichment ✅ COMPLETE (2026-08-20)
- [x] NVD API 2.0 client: sliding-window rate limiter, exponential backoff
      honouring `Retry-After`, redirects off the NVD host refused
- [x] Redis cache (24h hits / 1h misses), degrading to no-cache if unavailable
- [x] Persist CVSS v3 + v4 scores and vectors, description, published date
- [x] Persist **`cve_cpe` configuration rows** — vendor, product, and version
      bounds, normalised for Phase-2 matching
- [x] Severity/SLA re-scoring: NVD may **raise** an advisory's severity and both
      clocks, never lower them (D-019)
- [x] Graceful degradation: `SKIPPED_OFFLINE` when `NVD_ENABLED=false`; `ERROR`
      distinguished from `NOT_FOUND` so transport failures are retried and
      genuine absences are not
- [x] Background sweep in the worker + `advisory-hub enrich` CLI

**Verified against live NVD**, not mocks: real corpus CVEs enriched with 0
errors, CPE ranges landing per vendor/product. Throughput is rate-limit bound —
~50 min anonymous for a 404-CVE backfill, ~5 min with an API key.

### 1c. Tracker + dashboard ✅ COMPLETE (2026-08-21)
- [x] KPI tiles: open, unacknowledged, ack overdue/due-soon, resolution overdue,
      flagged for review — each links into a pre-filtered tracker view
- [x] Table: Source · Type · Title · Severity · Status · Acknowledge-by · Last comment
- [x] Filter on status/type/severity/source; full-text search box
      (`plainto_tsquery` + reference-number `ilike`); every filter/pagination
      request is an HTMX partial swap of `#tracker-body`, with `hx-push-url`
      so filtered views are bookmarkable/back-button-safe
- [x] Row expands (HTMX partial, lazy-loaded once) to the detail panel: overview,
      CVEs with CVSS + NVD enrichment status, affected products with evidence
      source, IOCs (**defanged**, with an explicit do-not-resolve warning),
      TTPs, related advisories, flags, attachment downloads, comment thread
- [x] Status badges follow the project's dataviz conventions (fixed status
      palette, icon+label never color-alone, light/dark via CSS custom
      properties)
- [ ] Inline status editor — **deferred to 1d**: the detail panel's "Change
      status" button is present but disabled, since it depends on the
      `change_status()` chokepoint

**Verified end-to-end** with `TestClient` against the real dev database and
corpus data (not just unit tests): anonymous `GET /` redirects to `/login`;
an authenticated session sees the dashboard, filtered/paginated table, an
expanded advisory detail row, and a working raw-email download. 18 new unit
tests for `core/services/advisories.py` (filtering, pagination, search,
dashboard stats, last-comment batching) — 242 tests passing project-wide,
`ruff` and `mypy --strict` clean.

### 1d. Status and audit ✅ COMPLETE (2026-08-21)
- [x] `change_status()` service — transaction, transition validation, mandatory comment
- [x] `status_change.comment_id NOT NULL` in the schema (already in place since Phase 0)
- [x] Append-only `audit_log` with no update/delete grants (already in place since Phase 0)
- [x] Row-locked advisory read (`SELECT ... FOR UPDATE`) so two concurrent
      status changes on the same advisory serialise rather than race (D-021)
- [x] Acknowledgement records `acknowledged_at`, `acknowledged_by_id`, and a
      required `ack_channel`
- [x] Web UI: the detail panel's status form (was a disabled placeholder in
      1c) posts to `POST /advisories/{id}/status`; ANALYST role or higher
      required; validation failures re-render the form with an inline error
      (D-021); a successful change triggers a full page refresh via
      `HX-Refresh` so the table, dashboard tiles, and detail panel all stay
      consistent

**Verified**: 10 new unit tests for `change_status()` (happy path, blank
comment, illegal transition, missing ack channel, unknown advisory, reopening
a closed advisory, status-history reflection) plus a manual end-to-end
`TestClient` run against the real dev database covering all four form
outcomes (missing comment, illegal transition, missing ack channel, valid
transition) and the viewer-role 403. 252 tests passing project-wide; `ruff`
and `mypy --strict` clean. No migration needed — the schema already had
everything Phase 1d needed since Phase 0.

### 1e. REST API ✅ COMPLETE (2026-08-21)
- [x] `/api/v1` advisory, comment, status, source endpoints
- [x] API tokens: scoped, hashed, revocable, last-used tracked (already in
      place since Phase 0 — this phase is the first to actually gate a route
      on a scope)
- [x] OpenAPI at `/api/docs` (already serving since Phase 0 — new routes
      appear automatically)
- [x] Cursor (keyset) pagination on `(received_at, id)`, per docs/api-and-mcp.md
- [x] RFC 9457 problem-details responses for every `/api/` error path,
      including the documented 409 `invalid-transition` (with an `allowed`
      list) and 422 `comment-required` shapes
- [x] `PATCH /advisories/{id}` — assignee/type/severity only, status not
      settable (enforced by the schema, not just convention)
- [x] `GET /sources`, `GET /sources/{id}` — read-only; CRUD is Phase 2a scope

**Scope trimmed from the original design**, recorded rather than silently
dropped: `has_cve`, `cve_id`, and `received_after`/`received_before` filters,
and `GET /advisories/{id}/attachments/raw` (the original email) are not in
this pass — `AdvisoryFilters` doesn't support the first three yet, and the
per-attachment download endpoint covers the common case. `POST /sources` is
deferred to 2a's source CRUD work. See docs/api-and-mcp.md's "As built" note.

**Real bug found and fixed while wiring the first scope-gated route**:
`Principal.require_scope()` let any authenticated *session* user through
regardless of role — a VIEWER could pass an `advisories:write` check purely
by being logged in, because the check short-circuited on `ActorKind.USER`
before ever looking at role. Only API tokens were actually scope-checked.
Fixed via a `SCOPE_MIN_ROLE` mapping; regression tests added. Web routes
happened to be unaffected in practice, since `web/tracker.py`'s status-change
route already enforced `Role.ANALYST` directly — but the gap was real and
would have bitten the first web route that relied on `require_scope` alone.

**Verified**: 16 new integration tests exercising the real FastAPI app via
`TestClient` (auth, pagination, RFC 9457 error shapes, status-change
enforcement, comments, PATCH semantics, IOC defanging) plus a manual
end-to-end run against the real dev database with minted tokens covering
every documented error shape. 270 tests passing project-wide; `ruff` and
`mypy --strict` clean.

**Done when:** a real regulator email with a PDF, dropped into `/data/inbox`,
appears in the tracker within a minute with correct source, type, CVEs, and IOCs;
status cannot be changed without a comment via UI *or* API; the audit trail shows
who changed what, when, and why; and the same operations work through the REST
API with a scoped token. — **All met.**

---

## Phase 2 — Inventory and scanning (~3–4 weeks)

The user's stated "next phase".

### 2a. Inventory sources tab ✅ COMPLETE (2026-08-21)
- [x] Source CRUD with kind-specific config forms — the create form shows
      base URL / credential fields only for API-kind sources, and
      credential fields specific to the chosen auth type
- [x] Encrypted credential storage (Fernet, key rotation supported), write-only —
      `core.security.crypto`; `FERNET_KEY`/`FERNET_KEY_PREVIOUS` support
      rotation; `has_credential` is the only credential-shaped thing that
      ever crosses an API or template boundary
- [x] "Test connection" action — honestly reports what it can today: SSRF-
      validates the configured `base_url` for API sources, since the actual
      adapter calls are Phase 2c; CSV sources report they have no live
      connection at all
- [x] Sync history — backed by the append-only `audit_log` rather than a new
      table (`inventory_source` already carries `last_sync_at/status/error`
      as the current-state summary; full history is every
      create/update/test/sync audit event for that source)
- [x] SSRF guard (`core.security.ssrf`) — host allowlist, scheme
      enforcement, DNS resolution checked against loopback/link-
      local/private/multicast/reserved ranges and the AWS/Azure/GCP
      metadata IP explicitly, per CLAUDE.md §2.3
- [x] Full Phase 2 schema landed in one migration (`inventory_source`,
      `integration_credential`, `inventory_snapshot`, `inventory_software`,
      `inventory_device`, `inventory_device_software`, `vendor_alias`,
      `scan_run`, `scan_match`) — same "schema now, features later" approach
      Phase 0 used, so 2b–2e are feature work, not schema work
- [x] REST API: `/api/v1/inventory/sources` CRUD + `/test` + `/history`
- [x] Web UI: new "Inventory" nav tab, source list with expandable detail
      (config, history, test-connection button, activate/deactivate)

**Real bug found and fixed**: Alembic's `op.drop_table()` doesn't drop the
PostgreSQL native `ENUM` types a table's columns used, so a full
`downgrade()`/`upgrade()` cycle collided on `CREATE TYPE ... already
exists` — for this migration **and**, it turned out, for the original
Phase 0 migration too, which had the identical latent bug in all 14 of its
enum types, undetected until now because no prior check had run a full
down/up cycle. Both migrations fixed; see D-023.

**Verified**: 20 new unit tests for `crypto.py`/`ssrf.py` (key rotation,
malformed keys, every non-routable address class, split-DNS partial
blocking), 13 for the inventory service, 10 API integration tests, plus a
manual end-to-end run against the real dev database covering the full
create → test-connection → toggle-active → history flow through both the
REST API and the actual web form. Migration reversibility verified with two
full `downgrade base` → `upgrade head` cycles against the disposable test
database. 316 tests passing project-wide; `ruff` and `mypy --strict` clean.

### 2b. CSV ingest ✅ COMPLETE (2026-08-21)
- [x] Upload → blob → header sniffing → **mapping preview** → confirm → snapshot —
      `core.services.inventory.preview_csv()` stores the upload as a blob and
      parses it without writing any `inventory_snapshot`/`inventory_software`
      rows; `commit_csv_snapshot()` re-reads that same blob by ID and commits,
      so the analyst's edited mapping only has to travel as form/JSON fields
      between the two requests, not as server-side session state
- [x] Built-in profiles for Desktop Central, Lansweeper, Azure —
      `inventory/csv_profiles.py`, matching this doc's §2 table exactly,
      including Azure's `osType`/`osName` OS-row detection
- [x] Editable, persisted column mapping per source — the mapping-preview
      screen's `<select>`s default to the auto-detected columns but are
      freely reassignable before confirming; a successful commit persists
      the mapping actually used onto `inventory_source.config.column_mapping`
      as the default for next time
- [x] Per-row parse error reporting with line numbers — every row that
      fails (blank product, non-numeric or negative device count) is
      reported with its 1-indexed CSV line number, never silently dropped
- [x] Rows sharing `(vendor, product, version, kind)` are aggregated by
      summing `device_count` — handles both already-aggregated exports (a
      count column) and raw per-device exports (no count column, each row
      implicitly one device) identically, without the analyst having to
      know which shape their export is
- [x] Re-uploading creates a new snapshot and atomically demotes the
      previous one's `is_latest` flag (partial-unique-index-safe ordering:
      `UPDATE ... SET is_latest = false` runs before the new row's `INSERT`)
- [x] Tier-1 version normalisation (numeric-tuple extraction) populates
      `version_normalized`/`version_parts` on write — deliberately partial;
      the full tiered comparator (PEP 440, Java `8u391`, Windows builds,
      `YYYY CUnn`) is Phase 2d, and a version that doesn't yield a numeric
      tuple is honestly stored as `None`, not guessed
- [x] REST API: `POST .../csv/preview` (multipart), `POST .../csv/commit`
- [x] Web UI: an "Upload inventory CSV" section on CSV-kind sources' detail
      panel, with the mapping editor and a live preview/error table before
      the analyst confirms

**Deliberately not vendor/product-canonicalised yet**: `InventorySoftware.
vendor`/`.product` are lowercase-trimmed only, a placeholder for the real
`vendor_alias`-backed canonicalisation, which is Phase 2d's job — matching
is what actually needs that table, and matching doesn't exist yet either.

**Verified**: 23 unit tests for `inventory/csv_parser.py` and
`inventory/version.py` (auto-mapping, every row-error class, Azure OS-row
detection, the row-count limit), 16 for the service-layer preview/commit
orchestration (aggregation across duplicate rows, the `is_latest` flip,
sync-status transitions, mapping persistence), 15 new REST API integration
tests, plus a manual end-to-end run against the real dev database through
both the API and the actual HTML upload form — a real Lansweeper-shaped CSV
with deliberate parse errors, confirming the exact row counts, error
messages, and aggregated device counts landed correctly in
`inventory_software`. 360 tests passing project-wide; `ruff` and
`mypy --strict` clean.

### 2c. API integrations ✅ COMPLETE (2026-08-22)
- [x] SSRF guard: host allowlist, metadata/link-local denial, no cross-host
      redirects (already built in 2a; every adapter call re-validates
      immediately before use, not just at config-save time — DNS can rebind)
- [x] Desktop Central adapter (per-device software) — **lower-confidence
      than the Microsoft adapters, unverified against a live instance**;
      see docs/inventory-matching.md's "As built" note
- [x] Azure ARM adapter (VMs, OS type — OS *version* is a documented gap,
      not silently guessed at)
- [x] MS Graph adapter (Intune managed devices + detected apps, capped at
      500 devices for the per-device software calls)
- [x] Scheduled sync — a worker poller (not RQ jobs; see below) checks
      `schedule_cron` via `croniter` every `INVENTORY_SYNC_POLL_SECONDS`
- [x] Immutable snapshots, failure leaves prior snapshot latest — a failed
      `fetch()` never touches `inventory_snapshot` at all; the failure is
      recorded on the source (`last_sync_status`/`last_sync_error`) and in
      the audit log instead
- [x] `test_connection()` now actually calls the adapter for API sources —
      the 2a stub ("not implemented yet") is gone
- [x] REST API: `POST .../sources/{id}/sync`; web UI: a "Sync now" button
      on API-kind sources, alongside the existing "Test connection"

**Scheduling is a worker background-thread poller, not RQ jobs** — same
pattern as the existing inbox and enrichment pollers (`worker/__main__.py`),
not a design change. Each due source gets sync'd in its own transaction, so
one source's failure can't roll back another's or block the sweep.

**Real bug found and fixed while wiring the "Sync now" endpoint**: both the
REST route and the web route originally let `ApiAdapterError` propagate
uncaught after `sync_source()` had already written the failure state
(`source.last_sync_status = ERROR`, an audit entry) via `db.flush()`. Since
neither route called `db.commit()` on that path, the failure record would
have been silently rolled back on session close — the one piece of
information an operator most needs (why the sync failed) would have
vanished. Fixed by committing the flushed failure state before returning
the error response.

**Verified against mocked HTTP, not live tenants** — no Desktop Central,
Azure, or Graph sandbox was available, unlike NVD in Phase 1b, which was
validated against the real live API. Request/response shape is verified
against the documented Azure ARM and MS Graph API contracts via
`httpx.MockTransport`; Desktop Central's shape is unverified, as stated
above. 10 adapter tests, 22 new service-layer tests (successful sync,
snapshot aggregation across duplicate devices, the failed-sync-preserves-
latest-snapshot guarantee, partial-fetch handling), 5 new REST API tests.
380 tests passing project-wide; `ruff` and `mypy --strict` clean.

### 2d. Normalisation and matching ✅ COMPLETE (2026-08-22)
- [x] `vendor_alias` table, seeded (`core/services/vendor_alias.py`,
      `cli.py seed-vendor-aliases`) — ~60-entry non-exhaustive seed list,
      loaded once per operation into an in-memory dict, never queried per-row
- [x] Product name normalisation — lowercase, whitespace-collapsed,
      architecture/edition noise stripped (`(x64)`, `64-bit`, `- en-US`, …).
      **Not preserved in a separate "edition" side field** — the original
      design's aspiration, but no such column exists and nothing downstream
      would consume it; not worth a migration. See docs/inventory-matching.md.
- [x] Tiered version comparator (`inventory/version.py`): PEP 440 first (gets
      pre-release ordering right, `2.15.0rc1 < 2.15.0`), numeric-tuple
      fallback, honest `None` when neither tier can compare with confidence —
      never a guess. `version_parts` (tier 1, storage-only) unchanged since 2b.
- [x] Matcher (`inventory/matcher.py`) producing `CONFIRMED` / `LIKELY` /
      `POSSIBLE` with a plain-English rationale string per match — see
      docs/inventory-matching.md for the confidence-tier rules
- [x] Persistence layer: `core.services.scan.run_scan()` — synchronous,
      writes `scan_run`/`scan_match`, filters `CveCpe.vulnerable` before
      building specs, spans multiple snapshots per scan. **No UI/route calls
      it yet** — that's 2e, by design; see its module docstring for the
      D-024-pattern commit discipline the 2e caller must follow.

**Grounded against two real inventory exports** the user placed in
`Inventory/` (an Endpoint Central "Software Summary" CSV and a Lansweeper
"web50" CSV, 11,481 and 6,749 rows) — not synthetic fixtures. Ingesting them
surfaced two real, previously-undetected bugs (see docs/decisions.md D-026,
D-027) and one real corrected CSV-profile gap (a second OS-row-detection
convention, value-equality rather than Azure's any-non-blank signal — see
docs/inventory-matching.md).

**End-to-end real-data verification**: cross-referencing the newly-ingested
inventory against the already-enriched Phase 1 corpus found exactly one
genuine overlap — 7-Zip, both in a real DOH advisory (DOH-2026539) and a
real installed row (version 26.02, one device). Running `run_scan()` against
it produced `match_count == 0`, the *correct* result: the installed version
sits exactly on the CPE range's exclusive upper bound (`< 26.02`), i.e. it's
the patched release, not vulnerable — confirming the comparator handles a
real boundary case correctly rather than off-by-one'ing it into a false
positive. 48 new tests (version comparator, normalisation, matcher, vendor-
alias service, scan service — including the vulnerable-filter and multi-
snapshot attribution). 441 tests passing project-wide; `ruff` and
`mypy --strict` clean.

### 2e. Scan from advisory ✅ COMPLETE (2026-08-22)
- [x] "Scan inventory" button in the expanded advisory, with source
      selection (checkbox list of every active source's current latest
      snapshot, all checked by default)
- [x] **Synchronous, not background** — a deliberate divergence from the
      design's "background `scan_run`; panel polls" sketch. There's no job
      queue behind `run_scan()`; matching completes in well under a second
      against every real snapshot this project has scanned, the same
      reasoning already established for the inventory "Sync now" button.
      The panel's `POST` gets the finished result in one request/response
      cycle. See docs/inventory-matching.md's "As built" note.
- [x] Results grouped by confidence (`CONFIRMED`/`LIKELY`/`POSSIBLE`),
      each with a plain-English rationale. **Device drill-down for
      `DETAILED` sources deliberately not built** — no `DETAILED`-mode
      source has real device-identifier data ingested yet to develop it
      against; `ScanMatch.device_ids` is populated by the matcher but
      nothing in the UI reads it yet.
- [x] Explicit "not found ≠ not affected" coverage-gap messaging —
      `core.services.scan.coverage_gaps()`, computed on demand (no schema
      change needed), surfaced in both the web panel and the REST API
      response
- [x] Scan history retained per advisory — `core.services.scan.scan_history()`,
      shown in the web panel and via `GET /advisories/{id}/scans`
- [x] REST API: `POST /advisories/{id}/scan` (defaults to every active
      source's latest snapshot), `GET /scans/{run_id}`,
      `GET /advisories/{id}/scans` — all under the `scan:run` scope

**Two real bugs found while wiring this up, not by inspection**: (1)
`core.services.scan.AdvisoryNotFoundError` is a distinct class from
`core.services.advisories.AdvisoryNotFoundError` despite the identical
name — `api/problems.py` matches exception handlers by exact type, so the
existing advisories handler would silently never have fired for a scan
route's 404; fixed by registering the scan module's own handler. (2)
`scan_history()`'s original `ORDER BY created_at DESC` was
non-deterministic for two scans in the same transaction, because
`created_at`'s `server_default=func.now()` is transaction-scoped in
Postgres; fixed by ordering on `started_at` (a Python-side `utcnow()` call
per `run_scan()` invocation) instead. See docs/decisions.md D-028.

**Verified**: 17 new tests (service-layer `scan_history()`/`get_scan_run()`/
`coverage_gaps()`, REST API auth/trigger/get/history), plus a manual
end-to-end run against the real dev database — logged in as a real session
user, opened the real DOH-2026539 advisory, triggered a scan through the
actual HTML form against a temporary vulnerable-version 7-Zip snapshot, and
confirmed the rendered `POSSIBLE`-confidence result (open-ended NVD range,
no lower bound) matched the service layer exactly; confirmed a VIEWER
session can read the panel but gets `403` triggering a scan. All temporary
verification data was removed afterward. 448 tests passing project-wide;
`ruff` and `mypy --strict` clean.

**Done when:** an analyst uploads a Desktop Central CSV, opens a Log4j-style
advisory, clicks Scan, and sees affected product/version rows with endpoint
counts, confidence tiers, and a plain-English rationale for each match — plus a
clear statement of which affected products no source covers.

---

## Phase 3 — API surface, MCP, and reporting (~2 weeks)

- [ ] MCP server (`mcp` Python package), stdio + streamable HTTP transports
- [ ] All read and write tools from `docs/api-and-mcp.md`, scope-enforced, `actor_kind = MCP`
- [ ] `/stats/*` endpoints: overview, aging, MTTR, exposure, timeseries
- [ ] Reporting page: filterable, with CSV and PDF export
- [ ] SLA clock by severity (once thresholds are supplied — open question 3)
- [ ] Scheduled digest email (open/overdue advisories)

**Done when:** an external dashboard can pull statistics via token-authenticated
REST, and an MCP client can list, search, comment on, and re-status advisories —
with the comment requirement enforced identically.

---

## Phase 4 — Hardening and quality of life (~2 weeks)

- [ ] Entra ID OIDC swapped in behind the existing `AuthProvider` interface
- [ ] Notifications: new critical advisory, scan found exposure, SLA breach
- [ ] Bulk operations (bulk status change — still one comment per advisory)
- [ ] Saved views and per-user filter presets
- [ ] Advisory linking (supersedes / relates-to) for reissued advisories
- [ ] Backup and restore runbook, exercised
- [ ] Load test at expected volume; index tuning

---

## Sequencing notes

- **Phase 1 is independently valuable.** If Phase 2 were cancelled, the tracker
  still solves the stated primary problem.
- **The REST API is in Phase 1, not deferred.** Building it alongside the UI is
  what forces the service-layer discipline; retrofitting it later would mean
  untangling logic from route handlers.
- **MCP is deliberately late but cheap.** Because services hold all logic, the MCP
  server is a schema-mapping exercise, not a reimplementation — provided the
  `core/`-only rule holds from day one.
- **Real sample emails are the biggest schedule risk.** Parser accuracy in
  Phase 1a is bounded by having 10–20 genuine regulator emails and PDFs to build
  fixtures from. Getting those early is the highest-leverage thing available.
