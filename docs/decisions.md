# Decisions

Settled technical decisions, why they were made, and what they rule out. Add a
new entry whenever a choice closes off alternatives. Never edit history — if a
decision is reversed, add a superseding entry that says so.

---

## D-001 — Python + FastAPI + HTMX, server-rendered
**Date:** 2026-08-20 · **Status:** Accepted

Python 3.14 is installed; Node is not. Python's email and PDF parsing ecosystem
(`pdfplumber`, `email`, `extract-msg`, `ocrmypdf`) is substantially stronger than
anything in JS, and parsing is the riskiest part of this project. HTMX covers the
three interactive needs — expandable rows, inline status edit, inline scan
results — as HTML fragment swaps, with no build step and one deployable.

**Rules out:** React/Vue SPA, Next.js. **Revisit if:** the dashboard grows into
genuinely complex client-side interactivity, at which point the REST API already
exists to serve a separate frontend without rework.

---

## D-002 — On-prem Docker Compose + PostgreSQL 16
**Date:** 2026-08-20 · **Status:** Accepted (user choice)

Handles concurrent writers, gives real full-text search via `tsvector`, and JSONB
for parsed payloads and integration config. Regulator advisories are sensitive;
keeping them on-prem avoids a data-classification conversation entirely.

**Rules out:** SQLite (concurrency and FTS quality), cloud-hosted (for now).

---

## D-003 — Local auth with roles, behind an `AuthProvider` interface
**Date:** 2026-08-20 · **Status:** Accepted (user choice)

Local Argon2id users with Viewer/Analyst/Admin unblock development immediately;
the interface means Entra ID OIDC is a Phase 4 swap rather than a refactor. The
`user` table already carries `external_subject` for the eventual OIDC `sub`.

**Rules out:** no-auth mode. Status changes must be attributable — that is the
whole point of the audit trail.

---

## D-004 — NVD as the only enrichment source, behind a provider interface
**Date:** 2026-08-20 · **Status:** Accepted (user choice)

NVD gives CVSS scores *and*, critically, CPE configuration data — the
vendor/product/version ranges that make Phase 2 inventory matching accurate
rather than string-guessing. The user selected NVD only; KEV and EPSS were
offered and not chosen.

Enrichment sits behind a provider interface, so CISA KEV and FIRST EPSS are
additive later without touching the ingestion pipeline.

**Consequence:** the deployment needs allowlisted outbound access to
`services.nvd.nist.gov`. If that is refused, everything still works — enrichment
is marked `SKIPPED_OFFLINE` and matching falls back to PDF-derived product data
at lower confidence.

---

## D-005 — REST API and MCP server are first-class requirements
**Date:** 2026-08-20 · **Status:** Accepted (user requirement)

Added by the user during scoping: the tool must expose an API and an MCP server
for future dashboard and agent integrations.

**This is the single most structurally important decision in the project.** It
forces all business logic into `core/` services, with `web/`, `api/`, `mcp/`, and
`worker/` as thin adapters. Without that discipline, the mandatory-comment rule
would need reimplementing per entry point — and would eventually diverge.

**Consequence:** the REST API is built in Phase 1 alongside the UI, not deferred.
The MCP server lands in Phase 3 and is a schema-mapping exercise only.

---

## D-006 — Mandatory status comment enforced at three layers
**Date:** 2026-08-20 · **Status:** Accepted (user requirement)

1. **Schema** — `status_change.comment_id` is `NOT NULL`
2. **Service** — `change_status()` rejects empty/whitespace comments and is the
   only code path that writes a status change
3. **Interface** — UI disables Save; API returns `422`; MCP marks `comment`
   required in the tool schema

Belt and braces on purpose. A future contributor adding a fourth entry point
cannot accidentally regress the requirement, because the database refuses.

---

## D-007 — Content-addressed immutable blob storage
**Date:** 2026-08-20 · **Status:** Accepted

Original `.eml` files, attachments, extracted text, and uploaded CSVs are stored
by SHA-256 and never deleted or mutated. Parsers read from blobs.

**Why:** these are compliance artefacts; parsers will improve and need to re-run;
content hashing gives idempotent ingestion for free.

**Consequence:** disk grows monotonically. Sizing and backup are covered in
`operations.md`. Filesystem for now, S3-compatible object storage later behind
the same abstraction if volume demands it.

---

## D-008 — Rules-based classification, not LLM
**Date:** 2026-08-20 · **Status:** Accepted

Advisory type (`CVE_ADVISORY` / `SECURITY_BULLETIN` / `THREAT_LANDSCAPE`) is
decided by a scored rule set. Deterministic, explainable, testable, free, and it
works air-gapped — and every classification can be justified to an auditor.

Confidence is stored; below 0.5 the advisory is flagged for review rather than
silently mis-filed. Analyst overrides are logged and become tuning data.

**Revisit if:** rule accuracy proves inadequate on real samples. An LLM classifier
would then go behind a feature flag, would require a separate decision about
sending regulator content off-network, and would target `claude-opus-5`.

---

## D-009 — Match confidence is always exposed, never collapsed
**Date:** 2026-08-20 · **Status:** Accepted

Inventory matches carry `CONFIRMED` / `LIKELY` / `POSSIBLE` plus a plain-English
rationale, and the UI groups by tier. Affected products with no inventory
coverage are reported explicitly as a coverage gap.

**Why:** a security tool that says "not affected" when it means "I couldn't tell"
is worse than one that says nothing. Version and product-name matching across
Desktop Central, Lansweeper, Azure, and NVD CPE is genuinely ambiguous; the
honest response is to show the uncertainty rather than launder it.

---

## D-010 — Untrusted-input handling for emails and PDFs
**Date:** 2026-08-20 · **Status:** Accepted

Parsing runs in a resource-capped, network-less subprocess with limits on bytes,
pages, decompression ratio, and wall clock. HTML bodies are allowlist-sanitised.
All IOCs are rendered defanged everywhere, including in MCP tool output.

**Why:** these documents arrive from outside the organisation and describe
attacks. Treating them as trusted input in a security tool would be the joke that
writes itself.

---

## D-011 — Aggregate (CSV) and detailed (API) inventory are distinct modes
**Date:** 2026-08-20 · **Status:** Accepted (reflects user's stated constraint)

CSV exports carry counts per product+version; API integrations carry per-device
records. `inventory_source.mode` records which, both populate
`inventory_software`, and only `DETAILED` populates `inventory_device`.

**Consequence:** the UI must never promise device identifiers for an aggregate
source. Scan results state their granularity explicitly.

---

## D-012 — Inventory snapshots are immutable
**Date:** 2026-08-20 · **Status:** Accepted

Every sync or upload creates a new `inventory_snapshot`; scans record exactly
which snapshots they ran against.

**Why:** scan results must be reproducible and defensible months later ("what did
we know on the day we closed this advisory?"). It also means a failed sync
degrades to stale data rather than to no data.

**Consequence:** growth is bounded by the 13-month retention policy, with the
latest snapshot per source always kept.

---

## D-013 — PDF is the document of record; email is a summary
**Date:** 2026-08-20 · **Status:** Accepted · **Evidence:** 135-message corpus

Measured across the real corpus: the email body yields 63 distinct CVEs, the PDF
yields **384**. 56 advisories carry CVEs the email never mentions. Five carry
CVEs the PDF omits.

Therefore: extract from **subject ∪ email body ∪ PDF**, with per-CVE provenance
in `advisory_cve.found_in`. PDF parsing is not an enhancement — an email-only
parser would miss the majority of vulnerability data.

**Supersedes** the earlier assumption that the email body was the primary source
and the PDF supplementary.

---

## D-014 — `.msg` is the primary input format
**Date:** 2026-08-20 · **Status:** Accepted · **Evidence:** 135/135 are `.msg`

`extract-msg` parses all 135 with zero errors. `.eml` remains supported but is
the fallback, reversing the earlier assumption.

Filenames are **not** parsed — Outlook sanitises `::` → `_` and strips `/`, so
the filename is a lossy copy of the subject. Subject comes from message
properties.

---

## D-015 — No OCR
**Date:** 2026-08-20 · **Status:** Accepted · **Evidence:** 135/135 text layer

Every PDF in the corpus has an extractable text layer. `OCR_ENABLED` stays as a
config flag with a runtime empty-text detector, but the OCR path is **not built**
in Phase 1. **Answers open question 2.**

**Revisit if:** an empty-text PDF ever appears — the detector will flag it.

---

## D-016 — Section-scoped extraction, never document-wide
**Date:** 2026-08-20 · **Status:** Accepted

The PDF template is fixed (`OVERVIEW`, `TECHNICAL DETAILS`, `RECOMMENDATIONS`,
`REFERENCES`, `PLEASE NOTE`, `ACTION` present in 132–135 of 135). Every extractor
is scoped to its section.

**Why:** a document-wide URL regex returns 216 hits across the corpus, almost all
of them `REFERENCES` citations rather than indicators. Document-wide extraction
would turn every advisory's bibliography into fake IOCs.

Corollary: the repeating page header `Advisory Number: … Published on: …` must be
stripped before extraction, or every match double-counts.

---

## D-017 — Classify on structure, not on the regulator's `Type` field
**Date:** 2026-08-20 · **Status:** Accepted · **Supersedes part of D-008**

The `Type:` field is present 135/135 but reports `Vulnerability` for 128 — including
IoT botnet campaigns, ransomware evolution reports, and quarterly threat-landscape
summaries.

The reliable discriminator is **structural**: the presence of an
`ATTACK CHAIN OVERVIEW` / `CAMPAIGN OVERVIEW` / `ATTACK VECTOR` section, or an
IOC section/sidecar, versus an `AFFECTED PRODUCTS…` section with CVEs. Section
headings are template-driven and therefore far more stable than either keyword
spotting or the regulator's own label.

The regulator's value is kept verbatim in `advisory.source_type_raw` — it is what
they asserted, and an auditor may ask.

---

## D-018 — Two SLA clocks; `ACKNOWLEDGED` is a first-class status
**Date:** 2026-08-20 · **Status:** Accepted · **Answers open question 3**

All 135 emails embed the regulator's SLA table and demand two responses:
acknowledgement, then resolution.

| Priority | Risk | Ack | Resolve |
|---|---|---|---|
| P1 | Critical | 8 h | 24 h |
| P2 | High | 16 h | 48 h |
| P3 | Medium | 72 h | 120 h |
| P4 | Low | 72 h | 120 h |

At the observed mix, **~59% of advisories carry an 8-hour acknowledgement fuse**.
This makes "unacknowledged, by time remaining" the dashboard's primary tile, and
makes bulk-acknowledge the one legitimate bulk operation (acknowledgement is a
receipt, not a judgement — it still requires a comment).

---

## D-019 — Detect regulator data errors; never silently correct them
**Date:** 2026-08-20 · **Status:** Accepted

The corpus contains real data-entry errors: 3/135 advisories where the PDF's
`Advisory Number` disagrees with the subject (`DOH-2026515` vs `DOH2026516`), and
4/134 where email `Risk level` disagrees with PDF `Severity`.

Rules: **trust the subject** for the reference (it is the routing key); **take the
higher severity** (under-triaging a Critical is the more expensive error); write
an `advisory_flag` in both cases and show a badge.

---

## D-020 — Re-issues are linked, never merged
**Date:** 2026-08-20 · **Status:** Accepted

Two distinct duplication modes exist in the corpus. Exact resends under the same
ref (`DOH-2026545` ×2, 19 minutes apart) are caught by content hash. **Re-issues
under a new ref** (`DOH-2026550` → `DOH-2026552`, identical title, 8 hours apart)
are not — different ref, different bytes.

Re-issues ingest as separate advisories, because they *are* separate regulator
notifications with separate SLA clocks. A normalised-title fingerprint within a
14-day window creates a `POSSIBLE_REISSUE` link and a UI banner. Auto-merging
would silently drop a notification the regulator expects a response to.

---

## D-021 — `change_status()` row-locks the advisory; validation failures are HTTP 200
**Date:** 2026-08-21 · **Status:** Accepted

Two implementation choices for the Phase 1d chokepoint, `core.services.
advisories.change_status()`:

1. **Row lock.** The advisory row is fetched with `SELECT ... FOR UPDATE`
   (`Session.get(..., with_for_update=True)`). Two analysts racing to change
   the same advisory from two tabs must serialise, not silently overwrite —
   the second request re-validates against the *post-lock* status and is
   correctly rejected as an illegal transition if the first request already
   moved it somewhere the second's target doesn't reach.
2. **Web-route validation failures return HTTP 200, not 4xx.** A blank
   comment, an illegal transition, or a missing acknowledgement channel all
   re-render the status form with an inline error, at status 200. This is a
   deliberate divergence from the REST API (Phase 1e), which will return
   the correct 4xx for the same conditions. HTMX only swaps response bodies
   on 2xx by default, and the app does not yet configure
   `htmx.config.responseHandling` to change that; re-rendering at 200 was
   simpler than adding global HTMX config for one form. **This does not
   weaken enforcement** — the mandatory-comment and transition-legality
   rules are enforced in `core`, not the HTTP layer; the status code only
   affects how the browser reacts to a rejection it already received.

---

## D-022 — Session-user scopes are derived from role, not granted unconditionally
**Date:** 2026-08-21 · **Status:** Accepted

Building the REST API's first scope-gated route (`POST
/advisories/{id}/status`, requiring `advisories:write`) surfaced a real gap:
`Principal.require_scope()` returned immediately for any `ActorKind.USER`
without checking role, because the original assumption — "a logged-in user's
role implies scopes" — was never actually encoded. A VIEWER session user
would have passed every scope check.

Fixed with `core.security.tokens.SCOPE_MIN_ROLE: dict[str, Role]`, a static
mapping from each scope to the minimum role that grants it, matching
`docs/architecture.md` §6's role table exactly (`advisories:read` →
`VIEWER`, `advisories:write` → `ANALYST`, etc.). `require_scope()` now
translates a session user's role through this table instead of
short-circuiting. API tokens are unaffected — they already carried explicit
scopes and were checked correctly.

Why a static mapping instead of, say, giving `Role` its own `scopes`
property: the API/MCP scope space and the UI's role space are deliberately
separate concepts (D-003 keeps auth pluggable), and a mapping table makes
the translation between them a single, auditable place rather than spread
across both enums.

---

## D-023 — Every migration's `downgrade()` must explicitly drop its native enum types
**Date:** 2026-08-21 · **Status:** Accepted

Alembic's `op.drop_table()` removes the columns that use a PostgreSQL native
`ENUM` type but leaves the type itself in the database. Running the Phase 2
migration's `downgrade()` then `upgrade()` again collided on `CREATE TYPE
... already exists` — a real bug, not a hypothetical one, caught only by
actually running a full down/up cycle rather than inspecting the diff.

The same bug was latent in the **original Phase 0 migration** too, for all
14 of its enum types — it had simply never been exercised, because no prior
verification ran a full `downgrade base` / `upgrade head` cycle (only
targeted `downgrade -1` on a migration that didn't touch enums). Both
migrations were fixed by appending an explicit `DROP TYPE IF EXISTS ...` loop
at the end of `downgrade()`, after all `drop_table()` calls. Verified with two
full down/up/down/up cycles against the disposable test database (never
against the dev database, which holds real ingested corpus data and would
fail on the *separate*, expected `f9d471469add` CVSS-column-width downgrade
issue — narrowing a column back over data that no longer fits is a correct
failure, not a bug).

**Going forward: every future migration that adds a native enum column must
add the matching `DROP TYPE IF EXISTS` calls to its own `downgrade()`.**
Alembic's autogenerate will not do this for you.

---

## D-024 — A failed sync still commits its own failure record
**Date:** 2026-08-22 · **Status:** Accepted

`core.services.inventory.sync_source()` writes the failure state
(`source.last_sync_status = ERROR`, `last_sync_error`, an audit log entry)
via `db.flush()` *before* re-raising `ApiAdapterError` to its caller — by
design, so the caller can still choose to roll everything back if it wants
to. The API and web routes, and the worker's scheduled-sync poller, must
each explicitly commit on that exception path rather than letting it
propagate uncaught, or the one thing an operator needs after a failed sync
— *why* it failed — silently vanishes when the session closes.

This was a real bug, not a hypothetical one: both the REST route and the
web route originally let the exception propagate straight through. Fixed
in both places; the worker poller was written correctly from the start by
opening one `session_scope()` per source and catching `ApiAdapterError`
inside it, so `session_scope()`'s own commit-on-clean-exit covers the case
without special handling. Any future caller of `sync_source()` needs the
same discipline: catch `ApiAdapterError`, commit, then handle the failure
however that layer needs to.

---

## D-025 — Desktop Central's adapter is unverified against a live instance
**Date:** 2026-08-22 · **Status:** Accepted, revisit before production use

The Azure ARM and MS Graph adapters (Phase 2c) are stable, versioned,
publicly documented Microsoft APIs — implemented with high confidence and
tested against the documented request/response contract via
`httpx.MockTransport`. Desktop Central has no equivalent: its REST API
shape varies across on-prem versions and the newer Endpoint Central Cloud
product, and no sandbox was available during development to validate
against, unlike NVD in Phase 1b, which *was* checked against the live API
before being called done.

The adapter (`inventory/adapters/desktop_central.py`) is built from
ManageEngine's commonly documented REST API conventions
(`/api/1.4/inventory/computers`, `authtoken` query auth) as a
reviewed-but-unverified starting point, stated as such in its module
docstring rather than presented with the same confidence as the other two.
**Before relying on it against a real deployment, verify the endpoint
paths and field names against that deployment's actual API responses** —
treat every field mapping in that file as evidence, not truth, per
CLAUDE.md §2.2.

---

## D-026 — Version-component magnitude is bounded to int32; implausible values are stored as `None`

**Date:** 2026-08-22 · **Status:** Accepted

`inventory_software.version_parts` is a Postgres `integer[]` column
(32-bit). A real row in the user-supplied `Inventory/InvSWSummary.csv`
export (an "Asure ID" entry) carries a corrupted, 195-digit version string.
`normalise_version()`'s digit-run extraction had no upper bound on the
magnitude of an extracted component, so this genuinely happened only when
running real data through the pipeline — no synthetic test had a reason to
try a 195-digit version.

`normalise_version()` now rejects the whole value (`(None, None)`) if any
extracted component exceeds int32 max (`2_147_483_647`) — no real version
component is anywhere near this large, so treating an implausible one as
unparseable is honest, per CLAUDE.md §2.2, not a truncation or a guess.
Silently clamping or truncating the number would have stored a wrong value
that looked plausible.

---

## D-027 — `inventory` vendor/product columns widened to `Text`, matching the design doc the code had always disagreed with

**Date:** 2026-08-22 · **Status:** Accepted

A second real row from the same export — a Microsoft-Store "app name" that
is actually a 245-character conference-description string, with a vendor
value of `"Google\Chrome"` — overflowed `inventory_software.vendor`/
`.product`, which the Phase 2a SQLAlchemy models implemented as
`String(200)`. Checking `docs/data-model.md` found it had **always**
specified `text` (unbounded) for these columns — the code had silently
disagreed with the design doc since Phase 2a, and nothing had exercised a
value long enough to surface it until this real, dirty CSV row.

The same deviation existed on 4 tables, 9 columns total:
`InventorySoftware.vendor`/`.product`, `InventoryDeviceSoftware.vendor`/
`.product`, `VendorAlias.alias`/`.canonical_vendor`/`.canonical_product`,
`ScanMatch.vendor`/`.product`. All 9 widened to `Text` in one migration
(`c4ccff4d5c82`), matching the doc — per CLAUDE.md §2.1, "if a doc and the
code disagree, fix both so they agree." `InventorySource.name` was checked
and correctly left as `String(200)`: the doc bounds it too, and nothing in
this bug involved it.

This is the same class of bug, with the same fix, as the
`advisory_cve.cvss_v3_vector`/`cvss_v4_vector` overflow found against the
live NVD API in Phase 1b — real-world data is consistently wider than a
design guess, and the project's "verify against real data" discipline is
what keeps catching it before production does.

---

## D-028 — `scan_history()` orders by `started_at`, not `created_at`

**Date:** 2026-08-22 · **Status:** Accepted

`ScanRun.created_at` uses `server_default=func.now()` — Postgres's `now()`
is **transaction-scoped**: every row inserted within one transaction gets
the identical timestamp. Two scans triggered back-to-back (the same request
re-running a scan, or two calls in one test) landed in the same
transaction and so got the same `created_at`, making
`ORDER BY created_at DESC` non-deterministic between them — caught
immediately by a genuinely flaky-looking test assertion, not by inspection.

`ScanRun.started_at` is set from `core.models.base.utcnow()`
(`datetime.now(UTC)`, Python-side) inside `run_scan()`, called fresh on
each invocation, so it actually distinguishes two runs in the same
transaction. `scan_history()` orders by `started_at DESC` instead.

This is a general hazard, not specific to scans: any table relying on
`created_at`'s `server_default=func.now()` for ordering is at risk of the
same non-determinism whenever two rows can be written in one transaction —
worth checking for elsewhere in `core/` if a similar "recently added items,
newest first" query is ever built without noticing this.

---

## D-029 — `Inbox.claim()` falls back to a cross-device claim when `inbox` and `processing` aren't on the same filesystem

**Date:** 2026-08-22 · **Status:** Accepted

Found live in the `ah-test` environment, not by inspection: after wiring up
`INBOX_HOST_PATH` (a compose-level option to bind-mount `/data/inbox` to a
real host folder — see docs/operations.md) and dropping the real 135-message
corpus into it, the worker sat for 12+ minutes and multiple 30-second poll
cycles doing nothing — no files claimed, none archived, nothing logged.

Root cause: `Inbox.claim()` used a plain `os.rename(path, target)` to
atomically move a file from `inbox/` into `processing/`, which only works
when both are on the same filesystem. With `INBOX_HOST_PATH` set, `inbox/`
is a host bind mount while `processing/` stays an internal Docker volume —
different filesystems — so every rename raised `OSError` (`errno.EXDEV`,
"Invalid cross-device link"). `claim()`'s `except (FileNotFoundError,
OSError): return None` treated that identically to "another worker already
claimed this file," so `claim_batch()` silently yielded nothing, forever,
with no error ever logged (the exception never reached `process_inbox()`'s
outer handler — it was swallowed one level down).

Fixed with a same-filesystem-first, cross-device-fallback claim: on
`EXDEV`, rename the file within `inbox/` itself into a hidden per-worker
staging directory (`inbox/.claiming/<worker_id>/`) — still atomic, still
correctly loses the race if another worker got there first — then copy the
now-exclusively-owned file across the filesystem boundary into
`processing/`. `recover_orphans()` was extended to sweep the staging
directory too, so a crash between those two steps is still recovered on
restart, not silently lost.

This was only exercised because a real host folder with real files was
mounted and watched end-to-end, not because of a design review — the same
"verify against real data/real deployment shape" pattern that has found
every other production bug this project, from the NVD CVSS-vector overflow
(Phase 1b) through the CSV int32/varchar overflows (D-026/D-027).

---

## D-030 — VirusTotal IOC checks are analyst-triggered per indicator, never an automatic sweep

**Date:** 2026-08-22 · **Status:** Accepted

Unlike NVD enrichment (Phase 1b), VirusTotal checks are never run
automatically against every IOC as advisories are ingested. VirusTotal's
public-tier API is rate-limited to 4 requests/minute and 500/day — the real
corpus alone has 227 IOCs, so an automatic sweep would exhaust a day's
quota in under a minute and provide no benefit nobody asked for (unlike
NVD's CVE data, which every advisory genuinely needs to assess severity,
an IOC's VT reputation is only useful when an analyst is actively
investigating that specific indicator).

Instead: a "Check on VirusTotal" action per indicator, triggered on
click, with the result cached — globally, by `(ioc_type, value)`, not per
`advisory_ioc` row, since the same indicator (a shared campaign IP, a
reused C2 domain) often appears across multiple advisories and should
answer the same way for all of them. See `core.models.advisory.VtLookup`.

**No SSRF review was needed for this integration**, unlike the Phase 2c
inventory API adapters: the destination host is always the fixed, trusted
`www.virustotal.com` — admins never configure it, and only the IOC value
itself (untrusted content parsed from a regulator email) travels as a
query parameter for VT's own database lookup. We never fetch or resolve
the indicator ourselves.

**The raw IOC value never crosses any API boundary for this feature.**
`POST /iocs/{ioc_id}/check-vt` takes an id, not a value, and `VtLookupOut`
has no `value` field — the same defanging discipline `IocOut` already
follows (CLAUDE.md §2.3). The one place a value legitimately appears is
inside `permalink` — VirusTotal's own report URL, a trusted domain, safe
to render as a real clickable link, unlike the indicator itself.

---

## D-031 — Admin panel covers NVD and VirusTotal only, not inventory API integrations

**Date:** 2026-08-22 · **Status:** Accepted

A new `/admin` page lets an ADMIN configure NVD and VirusTotal API keys
through the GUI instead of only via `NVD_API_KEY`/`VT_API_KEY` env vars and
a container restart — asked for as "GUI configuration for all API
integrations." Deliberately scoped to just these two, confirmed with the
user before building: Desktop Central, Azure ARM, and MS Graph credentials
already have full GUI management under the Inventory tab (source CRUD,
per-source credentials, "Test connection" — Phase 2a/2c), and folding that
already-working functionality into a differently-shaped "Admin" page would
have been a reorganization of working code, not new capability.

**Reuses `integration_credential`/`core.security.crypto` as-is** — the same
Fernet-encrypted, write-only credential storage the inventory sources
already use. `SystemIntegration` is a new, separate table (at most one row
per `SystemIntegrationKind`) rather than repurposing `InventorySource`:
NVD/VT are global singletons, not a user-creatable list of sources, and
giving them a `kind`/`mode`/`schedule_cron` shape built for a different
concept would have been a worse fit than a new, simpler table.

**Resolution precedence, resolved fresh on every call, no restart needed**:
an admin-panel key beats the env var; an admin-panel row with
`enabled = False` beats the env var too (a deliberate "actually turn it
off" affordance, not just "no key set"); no row at all falls back to the
original env-var-only behavior. Every existing env-var-only deployment
keeps working with zero configuration — see
`core.services.system_integrations.resolve_credential()`'s docstring for
the exact rule table. `core.services.enrichment.enrich_pending()` and
`core.services.vt_lookup.check_ioc()` both now call it instead of reading
`settings.nvd_*`/`settings.vt_*` directly; the worker's enrichment poller
had its own `if settings.nvd_enabled:` gate removed for the same reason —
gating there too would make an admin-panel "enable" silently ineffective
until the worker process restarted.

---

## D-032 — Text-derived version ranges are matched, but capped at `POSSIBLE` and never attributed to a specific CVE

**Date:** 2026-08-22 · **Status:** Accepted

Phase 2d's original design deliberately did not match
`AdvisoryProduct.version_expression` at all — the column had no structured
range to compare against, and nothing in `ingest/` populated `parsed_range`
(confirmed by grep at the time). Added on request: parse the affected/fixed
version text, and use it in scans.

**The parser (`ingest/version_range.py`) is deliberately conservative.**
Measured against the real 135-message corpus: only 28% of rows with a
`version_expression` (35 of 124) parse into a clean, structured range. The
other 72% is genuinely ambiguous real-world text — semicolon-separated
multi-range lists, comma-separated discrete version lists, pure prose,
build-qualified strings — and the parser returns `None` for all of it
rather than guessing. This is the same "evidence, not truth" discipline
CLAUDE.md §2.2 already applies everywhere else in this project; a
half-parsed, wrong range would be worse than no range at all.

**Two real bugs in the parser were caught by its own test suite before
this shipped** (not by later inspection): (1) a "Versions X - Y" pattern
with a leading word failed the original "must be nearly the whole clause"
heuristic, since the word itself ate into the length budget — fixed by
adding a `versions?/builds?/releases?`-anchored pattern, mirroring the
already-proven anchor `ingest/patterns.py`'s prose-extraction regex uses.
(2) A string with **two** separate comparator clauses for two product
variants (`"< 7.5.3 (v7), < 8.1.7.1 (v8)"`) was silently resolved to the
first clause only — fixed by counting comparator matches and rejecting the
whole string when more than one is found, rather than picking a winner.

**Matched specs are graded distinctly from NVD CPE specs, not merged into
the same tiers.** `AffectedSpec.text_derived = True` specs are always
capped at `POSSIBLE` confidence in `inventory.matcher.match_candidates()`,
regardless of how clean the version comparison itself was — both the
version range *and* the vendor/product spelling come from a regulator's
free text, not NVD's canonical, alias-table-backed naming, so even a clean
version match is one layer less trustworthy than the NVD path.
`AffectedSpec.cve_id` is `None` for every text-derived spec: an
`AdvisoryProduct` claim has no column tying it to one specific CVE within
a (possibly multi-CVE) advisory, and attributing it to "the first CVE
listed" would be a false precision `scan_match.cve_id`'s existing
`nullable=True` (with a "Null for non-CVE product matches" comment,
present since Phase 2a) had already anticipated.

---

## D-033 — `AdvisoryProduct.parsed_range` needs `none_as_null=True`; a Python `None` was being stored as JSON `null`, not SQL `NULL`

**Date:** 2026-08-22 · **Status:** Accepted

Found live, not by unit tests: after backfilling `parsed_range` on the real
`ah-test` corpus via `reparse`, a direct SQL inspection
(`SELECT count(*) WHERE parsed_range IS NOT NULL`) returned **253** — every
single `AdvisoryProduct` row, including the ~86% that never got a range at
all. `SELECT parsed_range FROM advisory_product LIMIT 5` explained why: a
row the parser had honestly given up on held the literal JSON value
`null` (`'null'::jsonb`), not a true SQL `NULL`.

Root cause: SQLAlchemy's `JSONB` type, by default, serialises a Python
`None` to the JSON literal `null` on write — a well-known pitfall, not
specific to this column. `none_as_null=True` is required to make a `None`
assignment produce a true SQL `NULL` instead. Every unit test for this
feature read the value back through the ORM (`row.parsed_range is None`),
which deserialises JSON `null` back to Python `None` and so never surfaced
the discrepancy — only a SQL-level query on the real corpus did.

Fixed the column definition (`JSONB(none_as_null=True)`) and added a data
migration (`2d99ec3309e7`) to convert every already-stored JSON `null`
literal to a true SQL `NULL` — a strict correctness fix, not a
behavioural change, so its `downgrade()` is deliberately a no-op rather
than restoring the bug.

**Worth checking for elsewhere**: any other nullable `JSONB`/`JSON`
column in this codebase that's ever assigned `None` in Python
(`inventory_source.config`, `advisory_flag.detail`, etc.) may have the
same latent gap if a SQL-level `IS NULL`/`IS NOT NULL` filter is ever
written against it — none currently is, which is exactly why this stayed
hidden until a real corpus and a real query surfaced it.

---

## D-034 — IOC remediation status: a nullable override, not a synced copy; bulk VirusTotal checks are queued through a Redis-backed rate limiter, never called synchronously

**Date:** 2026-08-23 · **Status:** Accepted

**New feature, not on the roadmap** — added on request: an "Affected
Software" tab (estate-wide, one row per product match from each
advisory's most recent completed scan) and an "IOC" tab (every indicator
across every advisory, with a remediation status and a multi-select bulk
VirusTotal check).

**IOC status defaults to tracking the advisory, but is overridable per
indicator — implemented as a nullable column, not a synced copy.**
`AdvisoryIoc.remediation_status` is `None` unless an analyst has
explicitly set it; the *effective* status an analyst sees
(`core.services.iocs.effective_status()`) is that override, or, when
unset, derived on read from the parent advisory's own `AdvisoryStatus` via
a fixed `ADVISORY_STATUS_TO_IOC_STATUS` mapping. This is the same
"evidence over duplicated state" discipline the rest of this project
already follows (CLAUDE.md §2.2): storing a synced copy would drift the
moment the advisory's status changed and nothing re-swept every IOC row to
match. Because both the IOC tab and the advisory detail page's IOC table
read the same column through the same function, a status set independently
in one place is visible in the other with no extra wiring.

**The status set is four values, not three** — DUE / BLOCKED / IN_PROGRESS
/ RESOLVED. The user's original ask named only "due, blocked, in
progress"; asked directly whether a closed/remediated advisory's IOCs
needed a distinct terminal state or should just stay on whichever of the
three applied last, the user confirmed adding `RESOLVED`. Terminal
`AdvisoryStatus` values (`REMEDIATED`, `RISK_ACCEPTED`, `NOT_APPLICABLE`,
`CLOSED`) all map to it; `AWAITING_VENDOR` maps to `BLOCKED`; every other
non-terminal status maps to `DUE` or `IN_PROGRESS`.

**Bulk VirusTotal checks are queued, never called synchronously from the
web request** — the user was explicit about this: a free-tier VT API key
is rate-limited (4 requests/minute; `enrich/virustotal.py` conservatively
caps at 3/60s), and the real corpus alone has 227 IOCs, so a naive
multi-select-and-loop would either blow the rate limit or block a web
request for minutes. `core.services.vt_lookup.enqueue_bulk_check()`
enqueues one RQ job per selected IOC on a new `vt_check` queue and returns
immediately.

**The rate limiter has to live in Redis, not in a Python object.** RQ's
default worker forks a fresh process per job, so an in-memory limiter
(like `enrich.nvd.RateLimiter`, reused by the *interactive* single-check
path) would reset on every job and throttle nothing across a batch.
`worker.jobs._acquire_vt_slot()` instead implements a sliding window as a
Redis sorted set — each acquired slot is a member scored by acquisition
time, pruned by `ZREMRANGEBYSCORE` and counted by `ZCARD` before a new one
is granted — and blocks (polling every 2s) until a slot frees up. Because
RQ's default worker processes one queue's jobs strictly serially, one
job's internal block naturally paces every job queued after it; a whole
bulk selection drains at the same rate a single interactive click already
respects, with no separate scheduler needed. Verified live against the
real `ah-test` deployment: a 3-IOC bulk selection queued through the web
UI ran to completion via the worker container, each job completing
roughly a second apart, and all three results (real VT lookups — VT is
configured on that deployment) were visible back on the IOC tab
afterward.

**"Refresh all" for Affected Software re-scans against each advisory's
inventory sources' *current* latest snapshots, not whatever snapshot the
prior scan used.** `core.services.scan.refresh_all_scans()` only revisits
advisories that have been scanned at least once before (i.e. everything
`list_affected_software()` already shows a row for) — an advisory that has
never been scanned is not swept in by "Refresh all"; that's still a
deliberate, explicit "Scan inventory" action on the advisory itself
(Phase 2e). Each advisory's re-scan commits independently, mirroring the
per-source commit discipline `sync_source()`'s scheduled poller already
established (Phase 2c) — one advisory's failure must not roll back or
block any other advisory's already-successful refresh.

**Two Alembic/enum quirks found, the second distinct from the first**:
(1) already known from Phase 2a — `op.drop_table()`/`op.drop_column()`
never drops the underlying Postgres native enum type, so this migration's
`downgrade()` includes the explicit `DROP TYPE IF EXISTS
iocremediationstatus_enum` D-023 requires. (2) **New this session**:
`op.add_column()` with a plain `sa.Enum(...)` does *not* implicitly
`CREATE TYPE` the way `op.create_table()` does — confirmed directly
against the dev database, which raised `UndefinedObject: type
"iocremediationstatus_enum" does not exist` on the first attempt. Fixed by
explicitly creating the type (`postgresql.ENUM(...).create(checkfirst=True)`)
before the `add_column()` call, and referencing it there with
`create_type=False` so it isn't created twice.

**Verified**: 570 tests passing project-wide (14 new for
`core.services.iocs` — effective-status derivation for every
`AdvisoryStatus`, override precedence, listing/filtering/pagination,
including that a status filter matches on the *effective* status, not just
a stored override; 4 for `enqueue_bulk_check()`'s partitioning of
supported/unsupported/unknown IOCs; extended `test_scan_service.py` for
`list_affected_software()` and `refresh_all_scans()`, including that a
refresh uses currently-active snapshots rather than a scan's original
ones, and that one advisory's scan failure doesn't block another's).
`ruff` and `mypy --strict` clean. Manually verified end-to-end against the
real `ah-test` deployment: both new nav tabs render with the real 227-IOC/
135-advisory corpus, setting a per-IOC status override on the IOC tab
correctly appeared as "overridden" on the same advisory's detail page, and
the bulk VT-check flow (select three, queue, worker drains them,
real results land back in the table) ran end-to-end against a real
worker container and a real configured VirusTotal key.

## D-035 — HTTPS is a compose overlay with an nginx proxy; certificates are installed per deployment, never generated or stored in the repo

**Date:** 2026-09-29 · **Status:** Superseded by D-041 (bundled HTTPS proxy removed, 2026-10-04)

**Requested**: an HTTPS option, *without* generating any certificates as
part of the change, plus a script to use at deployment time.

**Decision**: TLS terminates in an `nginx:1.27-alpine` `proxy` service
defined in a separate overlay, `docker-compose.https.yml`, layered on
`docker-compose.yml`. `scripts/https-setup.sh` installs and validates a
certificate into a git-ignored `certs/` directory and writes
`COMPOSE_FILE=docker-compose.yml:docker-compose.https.yml` into `.env`, so
every later `docker compose …` command uses the overlay without extra
flags. Walkthrough in docs/operations.md §7.

**Alternatives rejected**:

| Option | Why not |
|---|---|
| TLS in uvicorn (`--ssl-certfile`) | No HTTP→HTTPS redirect, no graceful cert reload, cipher/HSTS policy would live in Python code |
| Caddy with automatic ACME | Most on-prem estates here issue from an internal CA and the host may have no inbound internet — ACME is the wrong default. Caddy can still do manual certs, but nginx is what the ops team is likelier to already know |
| Baking TLS into `docker-compose.yml` | Would break plain-HTTP local development and force every dev to hold a cert |
| Generating a cert in the image / at startup | Explicitly not wanted; also a self-signed cert silently in production is worse than a loud failure |

**Consequences**:
- With the overlay, `app`'s port is **not published** (`ports: !reset []`),
  so plain HTTP can't bypass the proxy. That's also what makes
  `FORWARDED_ALLOW_IPS=*` safe — uvicorn then records the real client IP
  (from `X-Forwarded-For`) on sessions and the audit log instead of the
  proxy's.
- The script refuses a passphrase-protected key, a key that doesn't match
  the certificate, an expired certificate, or one that doesn't cover
  `SERVER_NAME`, *before* touching the installed pair.
- Self-signed mode exists for bridging only and sets `HSTS_MAX_AGE=0`: a
  browser that has cached HSTS won't let a user click past a certificate
  warning.
- `!reset` needs Docker Compose ≥ 2.24.

**Verified**: overlay renders with `docker compose config` (proxy added,
`app` ports removed, env applied); the nginx template renders through the
image's own envsubst step with only `SERVER_NAME`/`HSTS_MAX_AGE` substituted
and `$host` etc. preserved, and `nginx -t` parses it up to loading the
certificate — which is absent, since none were generated; every script
error path (missing args/files, non-PEM input, unknown option, no
certificate installed) and the `.env` edit helpers were exercised against a
scratch `.env`. **Not yet exercised: a real TLS handshake** — it needs a
certificate, which was deliberately not created.

## D-036 — UI themed to Mediclinic's colour language, light and dark, via CSS `light-dark()`

**Date:** 2026-09-29 · **Status:** Accepted

**Requested**: a dark and a light theme following Mediclinic's design and
colour language from their website.

**Decision**: colours were read directly from mediclinic.ae's production
stylesheet (by frequency and by what they are applied to), not
approximated: `#0094D4` (links/brand, 211 uses), `#534C46` (body and heading
text), `#0A235E` / `#003F72` (navy / hover blue), `#72665B` (nav, placeholders),
and the stone neutrals `#F7F6F5`, `#E2DFDB`, `#D0CAC6`; font `Metropolis,
Arial`. Token table in docs/architecture.md §3.3.2.

- **`#0094D4` is not used for text.** At 3.4:1 on white it fails WCAG AA;
  Mediclinic's own darker `#0072A3` (5.3:1, also in their stylesheet) takes
  links and buttons. `#0094D4` keeps the brand identity on non-text
  accents.
- **Dark theme is navy-based**, derived from `#0A235E`, rather than
  neutral grey — it keeps the brand recognisable and suits a SOC screen.
  Buttons flip to `#0094D4` with navy text (5.2:1), since white on it fails.
- **Status colours stay semantic**, not branded (see §3.3.2).
- **Sub-brand colours** in the same stylesheet (ER24 reds `#DF131B` /
  `#ED3237`, MHR lime `#BED747`, magenta `#E61772`) were not adopted as
  theme colours; `#DF131B` is used only for error banners, where red is
  expected anyway (4.95:1 on white).
- **`light-dark()` + `color-scheme`** over duplicated `@media` and
  `[data-theme]` blocks: one value per token, OS preference respected with
  no JavaScript, and native controls/scrollbars follow the theme. The
  header toggle only sets `data-theme` on `<html>`. Supported in every
  current evergreen browser (2024+); an older browser would ignore the
  declarations and fall back to its defaults.
- Metropolis is not bundled or loaded from a CDN (no new outbound
  dependency); clients without it get Arial, as mediclinic.ae itself falls
  back to.

**Verified**: rendered the real tracker, IOC tab, an advisory detail page
and the sign-in page against the dev corpus in headless Chromium in both
themes. One pre-existing contrast defect surfaced and was fixed — the
tracker's "No comments yet" placeholder was styled with the *border* colour
(≈1.3:1, unreadable); it now uses the inherited muted text colour.

## D-037 — Images are built by CI and pulled from Docker Hub; two images, namespace from config

**Date:** 2026-09-29 · **Status:** Accepted, amended by D-041 (the `advisory-hub-proxy` image no longer exists — one image only)

**Requested**: CI builds the images and pushes them to Docker Hub with
appropriate names; compose pulls from Docker Hub.

**Decision**:

| Image | Why this split |
|---|---|
| `<namespace>/advisory-hub` | `app` and `worker` are the same code with a different command. Two identical images would double push time and invite version skew between web and worker |
| `<namespace>/advisory-hub-proxy` | nginx with the site template baked in, so a host needs no source checkout. Supersedes D-035's bind-mount of the template; certificates are still mounted, never baked |

- **Namespace is configuration, not hard-coded** (`IMAGE_NAMESPACE` for
  compose, `DOCKERHUB_NAMESPACE`/`DOCKERHUB_USERNAME` for CI).
- **Unset namespace resolves to `localhost/…`, deliberately.** Docker treats
  `localhost` as a registry host, so a production host that forgot to set
  it fails to pull instead of falling back to some public default — a
  default like `advisoryhub/…` would pull from whoever registered that
  namespace, which is a supply-chain hole.
- **Base compose has `image:` only; the dev override adds `build:` with
  `pull_policy: build`.** With both in the base, `docker compose up` would
  build rather than pull on a host where the image isn't present.
- **Publishing is gated on `lint` + `test`** and happens only on pushes to
  `main` and `v*` tags. PRs still build both images (no push), keeping the
  old "image still builds" check.
- Tags: `latest`/`main`/`sha-<commit>` from `main`; `X.Y.Z`/`X.Y` from tags.
  Production should pin `IMAGE_TAG`; `latest` is a convenience.
- Multi-arch (amd64 + arm64) so Apple-silicon test hosts can pull the same
  image, at the cost of a slower (QEMU) arm64 build in CI. SBOM and
  provenance attestations are attached.

**Verified**: `actionlint` clean; `docker compose config` resolves correctly
for development (builds `localhost/advisory-hub`, `pull_policy: build`),
production (`acme/advisory-hub:1.4.0`, no build), and production + HTTPS
(`acme/advisory-hub-proxy`, only the certificate directory mounted);
`make images` builds both; the proxy image renders its baked-in template
(`SERVER_NAME` substituted, HSTS default applied, `$host` preserved); the
dev stack builds and boots from the override. **Not verified**: an actual
CI run and push — needs the Docker Hub secrets set on the GitHub repo.

## D-038 — A separate, self-contained production compose file

**Date:** 2026-09-29 · **Status:** Accepted, amended by D-041 (no bundled proxy; `app` is the published service)

**Requested**: a production-ready Docker Compose file.

**Decision**: `docker-compose.prod.yml`, used **on its own** (not layered on
`docker-compose.yml`), selected through `COMPOSE_FILE` in the production
`.env`. Hardening and topology are tabled in docs/deployment.md §1.

**Why a separate file rather than another overlay**: overlays can add and
`!reset` keys, but production differs from the base in almost every
service — required secrets instead of dev defaults, no published app port,
split networks, read-only filesystems, a migrate container, resource
limits. As an overlay, the effective config would only be knowable by
running `docker compose config`; as one file, the production shape is what
you read. The cost — some duplication with the base file — is accepted.

**Choices within it**:

| Choice | Reason |
|---|---|
| `IMAGE_TAG` required, no `latest` default | Every host runs a known, reproducible build |
| One-shot `migrate` service | Migrations happen exactly once per `up`, before app/worker, instead of by hand |
| Upgrades run `docker compose run --rm migrate` **before** `up -d` | Tested: if `migrate` fails during a plain `up -d`, Compose has already removed the old app/worker and doesn't start the new ones — an outage. Migrating first leaves the old version serving |
| `backend` network `internal: true` | Postgres/Redis never need the internet; verified they can't reach it |
| app on a non-internal network | Interactive VirusTotal checks and "Test connection" call out from the request |
| `read_only` + `/tmp` tmpfs + `cap_drop: ALL` on app/worker/migrate | They parse hostile input. Verified a real advisory (PDF extraction in the sandboxed subprocess) ingests under these |
| Proxy keeps default capabilities | nginx's master binds 80/443 then drops privileges itself; not narrowed without a certificate to test against |
| Worker healthcheck = `cli check` | The image's HEALTHCHECK probes the web port the worker doesn't serve, so the worker was *never* healthy under the old config |
| `WEB_CONCURRENCY` default 1 | An internal team's load; ~83 MB idle per process measured |
| Redis `--appendonly yes`, `noeviction` | It is the job queue — eviction or loss on restart would drop queued VirusTotal checks |
| `env_file: .env` plus pinned `environment` | Every documented setting reaches the containers, while values that must not vary (paths, `ENVIRONMENT`, `DATABASE_URL`) can't be overridden from `.env` |

**Found while building it**: the base `docker-compose.yml` had the same
passthrough gap — only a hand-picked subset of variables reached the
containers, so `VT_API_KEY`, `PDF_*`, `CSV_*`, the poll intervals and
`FERNET_KEY_PREVIOUS` in `.env` had no effect under Compose. Fixed with the
same `env_file` approach.

## D-039 — SQLAlchemy pinned below 2.1; mypy stub packages are declared dependencies

**Date:** 2026-09-29 · **Status:** Accepted

**What happened**: the first CI run failed `mypy --strict` with 17 errors
that never appeared locally. Reproduced exactly in a clean `python:3.13`
container doing CI's `pip install -e ".[dev]"`:

| Cause | Effect |
|---|---|
| `sqlalchemy>=2.0.36` had no upper bound; a fresh install now resolves **2.1.1** (local venv: 2.0.52) | 2.1 changed how `Select`/`Row` are typed — 16 errors in `core/services/advisories.py` and `iocs.py` |
| `types-defusedxml` was installed in the local venv by hand but never declared | `import-untyped` on `ingest/sidecars.py` |

**Decision**: `sqlalchemy>=2.0.36,<2.1`, and `types-defusedxml` added to the
`dev` extra. Same clean-container run afterwards: SQLAlchemy 2.0.54,
`mypy` clean; 594 tests pass.

**Why pin rather than port to 2.1 now**: the production image installs from
the same `pyproject.toml`, so the unbounded range meant any freshly built
image was *running* on a SQLAlchemy minor the code had never been tested
against — not only failing lint. Moving to 2.1 is worth doing, as its own
change with the typing fixes and a full test run, not as a side effect of
whenever an image happens to be built.

**Still open**: there's no lock file, so every other dependency floats the
same way. A lock (`uv lock` / `pip-compile`) used by CI and the Dockerfile
would make builds reproducible; not done here.

## D-040 — A second, self-contained production compose file for deployments behind an enterprise WAF/reverse proxy

**Date:** 2026-10-01 · **Status:** Accepted, amended by D-041 (now the only production file, renamed `docker-compose.prod.yml`)

**Requested**: a production deployment option without the bundled nginx
proxy, for sites that terminate TLS at an enterprise WAF or reverse proxy
(F5, Citrix ADC, Imperva, Azure Application Gateway, Cloudflare Enterprise,
…) instead.

**Decision**: `docker-compose.prod.no-proxy.yml`, a second self-contained
production file alongside `docker-compose.prod.yml` (same reasoning as
D-038 — production's hardening diverges from the base file in almost every
service, so the shape you read is the shape that runs; the file is a near-
duplicate of `docker-compose.prod.yml` with the `proxy` service removed and
`app` publishing its own port). Two alternatives were rejected:

| Alternative | Rejected because |
|---|---|
| Compose `profiles:` to make `proxy` opt-in on the existing file | Profile-having services are *off* by default unless the profile is activated. Any already-deployed host upgrading `docker-compose.prod.yml` without also setting the new profile variable would silently lose its proxy — and with it, its only published port and its TLS termination — at the next `docker compose up -d`. A breaking change with no loud failure is worse than the duplication an overlay avoids |
| An overlay on top of `docker-compose.prod.yml` | Compose has no merge operation to *delete* a service, only to add/replace/`!reset` keys on one that exists in both files. Removing `proxy` entirely isn't expressible as an overlay |

**The one thing that genuinely changes, not just "proxy present or not"**:
trust in `X-Forwarded-For`/`X-Forwarded-Proto`. The bundled proxy's
`FORWARDED_ALLOW_IPS=*` is safe *only* because `app` has no published port —
the proxy container is the one and only thing that can ever connect to it.
The no-proxy file publishes `app`'s port directly, so that assumption no
longer holds: anyone who can reach the port could forge those headers,
corrupting the audit log's client IP or impersonating an HTTPS connection
over plain HTTP. `docker-compose.prod.no-proxy.yml` therefore requires
**`TRUSTED_PROXY_IPS`** — a required compose variable, no `*` default,
naming the WAF/proxy's own literal address(es) — and documents that the
operator's firewall, not this stack, must keep the port unreachable from
anywhere else. This is the one part of the bundled-proxy design that cannot
simply be deleted; it has to be replaced with an explicit trust boundary.

**Deliberately out of scope**: a TLS listener of any kind in the no-proxy
file — `app` only ever speaks plain HTTP; `scripts/https-setup.sh` is
guarded to refuse to run against it (there is nothing in this file for it to
configure). HSTS, redirects, and the certificate itself are the WAF/proxy's
job, not this stack's — duplicating them here would just be a second place
for them to drift out of sync with whatever the WAF actually does.

**Verified**: `docker compose config` resolves cleanly against both files
with synthetic secrets; the new required `TRUSTED_PROXY_IPS` variable
correctly fails fast (`docker compose config`, no value set) with a message
naming where to set it, the same pattern every other required production
secret already uses; confirmed the existing bundled-proxy file's behaviour
(`disable` still refused, `check`/`enable` unaffected) is unchanged by the
new guard in `scripts/https-setup.sh`, and that the guard itself fires for
the no-proxy file's `.env` while leaving `--help` usable regardless of
`COMPOSE_FILE`. Not deployed against a real WAF — no enterprise WAF/reverse
proxy was available to test against; the request/response contract
(forwarded headers, trust boundary) is rechecked against whichever product
is actually used before go-live.

## D-041 — Bundled HTTPS reverse proxy removed; TLS is terminated upstream only

**Date:** 2026-10-04 · **Status:** Accepted · **Supersedes** D-035

**Requested**: "remove the https reverse proxy option altogether", including
its documentation.

**Decision**: the stack no longer ships any TLS component. Production is
the WAF-fronted design from D-040, and that is now the only production
file.

| Removed | Was |
|---|---|
| `docker/nginx/` (Dockerfile + site template) | The `advisory-hub-proxy` image (D-035, D-037) |
| `docker-compose.https.yml` | HTTPS overlay for the base stack |
| `scripts/https-setup.sh` | Certificate CSR / install / check script |
| `proxy` service in `docker-compose.prod.yml` | TLS-terminating front of the bundled production stack (D-038) |
| CI's `advisory-hub-proxy` build | Second image in the publish job — CI now builds one image |
| `certs/` / `*.key` / `*.csr` in `.gitignore`; `SERVER_NAME`, `HTTP_PORT`, `HTTPS_PORT`, `TLS_CERT_DIR`, `HSTS_MAX_AGE` | Settings only the proxy used |

| Renamed | To |
|---|---|
| `docker-compose.prod.no-proxy.yml` | `docker-compose.prod.yml` |
| `.env.production.no-proxy.example` | `.env.production.example` |

Keeping a `no-proxy` name with no proxy alternative would only invite the
question "where is the other one?".

**What stays, and why it matters more now**: with no bundled proxy, `app`'s
port is always the published service, so D-040's controls are the security
boundary in every deployment — `TRUSTED_PROXY_IPS` required (never `*`),
`SESSION_COOKIE_SECURE` forced on (users must arrive over HTTPS via the
WAF), and the firewall restricting `APP_PORT` to the WAF. All in
deployment.md §1.

**Consequence**: there's no supported way to run HTTPS without an external
TLS terminator. A deployment without one would serve plain HTTP, and
sign-in wouldn't work (the `Secure` cookie isn't sent over HTTP). That's
deliberate — the alternative is session cookies on the wire in clear text.

D-035, D-037, D-038 and D-040 are kept as history, marked superseded or
amended; the progress log in CLAUDE.md likewise records the proxy as it
was.

## D-042 — Manual tracker import: rule-inferred statuses, previewed, forward-only, through `change_status()`

**Date:** 2026-10-04 · **Status:** Accepted

**Requested**: convert the team's multi-sheet spreadsheet tracker into one
CSV, with everything the tool doesn't already parse in the comments; and an
option in the tool to upload it and update advisory statuses accordingly.

**Decision**: `/tracker-import` (ANALYST+) accepts the workbook or the
converted CSV, previews, then applies. Mechanics and the full rule table:
architecture.md §3.3.3.

**Choices, and the alternatives rejected**:

| Choice | Rejected alternative, and why |
|---|---|
| Statuses inferred by an ordered, documented rule table; unrecognised text changes nothing | Asking the user to map 46 free-text phrasings by hand first — slower and no better: the preview shows every inference, and the CSV lets any of them be corrected |
| A preview step that writes nothing | Applying on upload — status history is permanent (append-only audit log), so a bad mapping would be unfixable |
| Walk legal transitions through `change_status()` | Writing the target status directly — bypasses the mandatory comment and audit chokepoint (CLAUDE.md §2.2) |
| Intermediate steps restricted to Triaged / In progress / Remediated | Plain shortest path — tested: it routed NEW → Remediated through **Awaiting vendor** (alphabetical tie-break), recording a vendor wait that never happened |
| Forward-only; the tool wins on disagreement | Tracker wins — would let an old spreadsheet undo work done in the tool |
| Workbook *and* CSV accepted, through one converter | Workbook only (no way to correct an inference) or CSV only (an extra manual step every time) |
| Own `defusedxml` reader (`manual_tracker/xlsx.py`) | openpyxl — a large dependency for parsing an uploaded file; the existing sidecar reader reads only the first sheet and shifts columns at blank cells |

**Assumptions to confirm with the team** — each is one line in
`STATUS_RULES`:

- Auto-patching in place, hashes blocked, and "closed — automation job in
  place" count as **Remediated**.
- "No blocking mechanism available" means **Risk accepted**.
- Partial blocking ("Blocked Hashes, no blocking mechanism for IP and
  Domain") counts as **Remediated**; the caveat stays in the comment.
- "Assessment required" / "Need more information" mean **Triaged**.

**Verified on real data** (a throwaway copy of the dev database, dropped
afterwards): the real workbook's 174 rows read identically to openpyxl,
every field and date. Through the actual web upload, 97 advisories updated
via 135 legal status steps; re-importing changed nothing; re-issued
DOH-2026591 updated on both records. 64 new tests.

## D-043 — All persistent data in `./data/<volume>` host folders, made and owned by a one-shot `init-data` container

**Date:** 2026-10-04 · **Status:** Accepted

**Requested**: every deployment uses local directories for its volumes, at
`./data/{volume_name}`, for easy backup and restore.

**Decision**: every compose file bind-mounts `./data/pgdata`,
`./data/redisdata`, `./data/blobs`, `./data/inbox`, `./data/processing`,
`./data/archive` and `./data/failed`; there are no named volumes left.
`INBOX_HOST_PATH` still overrides the inbox. Backup, restore and migration
steps: operations.md §2 and §4.

| Choice | Why |
|---|---|
| One-shot `init-data` service (app image, root, `CHOWN`/`DAC_OVERRIDE`/`FOWNER` only, no network, read-only) before `migrate`/`app`/`worker` | On Linux, Docker creates a missing bind-mount folder owned by root, and the app runs as uid 10001 — it couldn't write blobs or claim inbox files. Named volumes hid this because they copy the image's folder ownership. Doing it in a container means no manual `chown` step to forget, and it also repairs files a restore copied back as root. Tested on Docker's Linux kernel: root-owned files inside a `0700` folder are reassigned; without `CHOWN` it fails |
| `init-data` leaves `pgdata`/`redisdata` ownership alone | Their images' entrypoints already fix their own folders; touching them would fight that |
| `find … ! -user 10001 -exec chown` rather than `chown -R` | Only touches what's wrong, so a large blob store isn't rewalked-and-rewritten on every start |
| New `.dockerignore` | A development checkout now keeps Postgres's files in `./data/`, which `docker build` would otherwise try to send as build context (and can't read on Linux). It also stops the restricted corpus and real inventory/tracker files being sent to the builder, which was already happening |
| Fixed path `./data`, no `DATA_DIR` setting | As requested; one less thing to configure. The deployment folder's location *is* the data location |

**Migration**: stacks started before this keep their data in named
volumes, and the new files would start with an empty `./data`. The copy
procedure is in operations.md §4. The development checkout's own volumes
were copied this way (2,032 Postgres files: dev database incl. the 135
advisories, plus the test database); the original volumes were kept.

**Found while checking**: the Test-Deployments stack and the development
checkout both use the project name `advisory-hub`, so `up` in either
replaces the other's containers. Documented (`COMPOSE_PROJECT_NAME`,
operations.md §1). It then happened for real (see D-044), so the dev
override now sets `name: advisory-hub-dev`.

## D-044 — Status export in the import format, written daily by the worker, as a restore path

**Date:** 2026-10-04 · **Status:** Accepted

**Requested**: export every advisory's status as CSV; the CSV must be
importable to restore a deployment that has crashed beyond recovery; and a
scheduled job in one of the containers writing such an export daily into a
data folder.

**Decision**: one export (`core.services.status_export`), three triggers:
the tracker page, CLI `status-export`, and a worker thread writing
`./data/exports/status-export-<date>.csv` on `STATUS_EXPORT_CRON` (UTC),
keeping `STATUS_EXPORT_KEEP_DAYS`. It's the tracker-import CSV format, so
`/tracker-import` is the restore tool. Details: architecture.md §3.3.4;
runbooks: operations.md §4.

| Choice | Rejected alternative, and why |
|---|---|
| Same CSV format as the tracker import | A separate format and restore endpoint — two parsers and two rule sets to keep consistent, for one job the import already does safely (preview, forward-only, idempotent, all-or-nothing) |
| Scheduled in the worker's existing poller pattern, on a cron expression | A `cron` daemon in a container — the image has none and runs as non-root. A second "scheduler" container adds a moving part for one job. The worker already runs the inbox/NVD/inventory pollers this way. `croniter` (already a dependency) gives real cron syntax |
| Run when *the file for the latest scheduled time is missing* | Fire at the clock time — a worker down at 02:00 would silently skip the day, and a restart near 02:00 could write twice. Keyed on the file, it catches up on start and writes exactly once; two workers converge on the same file via atomic rename |
| Comment history as one block per advisory, added only where an advisory has no comments | Re-creating each comment as its own row — the importer would author them all anyway, losing the original authors. And always adding the block would append it to every advisory when an export is imported into a healthy deployment |
| Export open to any signed-in user, audit-logged | Admin-only — it's exactly what a viewer can already read in the tracker; logging the bulk export is the meaningful control |

**Bugs in the tracker import found and fixed first** (failing tests
written before the fix):

1. A row with status ACKNOWLEDGED crashed Apply (`change_status()` needs an
   `ack_channel` the CSV couldn't carry), rolling back the whole import.
   Now: optional `ack_channel` column; without it the row is skipped with
   a message.
2. Two rows for one advisory (same number, e.g. re-issues) were both
   planned from the advisory's *original* status, so the second's first
   step was illegal once the first had applied, and Apply crashed. Now
   planned in sequence. The row's `received_date` also picks the right
   record among re-issues.

**Verified on real data**: the real corpus with real statuses (via the
tracker import, plus 3 acknowledgements) was exported. A **brand-new
database** was built and all 135 emails re-ingested. Importing the export
reproduced status, acknowledgement channel and acknowledged flag for all
135 advisories identically (100 updated through 136 legal steps).
Re-importing changed nothing. The worker container wrote the day's file
on start (catch-up), owned by uid 10001, 135 rows.

**Incident while building this**: running `make up` in the development
checkout recreated the Test-Deployments stack's Postgres and Redis
containers (shared project name `advisory-hub`). No data was affected (each
stack's data is in its own `./data`); the deployment's containers were
recreated from its own folder within minutes and verified. Prevented from
now on by `name: advisory-hub-dev` in `docker-compose.override.yml`.

## D-045 — The app can serve HTTPS itself, with a provided or generated self-signed certificate

**Date:** 2026-10-04 · **Status:** Accepted · **Reverses** the "TLS in uvicorn" rejection in D-035 · **Amends** D-040 (`TRUSTED_PROXY_IPS` optional)

**Why**: deployed behind NAT with no proxy, the login page took the
password and reloaded — the session cookie is `Secure`, and browsers only
send it over HTTPS or to `localhost` (which is why the same setup worked on
the developer's machine). Asked: HTTPS without a proxy — a self-signed
certificate generated if none exists, or a provided one, handled by the
application.

**Decision**: `HTTPS_ENABLED=true` makes `python -m advisory_hub.serve` (now
the image's default command) start uvicorn with TLS on the same app port.
`core/security/tls.py` decides the certificate:

| `./data/certs/` holds | Result |
|---|---|
| `server.crt` + `server.key` | Used unmodified, after checks: PEM, key matches, not expired; warnings for ≤30 days left or uncovered `TLS_HOSTNAMES` |
| neither | Self-signed EC P-256, 397 days, SANs = `TLS_HOSTNAMES` + localhost + 127.0.0.1 (IPs as IP SANs); key `0600`, atomic write; reused, renewed ≤30 days before expiry — only certificates it generated itself (marked by subject Organisation) |
| only one | Refuse to start — likely half of a real certificate |

| Choice | Why |
|---|---|
| uvicorn's own TLS, generated with `cryptography` | Asked for no proxy; both are already dependencies — no new package, no OpenSSL CLI in the image |
| Same port, no HTTP→HTTPS redirect listener | A redirect needs a second listener and knowledge of the published port; for an internal tool, "use https://" in the docs is the better trade. D-035's other objections (cipher policy in Python, no graceful reload) are accepted for this deployment shape; the WAF option remains for those who need them |
| Certificate folder mounted into `app` only | The worker never needs the private key |
| Health checks try HTTP, then HTTPS with `-k` | Liveness only; works in both modes, and in the compose files too for images built before this |
| `TRUSTED_PROXY_IPS` now optional, default `127.0.0.1` | With no proxy, requiring it made no sense. The default trusts no external peer — safe; still never `*` |
| Development stays HTTP | The override runs uvicorn `--reload` directly; `http://localhost` already satisfies browsers |

**Verified**: fresh image, scratch stack, `HTTPS_ENABLED=true`, browsed via
the host's **LAN IP** (the failing case): certificate generated with that IP
as a SAN; plain HTTP got no answer; HTTPS health 204; sign-in POST → 303,
`Secure` cookie stored and returned, tracker page shown — no loop. Then a
provided certificate from a stand-in CA: served unchanged, not regenerated.
17 tests (generation, reuse, renewal of own vs. never touching provided,
mismatch, passphrase, expiry, half-present, launcher options).

---

## D-046 — User administration in the web UI: deactivate, never delete; the last admin is protected

**Date:** 2026-10-05 · **Status:** Accepted

**Why**: accounts could only be created with the `create-admin` CLI (always
ADMIN), and roles changed only in the database. Asked: user administration
for admins, with roles editable from that view.

**Decision**: `/admin` → Users (add, change role, deactivate/reactivate,
reset password), all rules in `core.services.users`, each change audited.

| Rule | Because |
|---|---|
| Deactivate instead of delete | Audit log, comments and status history reference the user; deleting would orphan (`SET NULL`) who did what. Deactivation keeps the trail and is reversible |
| An admin can't change their own role or deactivate themselves | One misclick shouldn't lock you out; another admin does it |
| The last active admin can't be demoted or deactivated (checked under a row lock on the active admins) | Otherwise the instance has no one who can manage it, and recovery needs shell access. The lock stops two admins demoting each other at once |
| Role changes don't end sessions; deactivation and password resets do | The role is re-read from the database on every request, so a change applies immediately; a deactivated user or a reset password must not leave a live session behind |
| Passwords ≥ 12 characters | Same as `create-admin` |

**Not done**: self-service password change, forcing a password change at
next sign-in, invitations by email. Users who will move to Entra ID (D-003)
keep the same `user_account` rows.

---

## Open decisions

Tracked in `CLAUDE.md` §5 until resolved. When one is answered, record it here as
a numbered entry.
