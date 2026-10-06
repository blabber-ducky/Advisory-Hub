# Architecture

## 1. Design goals

1. **Never lose the source of truth.** Regulatory advisories are compliance
   artefacts. The original `.eml` and every attachment are stored immutably and
   forever; parsed data is a derived, re-computable view.
2. **One business-logic layer, many front doors.** The UI, the REST API, and the
   MCP server are interchangeable adapters over the same service layer. This is
   what makes the mandatory-comment rule impossible to bypass, and what makes the
   API and MCP server cheap to build rather than parallel implementations.
3. **Evidence over assertion.** Parsing and inventory matching are heuristic.
   Every derived fact carries its method and confidence and is presented as such.
4. **Untrusted input by default.** Emails and PDFs arrive from outside the
   organisation. The parser is a sandbox, not a convenience.
5. **Runs on-prem, air-gap-tolerant.** The only outbound dependency is NVD, and
   it is optional and degradable.

## 2. System overview

```
      Regulator                Power Automate
       mailbox      ───────►   (Office 365 flow)
                                     │  writes .eml + attachments
                                     ▼
                            ┌──────────────────┐
                            │  /data/inbox     │   mounted volume
                            └────────┬─────────┘
                                     │ polled every 30s
┌────────────────────────────────────┼─────────────────────────────────────┐
│  Docker Compose                    ▼                                     │
│                        ┌───────────────────────┐                         │
│                        │  worker (RQ)          │                         │
│                        │  ├ inbox watcher      │                         │
│                        │  ├ email/PDF parser ──┼──► sandboxed subprocess │
│                        │  ├ NVD enrichment     │        (no network)     │
│                        │  └ inventory sync     │                         │
│                        └───────┬───────────────┘                         │
│                                │                                         │
│   ┌────────────────────────────┼─────────────────────────────────┐       │
│   │  app (FastAPI)             ▼                                 │       │
│   │  ┌─────────┐  ┌────────┐  ┌──────────────────────────────┐   │       │
│   │  │ web/    │  │ api/   │  │ mcp/  (stdio + HTTP)         │   │       │
│   │  │ HTMX UI │  │ REST   │  │ tools for dashboards/agents  │   │       │
│   │  └────┬────┘  └───┬────┘  └──────────────┬───────────────┘   │       │
│   │       └───────────┴──────────┬───────────┘                   │       │
│   │                              ▼                               │       │
│   │                   ┌─────────────────────┐                    │       │
│   │                   │  core/  services    │  ◄── ALL rules     │       │
│   │                   └──────────┬──────────┘                    │       │
│   └──────────────────────────────┼───────────────────────────────┘       │
│                                  ▼                                       │
│              ┌───────────────┐  ┌────────────┐  ┌──────────────┐         │
│              │ PostgreSQL 16 │  │ Redis      │  │ /data/blobs  │         │
│              │ (system of    │  │ (queue +   │  │ (content-    │         │
│              │  record)      │  │  cache)    │  │  addressed)  │         │
│              └───────────────┘  └────────────┘  └──────────────┘         │
└──────────────────────────────────────────────────────────────────────────┘
                                     │
                          optional outbound (allowlisted)
                                     ▼
                   NVD API 2.0  ·  Desktop Central  ·  Azure ARM / MS Graph
```

In production (`docker-compose.prod.yml`) `app` is the only published
service. It serves HTTPS itself (`HTTPS_ENABLED`, with a provided or
generated certificate — `core/security/tls.py`, D-045) or sits behind an
enterprise WAF / reverse proxy that terminates TLS (D-040). Postgres and
Redis sit on an internal network with no outside route; a one-shot
`migrate` container applies migrations before `app`/`worker` start.
Topology and hardening are in [deployment.md](deployment.md) §1.

## 3. Components

### 3.1 `core/` — the service layer

The only place business rules exist. Everything else calls into it.

| Service | Responsibility |
|---|---|
| `advisories` | CRUD, search, filtering, the **`change_status()`** chokepoint |
| `comments` | Free comments and status-linked comments |
| `sources` | Regulator/source registry, sender-domain → source mapping |
| `enrichment` | NVD lookup orchestration and cache policy |
| `inventory` | Source config, credential handling, snapshot lifecycle |
| `scan` | Advisory × inventory matching, scan run lifecycle |
| `stats` | Aggregations for dashboard and reporting endpoints |
| `audit` | Append-only event log |
| `auth` | Users, roles, sessions, API tokens (SSO-swappable) |

Services take a DB session, enforce authorisation, emit audit records, and return
plain domain objects. They know nothing about HTTP, HTML, or MCP.

### 3.2 `ingest/` — the pipeline

Detailed in [ingestion.md](ingestion.md). Summary: watcher → dedupe → blob store
→ sandboxed parse → extract → classify → persist → enqueue enrichment.

### 3.3 `web/` — the UI

Server-rendered Jinja2 with HTMX for interactivity. Chosen because the three
interactive needs — expand-a-row, inline status edit with a forced comment, and
"scan inventory" results appearing in place — are all naturally HTML-fragment
swaps. No Node build step, one deployable, one language.

- **Tracker + dashboard** (`/`): KPI tiles above a filterable table with columns
  Source · Type · Title · Description · Status · Last comment. Rows expand to a
  detail panel loaded as an HTMX partial. The Title cell carries an IOC
  indicator — a total ("38 IOCs") plus one chip per distinct kind of
  indicator (`IP`, `Domain`, `MD5`, …), up to four with a `+N` overflow
  whose tooltip still names every kind. A sort picker in the filter bar
  offers, alongside date and severity, **Most/Fewest IOC types** and
  **Most/Fewest IOCs**; the two rank differently on purpose — see the table
  in §3.3.1. A "Scan inbox now" button
  (ANALYST+, `POST /inbox/scan`) runs `ingest.pipeline.process_inbox()`
  immediately rather than waiting for the worker's background poller's next
  sweep — the same function the poller and `advisory-hub watch` call, safe
  to run concurrently since `Inbox.claim()`'s atomic rename means only one
  caller ever wins a given file.
  An "Upload email" button (ANALYST+, `POST /inbox/upload`) takes one or
  more `.eml`/`.msg` files (≤ `UPLOAD_MAX_FILES` per upload, each
  ≤ `UPLOAD_MAX_BYTES`) and runs `ingest.pipeline.ingest_uploads()`: every
  file is validated first (all or nothing), then deposited into the inbox
  (`.tmp` + rename, sanitised basename), claimed, and processed like any
  drop — archived or moved to `failed/` with a sidecar, never discarded.
  The ingest audit entry names the uploader, not `system`. A file the
  worker's poller claims first is reported "Queued for the worker". The
  result (per file: Ingested / Already ingested / Failed + reason, linked
  to its advisory, and its source) is swapped in above the dashboard. A
  file whose source wasn't detected gets a source picker right there.
- **Advisory source** (detail view → Details → Source): the source, how it
  was decided (matched sender / from reference DOH-… / set manually / Not
  detected), and for ANALYST+ a **Change** picker —
  `POST /advisories/{id}/source` → `advisories.change_source()`, audited
  `advisory.source_changed`, marks it `MANUAL`, resolves an open
  `UNKNOWN_SENDER` flag. Rules: docs/ingestion.md §6 "Source", D-047.
- **Buttons and controls**: one size everywhere (`--control-h`, 2.25rem):
  every `<button>`, the "Upload email" label-button and the native file
  picker share height, padding, font and radius. Primary (filled) is the
  default; `.secondary` (outlined, same size) for an action beside a
  primary one — Refresh, Scan inbox now, Test connection, Deactivate.
  `button.link` is for text actions (Sign out, Deactivate a user).
  Inputs/selects that sit beside buttons use the same height.
- **Ivanti tickets** (D-050): on an advisory, ANALYST+ **Create ticket**
  opens a dialog whose Service → Category → Sub-category → Team dropdowns are
  read live from Ivanti (`GET /advisories/{id}/tickets/options?level=…`
  fills the next level and empties the dependent ones below it, cached 10
  min). `POST /advisories/{id}/tickets` → `core.services.tickets.create_ticket`
  re-checks every value against Ivanti's list for its parent, creates the
  Service Request (`CreateObject`), attaches the PDF, stores an
  `advisory_ticket` row and audits `advisory.ticket_created`. SOAP client:
  `integrations/ivanti.py` (httpx + defusedxml, SSRF-checked, the key only to
  the tenant host). Settings: /admin → Ticketing (operations.md §10).
- **Mailbox sync** (D-049): a worker poller (`mailbox_sync.run_sync`, every
  `poll_seconds`) reads one mailbox folder through Microsoft Graph, app-only
  and read-only (Exchange RBAC for Applications scopes the app to that
  mailbox). New messages (Graph delta query; position in
  `mailbox_sync_state`) are downloaded as MIME and **deposited into the
  inbox** — from there it's the normal pipeline. The token is only ever sent
  to `graph.microsoft.com`; messages over `UPLOAD_MAX_BYTES` are skipped and
  counted.
- **Import manual tracker** (`/tracker-import`, ANALYST+, linked from the
  tracker page): upload the team's spreadsheet tracker (`.xlsx`) or the CSV
  converted from it, preview, then apply — statuses and comments brought
  into the tool. See §3.3.3.
- **Inventory** (`/inventory`): source configuration, CSV upload, sync history.
- **Affected Software** (`/affected-software`): one row per product match from
  each advisory's most recent completed scan — Product · Version · Affected
  hosts · Severity · Advisory · Status. "Refresh" reloads the table with no
  side effects; "Refresh all (re-scan)" re-runs `scan.refresh_all_scans()`
  against every already-scanned advisory's inventory sources' current latest
  snapshots.
- **IOCs** (`/iocs`): every indicator across every advisory, with a remediation
  status (DUE/BLOCKED/IN_PROGRESS/RESOLVED — defaults to tracking the parent
  advisory's own status, overridable per indicator; see D-034), a multi-select
  bulk "Check on VirusTotal" action that queues rate-limited RQ jobs rather
  than calling VirusTotal synchronously, a "Refresh" button to reload the
  table (bulk VT results land asynchronously), and a CSV export
  (`/iocs/export`, honours the tab's current filters) that includes each
  indicator's cached VirusTotal result alongside its defanged value.
- **Admin layout** (2026-10-06): four collapsible groups — **People & access**
  (Users, Microsoft sign-in), **Email intake** (Sources, Mailbox sync),
  **Ticketing** (Ivanti), **Enrichment** (NVD, VirusTotal). Each summary shows
  the group's state while collapsed; a jump bar opens a group
  (`/admin#group-intake`); which groups are open is remembered per browser.
- **Sources** (/admin → Email intake): add a source (short code, name,
  sender addresses/domains), edit it, deactivate/reactivate it —
  `core.services.sources.create_source` / `update_source` /
  `set_source_active`, ADMIN only, audited (`source.created|updated|
  deactivated|activated`). No delete: advisories reference sources. Active
  sources are matched on incoming mail (sender, then reference prefix — the
  short code, 2–6 letters for that) and offered wherever an analyst sets a
  source (detail view, upload result, bulk edit). UNKNOWN is built in.
- **Bulk edit** (tracker, ANALYST+): tick rows (or the page with the header
  box) → a bar offers **Set source** and **Change status** (with the
  acknowledgement channel when needed and a comment, required, added to each).
  `POST /advisories/bulk` → `advisories.bulk_change_source` /
  `bulk_change_status`, which run the single-advisory services
  (`change_source`, the `change_status` chokepoint) per advisory, each in a
  savepoint: one whose transition isn't allowed is skipped and listed with
  the reason, the rest go through. Up to 200 at a time. The table refreshes
  itself (`tracker-refresh` event) with the current filters.
- **Resizable columns**: on the tracker, IOC and Affected Software tables
  (`<table data-resizable="…">`) drag a header's right edge; widths are
  stored per browser (localStorage, per table) and re-applied after every
  htmx swap; double-click an edge to reset. A widened table scrolls
  sideways.
- **Admin** (`/admin`, ADMIN role only): **Microsoft 365** — one card each
  for Microsoft sign-in and mailbox sync (tenant/client IDs, write-only
  secret, Test, Enable; mailbox sync also mailbox, folder, interval, Sync
  now, last sync status) — D-049, operations.md §9. **Users** — list every account
  (role, active/deactivated, last sign-in), add a user with an initial
  password, change a role inline, deactivate/reactivate, reset a password —
  all rules in `core.services.users`, see §6 and D-046. Below it,
  per-integration enable toggle and write-only key rotation for NVD and
  VirusTotal.

#### 3.3.1 Sorting the tracker by IOCs

Two different questions, two different sort keys. Against the real 135-message
corpus they pick different advisories as "the biggest":

| Sort key | Ranks by | Top advisory in the real corpus |
|---|---|---|
| `-ioc_type_count` | Distinct **kinds** of indicator | 38 IOCs across **4** kinds (Domain 15, MD5 11, IPv4 10, SHA256 2) |
| `-ioc_count` | Total **number** of indicators | **72** IOCs across 3 kinds |

The kind count is the one that predicts effort: six SHA256 hashes is a single
blocklist update, while two hashes, two domains, an IP and a registry key is
four separate controls to touch. The raw total is the one that predicts volume.

Both are computed by `LEFT JOIN`ing a `GROUP BY advisory_id` aggregate over
`advisory_ioc` and ordering on `COALESCE(…, 0)`, so:

- advisories with **no** IOCs are still listed (left, not inner, join), and
  sort as `0` rather than as `NULL` — which Postgres would otherwise place
  *first* on a descending sort;
- the join can never fan one advisory out into several rows, because the
  aggregate has one row per `advisory_id`;
- ties — which dominate, since most advisories carry no IOCs at all — fall
  back to the default newest-first order rather than an arbitrary one.

Unknown sort keys fall back to the default (`normalise_sort()`); the key never
reaches SQL as anything but a lookup into a fixed table.

#### 3.3.2 Theme and colour

The UI follows **Mediclinic's colour language**, taken from the stylesheet
of mediclinic.ae (D-036), in a light and a dark theme.

| Token | Light | Dark | Used for |
|---|---|---|---|
| `--bg` | `#F7F6F5` stone | `#0B1733` deep navy | Page background |
| `--surface` | `#FFFFFF` | `#112046` | Cards, header, tables |
| `--border` | `#E2DFDB` | `#22335E` | Rules, input borders |
| `--ink` | `#534C46` warm grey | `#F0EFED` | Body text |
| `--heading` | `#0A235E` navy | `#FFFFFF` | Headings, brand wordmark, active tab |
| `--muted` | `#72665B` | `#B6ADA5` | Secondary text, labels |
| `--brand` | `#0094D4` | `#0094D4` | **Non-text only**: header rule, active-tab underline, focus ring, hover borders |
| `--accent` | `#0072A3` | `#4FB8E6` | Links |
| `--button` / `--on-button` | `#0072A3` / white | `#0094D4` / navy | Primary buttons (hover `#003F72` / `#33A9DD`) |
| `--danger` | `#DF131B` Mediclinic red | `#FF6B70` | Error banners |

Mediclinic's signature blue `#0094D4` is only **3.4:1** against white, below
WCAG AA for text — which is why it is reserved for non-text accents, and
links/buttons use Mediclinic's own darker `#0072A3` (5.3:1). Every text
pairing in both themes is ≥ 4.5:1.

The **status palette** (good/warning/serious/critical/neutral badges) is
deliberately *not* brand-coloured: it is the dataviz skill's validated
semantic set, and making "critical" a Mediclinic blue would erase its
meaning. Only the dark-mode *neutral* badge was retuned (`#B6ADA5` on
`#1D2C52`) so it reads against the navy surface; the rest are unchanged.

Font stack is `Metropolis, Arial, …` — Mediclinic's typeface if installed on
the client, Arial otherwise. It is not bundled or loaded from a CDN.

**Switching**: each token is a CSS `light-dark(<light>, <dark>)` pair, so by
default the theme follows the operating system. The toggle in the header
(and top-right of the sign-in page) cycles **System → Light → Dark** and
stores the choice in the browser's `localStorage` (`ah-theme`) — per
browser, nothing server-side. A pinned choice is applied by a small inline
script in `<head>` before first paint, so there is no light-to-dark flash.

#### 3.3.3 Importing the manual tracker

Before this tool, advisories were tracked in a spreadsheet: one sheet per
month, plus "Summary" and "Pending Actions" sheets that are formulas over
the month sheets. The import brings that history in.

**What's read.** Every sheet with both an *Advisory No.* and an *Action
Taken by MCME Infosec* column. The roll-up sheets have neither, so they're
skipped. Columns are matched by header name, not position, because the
month sheets don't share a layout (September dropped *Sender*, *Action
Required* and *Summary*; July has no *Comments*). The workbook reader is
`manual_tracker/xlsx.py`: `defusedxml`, size-checked before decompression,
cells placed by their cell reference so blank cells don't shift columns.

**What becomes a comment.** Only what the tool doesn't already extract from
the email and PDF — *MCME Owner*, *Action Taken by MCME Infosec* and
*Comments*:

```
From manual tracker (August 2026):
Owner: Systems Team
Action taken: Ticket raised : 940435
Notes: Compensating control for vcenter
```

Subject, dates, sender, products/versions, CVEs, risk level, type, summary
and IOC availability are all parsed by the tool already, so they aren't
repeated.

**How tracker text becomes a status.** *Comments* and *Action Taken* are read
together; the first rule that matches wins (`core.services.tracker_import.STATUS_RULES`):

| # | Tracker text (examples) | Status |
|---|---|---|
| 1 | "Resolved and Fixed" | Remediated |
| 2 | "Closed with comments that automation Job in place" | Remediated |
| 3 | "Duplicate of DOH-2026599" | Not applicable |
| 4 | "Not Applicable", "General Information", "Generic advisory" | Not applicable |
| 5 | "Raised as a risk already" | Risk accepted |
| 6 | "…closed with IT recommendations will upgrade after stable version" | Awaiting vendor |
| 7 | "Ticket raised : 969675, In progress" | In progress |
| 8 | "Hash Blocked : 04555296", "Blocked Hashes" | Remediated |
| 9 | "No Blocking mechanisom available" | Risk accepted |
| 10 | "Auto Patching is in Place", "Autopatching" | Remediated |
| 11 | "Ticket raised : 940435" | In progress |
| 12 | "Assessment required", "Need more informaiton", "Need to raise ticket", "Bulk Vulnerabilities" | Triaged |
| — | Blank, or anything else (e.g. "Pending response from …") | **No status change** — the comment is still added |

The order matters, and tests pin it: a Comments verdict ("Resolved and
Fixed") outranks the "Ticket raised" beside it; "closed … will upgrade after
stable version" is checked before the plain "ticket raised" it contains; a
duplicate is not applicable even if it also mentions patching. Patterns
accept the tracker's real misspellings. The rule that fired is shown next to
every proposed status in the preview — it's an inference, not a fact
(CLAUDE.md §2.2).

**How a status is applied.**

| Rule | Why |
|---|---|
| Every change goes through `change_status()`, one legal transition at a time, each with a comment | The single chokepoint (§4.2). NEW → Remediated is recorded as NEW → Triaged → In progress → Remediated |
| Intermediate steps only ever pass through Triaged / In progress / Remediated | Passing through Awaiting vendor, Risk accepted or Not applicable would record history that never happened |
| Acknowledged only with an `ack_channel` | `change_status()` requires the channel. A row with an `ack_channel` is acknowledged first (NEW → Acknowledged → …); a row asking for ACKNOWLEDGED without one is skipped with a message |
| Only forward. If the tool already has a status as far along (or further), the tool wins — "Kept" in the preview | Once someone works an advisory in the tool, an old spreadsheet mustn't undo it |
| Matched on advisory number; every record with that number is updated — unless the row's `received_date` picks out one of them | The regulator re-issues advisories under the same number |
| Several rows for one advisory apply in order, each from where the previous left it | Otherwise the second row's first step is illegal and the whole import fails |
| Rows with no matching advisory are reported, not created | Advisories come from email only. Re-import after they're ingested |
| Re-importing the same file changes nothing and posts no duplicate comments | Safe to run again, e.g. monthly while both are in use |
| Preview writes nothing; Apply is one transaction | All or nothing |

**Editing before importing.** "Download as CSV" on the preview,
`advisory-hub tracker-to-csv`, or `scripts/tracker-to-csv.sh` (operations.md,
CLI — all the same conversion) gives one flat CSV —
`advisory_ref, received_date, subject, status, comment, source, ack_channel` — with the
proposed status and comment filled in. Correct the `status` column (any tool
status, or blank for no change) or the comment, and upload the CSV instead
of the workbook. Statuses in the CSV are taken as written; an unknown value
skips that row with a message rather than being guessed.

Web-only for now: there's no REST endpoint for the import.

#### 3.3.4 Status export — an importable backup

**Export statuses (CSV)** on the tracker page (any signed-in user;
audit-logged as `advisories.status_exported`), the CLI `status-export`, and
a daily job in the worker all produce the same file: **one row per advisory,
in the import CSV format above**. So the import page is also the restore
tool.

| Column | Holds |
|---|---|
| `status` | The advisory's current status |
| `ack_channel` | How it was acknowledged, if it was |
| `comment` | Its whole history as one block: when, who and how it was acknowledged, then every comment with its date, author and status change |
| `received_date` | Tells re-issues sharing a number apart |
| `source` | `Status export <date>` — marks the row as a restore row |

**Restoring a lost deployment** (runbook: operations.md §4): stand up a
fresh deployment, re-ingest the original emails (from the archive or by
re-dropping them), then upload the latest export on `/tracker-import`.

| What comes back | How |
|---|---|
| Status | Through legal transitions via `change_status()`, each recorded |
| Acknowledgement | Re-recorded with its channel. The *time* becomes the import time; the original time and person are in the history comment |
| Comments | As one history comment per advisory, authored by whoever runs the import, preserving each original's date and author in the text |
| Assignee, priority overrides, VirusTotal results, IOC remediation statuses, inventory scans | **Not in the export** — re-derive or redo |

**Safe against a healthy deployment.** Statuses already in place are left
alone, and the history comment is only added to an advisory that has *no*
comments yet. Importing an export into a working deployment changes
nothing, so a mistaken upload doesn't append a history block to every
advisory.

**Known limit.** Two re-issues sharing a number *and* a received day can't
be told apart. If they ended in different statuses, both restore to the
further-along one.

**Verified on real data**: the 135-advisory corpus with real statuses
(including acknowledgements) was exported, and a brand-new database was
built by re-ingesting all 135 emails. Importing the export reproduced
status, acknowledgement channel and acknowledged flag identically for every
advisory. Importing it again changed nothing.

### 3.4 `api/` — REST

`/api/v1`, OpenAPI 3.1 auto-generated at `/api/docs`. Session cookie for the UI,
bearer tokens for integrations. Same services, same rules — a `PATCH` to change
status without a comment returns `422`, exactly as the UI blocks it.

### 3.5 `mcp/` — MCP server

A separate process built on the official `mcp` Python package, exposing the same
services as tools over stdio and streamable HTTP. It contains no logic of its
own. See [api-and-mcp.md](api-and-mcp.md).

### 3.6 Storage

| Store | Holds | Why |
|---|---|---|
| PostgreSQL | All structured data, full-text search (`tsvector`), JSONB for parsed blobs and integration config | Concurrent writers, real FTS, JSONB |
| Blob volume | Original `.eml`, attachments, extracted text — keyed by SHA-256 | Immutable, deduplicated, re-parseable |
| Redis | RQ job queue, NVD response cache, rate-limit counters | Ephemeral by design |

On disk, all three live in host folders under `./data/<volume>` beside the
compose file (`pgdata`, `blobs`, `redisdata`, plus `inbox`, `processing`,
`archive`, `failed` for ingestion), so backup and restore are file
operations on one directory — operations.md §2 and §4, D-043.

## 4. Key flows

### 4.1 Ingestion

```
file appears → sha256 → seen before?
   yes → link to existing advisory, stop (idempotent)
   no  → move to processing/ → store blobs → sandboxed parse
       → extract CVEs, IOCs, products, CVSS → classify type
       → resolve source from sender domain → persist advisory (status = NEW)
       → archive/ + enqueue NVD enrichment
   failure at any step → failed/ + .error.json sidecar + admin-visible alert
```

Nothing is deleted. `archive/` and `failed/` both retain the original.

### 4.2 Status change (the enforced path)

```
UI / API / MCP
      └─► core.services.advisories.change_status(
              advisory_id, to_status, comment_body, actor)

          BEGIN
            validate transition is legal for the current status
            reject empty/whitespace comment          → 422
            INSERT comment
            INSERT status_change (comment_id NOT NULL)
            UPDATE advisory.status
            INSERT audit_log
          COMMIT
```

The comment is required at three layers: the UI disables Save until non-empty,
the service raises, and `status_change.comment_id` is `NOT NULL` in the schema.
Defence in depth, so a future caller cannot regress it.

### 4.3 Inventory scan (Phase 2)

```
user expands advisory → clicks "Scan inventory"
   → create scan_run (status = RUNNING), return immediately
   → worker: for each selected inventory source's latest snapshot
        for each CVE on the advisory
          resolve affected products:
            NVD CPE ranges (preferred)  →  parsed PDF product/version  →  none
          normalise vendor + product names via alias table
          compare versions with the tiered comparator
          record scan_match rows with method + confidence
   → HTMX polls scan_run; results render inline in the detail panel
```

Results are grouped **Confirmed / Likely / Possible / Not found**, never a bare
"vulnerable: yes". See [inventory-matching.md](inventory-matching.md).

## 5. Status model

Revised 2026-08-20 after corpus analysis. The regulator demands **two distinct
responses** on **two separate clocks** — acknowledgement, then resolution — so
`ACKNOWLEDGED` is a first-class status, not an implicit step.

```
                         ┌──────────────► NOT_APPLICABLE ─┐
                         │                                │
NEW ──► ACKNOWLEDGED ──► TRIAGED ─┬──► IN_PROGRESS ──► REMEDIATED ──► CLOSED
 │         ▲                      │         │                          ▲
 │         │                      ├──► RISK_ACCEPTED ───────────────────┤
 └─────────┘                      └──► AWAITING_VENDOR ──┘              │
   ack clock stops           (back to IN_PROGRESS)                      │
                                                          reopen ───────┘
```

- **`NEW` → `ACKNOWLEDGED`** stops the acknowledgement clock and records
  `acknowledged_at` and the channel (email or phone — the regulator accepts
  either). This is the only transition that may be performed in bulk, because
  acknowledgement is a receipt, not a judgement.
- Everything from `TRIAGED` onward runs against the resolution clock.
- Transitions are validated server-side in `core`. **Every edge requires a
  comment**, including acknowledgement.
- `CLOSED` is reopenable to `TRIAGED` — regulators re-issue advisories, as the
  corpus confirms (`DOH-2026550` → `DOH-2026552` eight hours apart).

**Implemented (2026-08-21):** `core.services.advisories.change_status()` is
the single chokepoint — see CLAUDE.md §2.2. It row-locks the advisory,
validates the transition against `ALLOWED_TRANSITIONS`, requires a non-blank
comment, requires an `ack_channel` when the target is `ACKNOWLEDGED`, writes
the `comment` and `status_change` rows and the `audit_log` entry in one
transaction, and updates `acknowledged_at`/`acknowledged_by_id`/`ack_channel`
on acknowledgement. The web UI's detail-panel status form is the only caller
so far; the REST API (Phase 1e) will be the second. **Bulk acknowledgement is
not yet built** — every transition, including acknowledgement, currently goes
through the single-advisory form.

### SLA clocks

Both start at `received_at`. Thresholds are the regulator's own, embedded in all
135 emails:

| Priority | Risk level | Acknowledge | Resolve |
|---|---|---|---|
| P1 | Critical | **8 h** | **24 h** |
| P2 | High | **16 h** | **48 h** |
| P3 | Medium | 72 h (3 working days) | 120 h (5 working days) |
| P4 | Low | 72 h (3 working days) | 120 h (5 working days) |

At the observed mix (79 Critical / 39 High / 16 Medium over ~5 weeks) roughly
**59% of advisories carry an 8-hour acknowledgement fuse**. The dashboard's
primary KPI tile is therefore "unacknowledged, by time remaining" — not total
open count.

## 6. Authentication and authorisation

Local username/password with Argon2id, plus optional **Microsoft Entra ID
sign-in** (OIDC authorization code + PKCE, single tenant) — D-049. Entra
proves *who* someone is; *whether* they may sign in and their role come only
from the local `user_account` row. No group or role claim is requested or
read.

| Account | Signs in with |
|---|---|
| Added with a password, never linked | Password (e.g. the break-glass admin) |
| Added without a password (Microsoft sign-in on) | Microsoft; the first sign-in links it by email = UPN |
| Linked (`external_subject = tenant:oid`) | Microsoft only — password refused, so MFA / Conditional Access always apply |

`core.services.entra_auth` holds every rule: state + nonce + PKCE carried in
a 10-minute signed cookie; code exchanged at the tenant's token endpoint; ID
token signature-verified (RS256, tenant JWKS, cached 1 h, one refetch on an
unknown `kid`) with `aud`, `iss`, `tid`, `nonce`, `exp` checked; match by
`tid:oid`, else link an unlinked user with the same email, else refuse.
Every refusal is audited (`auth.entra_refused` + reason); the person sees one
generic message. Setup: operations.md §9.

| Role | Can |
|---|---|
| Viewer | Read advisories, comments, scan results |
| Analyst | Viewer + change status, comment, run scans, upload CSV inventory |
| Admin | Analyst + manage users, sources, inventory integrations, API tokens |

**User administration (2026-10-05)** — `/admin` → Users, backed by
`core.services.users` (every function takes the acting `Principal` and
requires ADMIN itself):

| Action | Rule | Audit action |
|---|---|---|
| Add user | Email unique (case-insensitive), password ≥ 12 chars — same as `create-admin` | `user.created` |
| Change role | Not your own; never demotes the last active admin. Applies on the user's next request — no sign-out needed | `user.role_changed` (`from`/`to`) |
| Deactivate | Not yourself; never the last active admin. Ends all their sessions; sign-in refused | `user.deactivated` |
| Reactivate | — | `user.activated` |
| Reset password | ≥ 12 chars. Ends all their sessions (except the admin's own current one when resetting their own) | `user.password_reset` |

There is no delete: audit entries and comments reference the account, so it
is deactivated instead (D-046).

With Microsoft sign-in on: the password is optional when adding a user
(blank = Microsoft only); a **Sign-in** column shows Password / Microsoft /
Microsoft (not yet signed in); **Unlink Microsoft** (`user.entra_unlinked`,
ends their sessions) replaces Reset password for linked users.

API tokens are scoped (`advisories:read`, `advisories:write`, `inventory:read`,
`scan:run`, `stats:read`), hashed at rest (only the prefix is stored in clear for
identification), and shown exactly once at creation.

**Implemented (2026-08-21):** a browser session's role is translated into the
same scope space via `core.security.tokens.SCOPE_MIN_ROLE`, so
`Principal.require_scope()` — the single check both the REST API and any
future MCP tool use — enforces the role table above for session users too,
not just for API tokens. This closed a real gap found while building the
REST API: the check previously passed any logged-in user regardless of role.

## 7. Security posture

| Threat | Control |
|---|---|
| Malicious PDF (bomb, JS, huge page count) | Sandboxed subprocess, no network, caps on bytes / pages / decompression ratio / wall clock; JS never executed |
| Malicious HTML email body | Allowlist sanitiser before render; no remote resource loading |
| Accidental IOC detonation | All IOCs defanged in every rendered surface |
| SSRF via inventory source URL | Host allowlist, deny link-local/loopback/metadata, no redirects to new hosts |
| Credential theft | AES-GCM (Fernet) at rest with key from env/KMS; never returned by any endpoint |
| Unattributable changes | Mandatory comment + `status_change` + append-only `audit_log` |
| Token leakage | Hashed at rest, scoped, revocable, last-used tracked |
| Credentials / session cookies sniffed on the network | HTTPS — served by the app itself (`HTTPS_ENABLED`, TLS via uvicorn, certificate validated at start) or by the WAF in front; session cookie always `Secure` in production, so it's never sent over plain HTTP (deployment.md §1) |
| Spoofed `X-Forwarded-For`/`-Proto` (audit-log IP forgery) by anyone who can reach `app`'s port | `FORWARDED_ALLOW_IPS` pinned to `TRUSTED_PROXY_IPS` — only the operator-declared WAF address(es) are trusted to set those headers; the firewall, not this app, must keep everyone else from reaching the port at all (deployment.md §1, D-040) |

## 8. Deliberate non-goals (for now)

- Not a SIEM, not a scanner. It reads inventory others collect.
- No agent on endpoints.
- No automated remediation or patch deployment.
- No multi-tenancy. One organisation per deployment.
