# CLAUDE.md — Advisory Hub

Standing instructions for anyone (human or agent) working in this repo, plus the
running progress log.

---

## 1. What this project is

An internal security-advisory tracking, statistics, and remediation portal.
Regulatory bodies email us CVE bulletins and threat-landscape reports; Power
Automate drops those emails into a watched folder; we parse them (body + PDF),
track remediation with a mandatory-comment audit trail, and cross-reference
against endpoint inventory to determine real exposure.

Read [docs/architecture.md](docs/architecture.md) before changing anything
structural.

---

## 2. Standing instructions

These apply to every change, without being restated in the task.

### 2.1 Documentation is part of the change

- **Every behavioural change updates its doc in the same commit.** Schema change
  → `docs/data-model.md`. New parser or extractor → `docs/ingestion.md`. New or
  changed endpoint → `docs/api-and-mcp.md`. New env var, container, or ops step →
  `docs/operations.md`. A decision that closes off alternatives →
  `docs/decisions.md`.
- **Update the progress log in §4 of this file** when a phase task completes or
  its status changes. Keep it factual: what works, what doesn't, what's next.
- If a doc and the code disagree, the code is the bug *or* the doc is — fix both
  so they agree. Never leave a known-stale doc.
- Docs are written for a security analyst who did not write the code. Prefer
  tables and concrete examples over prose.

### 2.2 Architecture rules

- **`core/` is the only place business logic lives.** `api/`, `web/`, `mcp/`, and
  `worker/` are thin adapters that call `core/` services. If you find yourself
  writing a rule in a route handler, it belongs in a service.
- **Never bypass `core.services.advisories.change_status()`.** It is the single
  chokepoint that enforces the mandatory comment, validates the transition, and
  writes the audit record — atomically, in one transaction. The UI, REST API, and
  MCP server all go through it. A new caller is not an excuse for a second path.
- **Never mutate or discard the original email or attachment.** Raw bytes are
  content-addressed in blob storage forever. Parsers read from blobs; they never
  consume the only copy. Re-parsing must always be possible.
- **Parsing is versioned and idempotent.** Every advisory records the
  `parser_version` that produced it. Re-ingesting the same message must update,
  never duplicate.
- **Extraction results are evidence, not truth.** Anything the parser inferred
  (type classification, product/version, match confidence) is stored with its
  method and confidence, and is displayed to the user as such. Do not present a
  heuristic guess as a fact.

### 2.3 Security rules

Parsed emails and PDFs are **untrusted input from outside the org**. Treat them
that way:

- PDF and email parsing runs in a resource-capped subprocess with **no network
  access**, with limits on file size, page count, decompression ratio, and wall
  clock. A malicious PDF must not be able to hang or exhaust the worker.
- Sanitise HTML email bodies (allowlist, not blocklist) before rendering.
- **Render every IOC defanged** (`hxxp://`, `192.168[.]1[.]1`) so nobody
  accidentally clicks or resolves one from the UI. Store both raw and defanged.
- Inventory-source URLs are user-supplied: validate against an allowlist and
  block link-local, loopback, and cloud-metadata ranges (`169.254.169.254`).
  Assume SSRF is being attempted.
- Integration credentials are encrypted at rest and **never returned by any API,
  ever** — not redacted, not partially. Write-only fields.
- All authz decisions happen in `core/`, not in templates.

### 2.4 Conventions

- Python 3.14, type hints throughout, `ruff` + `mypy` clean before commit.
- Tests: `pytest`. Every parser gets a fixture-based test with a real (redacted)
  sample. Every service gets a unit test. Bug fixes start with a failing test.
- Migrations are Alembic, always reviewed, never auto-generated-and-committed
  without reading the diff. **Any migration adding a native enum column must
  add explicit `DROP TYPE IF EXISTS ...` calls to its own `downgrade()`** —
  `op.drop_table()` does not drop the PostgreSQL type, and autogenerate will
  not add this for you. See D-023.
- Commit messages: imperative subject line, body explains *why*.
- No secrets in the repo. `.env.example` documents every variable with a dummy
  value.

### 2.5 When requirements are ambiguous

Make the routine call yourself and state the assumption in the PR description
and the relevant doc. Only stop and ask when two readings would produce
materially different work.

---

## 3. Repository layout

```
advisory_hub/
  core/            # domain models + services — ALL business logic
    models/        # SQLAlchemy models
    services/      # advisories, comments, status, inventory, scan, enrichment
    security/      # crypto, ssrf guards, sanitisers
  ingest/          # watcher, email parser, pdf parser, extractors, classifier
  enrich/          # NVD client, cache, CPE normalisation
  inventory/       # csv adapters, api adapters, version normalisation, matcher
  manual_tracker/  # reading the team's spreadsheet tracker (safe xlsx reader, CSV format)
  api/             # FastAPI REST routers (thin)
  web/             # Jinja templates + HTMX partial routes (thin)
  mcp/             # MCP server exposing core services as tools (thin)
  worker/          # RQ job definitions and schedules
  cli.py
docs/              # deployment.md is the production guide
migrations/
tests/
docker/            # Dockerfile (app + worker + migrate image)
scripts/           # tracker-to-csv.sh — manual tracker .xlsx → import CSV (venv or Docker)
docker-compose.yml           # base stack (pulls images)
docker-compose.override.yml  # dev: builds locally, reload — auto-applied
docker-compose.prod.yml      # production, self-contained, behind your WAF — see docs/deployment.md
data/                        # all persistent data, ./data/<volume> (git- and docker-ignored); certs/ = HTTPS key+cert
.env.example / .env.production.example
```

---

## 4. Progress log

Newest first. Update this when work lands.

### 2026-10-06 — Microsoft Entra ID sign-in + mailbox-folder sync (roles stay local)
- **On request**: Entra SSO alongside local user management, and direct sync
  from a mailbox folder; Entra for authentication and mailbox access only,
  roles in the app. User chose: pre-added users only; app-only mailbox access
  scoped by Exchange; leave messages untouched; passwords only for accounts
  never linked. D-049; setup in operations.md §9.
- **Sign-in**: `core/services/entra_auth.py` — auth code + PKCE, state/nonce
  in a signed 10-min cookie, ID token RS256-verified against the tenant JWKS
  (aud/iss/tid/nonce/exp), match `tid:oid` → link unlinked user by email →
  refuse (audited). Routes `/auth/entra/login`, `/auth/entra/callback`;
  "Sign in with Microsoft" on the login page (which still renders if the
  setting can't be read — break-glass). Linked users can't password-login.
- **Users**: password optional when SSO is on; Sign-in column; Unlink
  Microsoft; no password reset for linked users.
- **Mailbox sync**: `ingest/graph_mailbox.py` (Graph, read-only, token only to
  graph.microsoft.com, streamed size cap) + `core/services/mailbox_sync.py`
  (delta query, position in `mailbox_sync_state`, deposits MIME into the
  inbox; 410 → start over; errors recorded, never raised) + worker poller.
- **Admin**: Microsoft 365 cards (settings, write-only secret, Test, Enable,
  Sync now, last sync). API-key routes now refuse the Entra kinds
  (`API_KEY_KINDS`). New `PUBLIC_BASE_URL`; PyJWT dependency (also in the
  Dockerfile fallback list). Migration `c1d2e3f4a5b6` (enum values,
  `system_integration.config`, `mailbox_sync_state`; downgrade rebuilds the
  enum).
- **Verified**: 809 tests (29 sign-in incl. every token check and a full
  browser round trip, 17 mailbox incl. read-only/no-token-leak/expired
  position/real pipeline ingest); ruff/mypy clean; migration up/down/up with
  rows, no drift. Running app: Microsoft button only when enabled, redirect to
  the tenant's authorize URL, Microsoft-only user added, Test reports a
  missing allowlist entry. **Not verified against a real tenant** — needs the
  two app registrations (operations.md §9).

### 2026-10-06 — Duplicate gates on import
- **Reported**: duplicates when importing emails. **Cause**: the only gate
  was sha256 of the file; Outlook writes per-save metadata into each `.msg`,
  so the same email saved twice never matched. Corpus: 321 files = 186
  emails; importing both exports made 321 advisories. D-048.
- `ingestion.find_duplicate()`: hash → same Message-ID → same reference +
  identical PDF (re-send / forward). Same reference with a revised PDF is
  still a separate advisory (re-issue). Check + insert under a
  transaction-level advisory lock (upload, scan button and poller run
  concurrently). Duplicates of a different email are audited
  (`advisory.duplicate_received`) on the kept advisory; upload results
  say "Already ingested (same email)" / "(re-sent copy)".
- `advisory-hub duplicates`: read-only report of duplicates already stored,
  clustered (Message-ID or ref + PDF, transitively), oldest first. No
  auto-merge.
- ingestion.md §4 corrected — it claimed re-sends were caught by the hash
  and listed DOH-2026599 (a re-issue with a new PDF) as a re-send.
- **Verified**: 10 new tests (`tests/test_dedupe.py`, written failing first);
  the concurrency test fails 5/5 with the lock removed, passes 5/5 with it.
  Real corpus, both exports: old code → 321 advisories; new → 184 (133 by
  Message-ID, 4 by ref + PDF; DOH-2026599/-591 kept as re-issues). The
  report on the old database: 133 groups, 137 extra rows (= 321 − 184).
  763 tests, ruff/mypy clean.

### 2026-10-05 — Source from the DOH reference; set source by hand; uniform buttons
- **On request**: DOH-xxxxx advisories attributed to the Department of
  Health; source settable when not detected, on upload and in the detail
  view; all buttons uniform and size-matched. D-047.
- **Detection**: `resolve_source()` now sender → reference prefix
  (`short_code`) → UNKNOWN, returning a `SourceResolution`. New column
  `advisory.source_method` (SENDER/REFERENCE/MANUAL/NONE; migration
  `7b3e2f1a9c4d`, backfilled, `DROP TYPE` in downgrade). Unknown senders stay
  flagged even when the reference decides the source. Parser v3:
  `subject_parts()` strips FW:/RE:/[EXTERNAL] and finds a reference anywhere
  (never CVE-…); 182/182 unique corpus subjects parse identically to v2.
- **Manual**: `advisories.change_source()` (ANALYST+, audited, → MANUAL,
  resolves the UNKNOWN_SENDER flag); `POST /advisories/{id}/source`;
  `_source_field.html` in the detail view (Change picker) and a picker in
  upload results for undetected files.
- **Re-parse**: re-derives `external_ref` and re-resolves source (never
  MANUAL). Two pre-existing bugs fixed: it deleted UNKNOWN_SENDER /
  POSSIBLE_REISSUE flags, and couldn't rebuild `.eml` (assumed `.msg`).
- **Buttons**: one rule in base.html (`--control-h` 2.25rem) for every
  button, the upload label-button and the native file picker; `.secondary`
  (same size, outlined) beside a primary; inline-style buttons removed;
  text inputs/selects beside buttons share the height (inventory's Name
  input was unstyled). Detail view's "Original email (.msg)" → "Original
  email" (uploads can be .eml).
- **Verified**: 753 tests (21 new in `tests/test_source_detection.py`;
  re-parse tests fail on the old code); ruff/mypy clean; migration up/down/up
  with rows. Real HTTP run: 2 corpus .msg → DOH (sender), forwarded .eml →
  DOH (reference, flagged), unrelated .eml → "Source not detected" picker →
  saved → MANUAL, flag resolved, audited. Screenshots of every page in light
  and dark checked for button/control alignment.

### 2026-10-05 — User administration on `/admin`
- **On request** (user administration for admins, with role changes from
  that view). D-046; architecture.md §3.3 and §6.
- New `core/services/users.py`: list, add (≥12-char password, unique email),
  change role, deactivate/reactivate, reset password. Each takes the acting
  `Principal` and requires ADMIN itself; each change is audited
  (`user.role_changed` records from/to). Lock-out guards: no changing your
  own role or deactivating yourself; the last active admin can't be demoted
  or deactivated (row-locked check). Deactivation and password reset end the
  user's sessions; a role change applies on their next request.
- `/admin` gains a Users section (`_admin_users.html`): role picker per row
  (not for yourself), status, last sign-in, reset password, deactivate, add
  user. Each action re-renders the section in place with a confirmation or
  the rule it broke; actions run in a savepoint so a refusal undoes only its
  own writes.
- **Verified**: 732 tests (15 new in `tests/test_user_admin.py`); ruff/mypy
  clean. Real HTTP run: add user → viewer gets 403 on import → promote to
  analyst → 200 on their very next request; self-demotion refused; deactivate
  → their session redirects to login and sign-in fails; reactivate → sign-in
  works; audit trail correct. Screenshots checked in light and dark.

### 2026-10-05 — Upload email from the web app; header on IOCs / Affected Software
- **On request.** Tracker page "Upload email" button (ANALYST+,
  `POST /inbox/upload`, multiple `.eml`/`.msg`): `ingest.pipeline.ingest_uploads()`
  validates every file first (extension, empty, `UPLOAD_MAX_BYTES` 50 MB,
  `UPLOAD_MAX_FILES` 20 — new settings), then `Inbox.deposit()`s each into
  the inbox (`.tmp` + rename, sanitised basename) and claims/processes it
  through the normal `_process_one()` → archive/failed path. Ingest audit
  entries name the uploader (actor now threaded through `_process_one`).
  Per-file result (Ingested / Already ingested / Queued / Failed, linked to
  the advisory) swapped in above the dashboard.
- **Header missing on `/iocs` and `/affected-software`**: neither route put
  `principal` in the page context, and `base.html` only renders the header
  when it's set. Fixed; regression test covers every top-level page.
- **Latent bug fixed**: `Inbox.fail_file()` logged `file=` alongside an error
  dict that `_process_one()` always gives a `"file"` key → `TypeError` after
  the move, aborting the rest of the batch the first time a message failed.
  Never hit in the Test-Deployments stack yet (no failures in its logs).
- **Verified**: 717 tests passing (new `tests/test_upload.py` + a fail_file
  regression); `ruff`/`mypy --strict` clean; header test fails without the
  fix. Real HTTP run against a scratch DB: two real corpus `.msg` uploaded
  together → both ingested and linked, re-upload → "Already ingested", `.pdf`
  rejected with nothing written, files archived, audit actor = the uploader.
  Known: a plain-text file named `.eml` is ingested (Python's email parser
  accepts any text) — same as an inbox drop today.

### 2026-10-05 — `scripts/tracker-to-csv.sh`
- **On request** (a script for the manual tracker Excel → CSV conversion). A
  wrapper, not a second converter: runs the existing `advisory-hub
  tracker-to-csv` via the repo's `.venv`, or via Docker using the published
  image (`--network none`, read-only, `--cap-drop ALL`, your uid, workbook
  mounted read-only) — so its output is exactly the import page's.
- **Verified**: both routes on the real tracker give byte-identical output
  (174 rows), including a filename with a space; Docker output owned by the
  caller, not root; clear errors for a missing file, non-`.xlsx`, missing
  output folder, no image configured. Versus the CSV made on 2026-10-04,
  every row is identical apart from the `ack_channel` column added since
  (empty for the tracker) — the old file still imports.

### 2026-10-04 — HTTPS served by the app itself (no proxy needed)
- **Why**: behind NAT with no proxy, sign-in reloaded the login page — the
  `Secure` session cookie isn't sent over `http://` (browsers exempt only
  `localhost`, hence "works on my machine"). Asked for app-handled HTTPS
  with a provided certificate or a generated self-signed one. D-045.
- New `core/security/tls.py` (`ensure_certificate()`: use provided pair
  unmodified after validation / generate self-signed EC P-256 for
  `TLS_HOSTNAMES` / refuse a half-present pair; renews only its own
  self-signed cert) and `advisory_hub/serve.py` (launcher; now the image's
  `CMD` and the production app command). Settings `HTTPS_ENABLED`,
  `TLS_HOSTNAMES`, `TLS_CERT_FILE`, `TLS_KEY_FILE`; `./data/certs` mounted
  into `app` only; `init-data` owns it; health checks try HTTP then HTTPS.
  `TRUSTED_PROXY_IPS` now optional (default `127.0.0.1`).
- Docs: operations.md §7 rewritten (both HTTPS modes, certificate table,
  the localhost explanation), deployment.md (choose (a)/(b), verify,
  troubleshooting incl. the login loop), `.env` examples, architecture,
  README.
- **Verified**: 17 new tests; real stack via the Mac's LAN IP: cert
  generated with that IP as SAN, HTTP no answer, HTTPS 204, sign-in → tracker
  (no loop); a provided certificate from a stand-in CA served unchanged.

### 2026-10-04 — Status export: on demand, daily, and re-importable to restore
- **On request** ("export the status of all advisories … must be
  importable in case my deployment crashes … a cronjob in one of the
  containers to create a CSV export everyday in one of the volumes").
  D-044; architecture.md §3.3.4; runbooks in operations.md §4.
- New `core/services/status_export.py`, tracker-page link **Export
  statuses (CSV)** (`/status-export.csv`, any signed-in user,
  audit-logged), CLI `status-export`, worker poller writing
  `./data/exports/status-export-<date>.csv` on `STATUS_EXPORT_CRON` (UTC,
  default 02:00), keeping 30 days; catches up if the worker was down. New
  `./data/exports` folder (both compose files, `init-data`); 4 new
  `STATUS_EXPORT_*` settings.
- Same format as the tracker import, so `/tracker-import` restores it.
  The import gained an optional `ack_channel` column (acknowledges first,
  NEW → ACKNOWLEDGED → …), sequential planning of repeated rows,
  received-date matching for re-issues, and restore-history comments only
  on advisories with no comments.
- **Two tracker-import bugs fixed** (failing tests first): ACKNOWLEDGED
  rows crashed Apply (no channel); two rows for one advisory crashed Apply
  (second planned from the stale status).
- **Incident (mine)**: `make up` in the dev checkout replaced the running
  Test-Deployments stack's Postgres/Redis containers (both named
  `advisory-hub`). No data affected; restored from that stack's own folder
  and verified (`cli check` all ok, 29 tables, its admin present). Fixed at
  the source: `docker-compose.override.yml` now sets `name:
  advisory-hub-dev`.
- **Verified**: 672 tests passing (14 new); `ruff`/`mypy --strict` clean.
  Real disaster drill: export from a clone with real statuses, brand-new
  database re-ingesting all 135 emails, import → status + acknowledgement
  identical for all 135, re-import a no-op. Worker container wrote the
  day's file on start (uid 10001, 135 rows). Known limit: same-number
  re-issues received on the same day can't be told apart.

### 2026-10-04 — All data in `./data/<volume>` host folders
- **On request** ("force all deployments to create local directories for
  volume mapping … at ./data/{volume_name}"). Both compose files
  (`docker-compose.yml`, `docker-compose.prod.yml`) now bind-mount
  `./data/{pgdata,redisdata,blobs,inbox,processing,archive,failed}`; no
  named volumes remain. D-043.
- New one-shot **`init-data`** service: creates the folders and gives the
  app's ones to uid 10001. Without it, Linux Docker creates them as root and
  the app can't write. In production it runs with only `CHOWN`,
  `DAC_OVERRIDE` and `FOWNER`, no network, read-only. New `.dockerignore`
  (keeps `./data`, the corpus and real inventory/tracker files out of build
  context).
- Docs: operations.md §2 (data folders), §4 rewritten (cold/hot backup,
  restore, migrating from named volumes), project-name collision note;
  deployment.md (host layout, day-to-day, troubleshooting); both `.env`
  examples. Fixed a containers table I'd broken earlier (a paragraph had
  split off the postgres/redis rows).
- **Dev data migrated**: the development checkout's named volumes were
  copied (not moved) into its `./data/` — 2,032 Postgres files, all 135
  advisories present afterwards. Old volumes kept.
- **Verified**: dev stack (separate project name, so the running
  Test-Deployments stack was untouched) and production file from an empty
  `./data` both reach healthy; app folders owned by 10001; a real email
  dropped into `./data/inbox` on the host was claimed and archived to
  `./data/archive`; production migrations ran into `./data/pgdata`.
  `init-data`'s exact privilege set tested on Docker's Linux kernel
  against root-owned restored files (works; fails without `CHOWN`). Not
  verifiable on macOS: Linux host-side ownership.

### 2026-10-04 — Import the manual spreadsheet tracker
- **On request** ("convert [the tracker] into a single csv, put all info
  not already parsed in the tool to the comments … an option on the tool
  to upload this tracker and update the status of advisories"). D-042;
  how it works, incl. the full status-rule table: docs/architecture.md
  §3.3.3.
- New: `manual_tracker/` (`xlsx.py` — safe multi-sheet reader;
  `parse.py` — month-sheet detection by header, CSV format),
  `core/services/tracker_import.py` (`STATUS_RULES`/`infer_status`,
  `build_comment`, `transition_path`, `preview_import`, `apply_import`),
  `web/tracker_import.py` + `tracker_import.html` (upload → preview →
  apply, "Download as CSV"), CLI `tracker-to-csv`. Link on the tracker page.
- **Converted** the uploaded `Test_Files/Security_Advisories-2026.xlsx`
  into `Test_Files/Security_Advisories-2026.csv` (git-ignored, like the
  workbook): 174 rows — 63 Not applicable, 31 Triaged, 27 Remediated, 18 In
  progress, 6 Risk accepted, 1 Awaiting vendor, 28 no status change (27
  blank actions + "Pending response from …", deliberately not guessed).
- **Caught before it shipped**: the plain shortest status path recorded
  NEW → Remediated as passing through Awaiting vendor (alphabetical
  tie-break) — false history in an append-only audit log. Intermediate
  steps are now restricted to the plain lifecycle; a test checks every
  status pair.
- **Not done**: no REST endpoint for the import (web + CLI only). The
  status rules encode assumptions the team should confirm (D-042).
- **Verified**: 658 tests passing (64 new); `ruff`/`mypy --strict` clean.
  Real workbook read identically to openpyxl (174/174 rows). Real-data
  dry run on a dropped copy of the dev database through the actual web
  upload: 97 advisories updated in 135 legal steps, re-import a no-op,
  both records of re-issued DOH-2026591 updated. Dev database untouched.

### 2026-10-04 — Bundled HTTPS reverse proxy removed
- **On request** ("remove the https reverse proxy option altogether … remove
  the mentions in documentation as well"). Deleted `docker/nginx/`,
  `docker-compose.https.yml`, `scripts/https-setup.sh`, the `proxy` service,
  CI's `advisory-hub-proxy` build, and the proxy-only settings
  (`SERVER_NAME`, `HTTP(S)_PORT`, `TLS_CERT_DIR`, `HSTS_MAX_AGE`, `certs/`
  ignores). D-041.
- The WAF-fronted design (D-040) is now the **only** production setup:
  `docker-compose.prod.no-proxy.yml` → `docker-compose.prod.yml`,
  `.env.production.no-proxy.example` → `.env.production.example`. TLS is
  always terminated upstream; `TRUSTED_PROXY_IPS` is required.
- Docs rewritten to match: `docs/deployment.md` (one path, WAF requirements
  table, verification incl. a firewall check and real-client-IP check),
  `docs/operations.md` (§7 is now "TLS is terminated upstream"; numbering
  kept so §8 references still hold), `README.md`, `docs/architecture.md`,
  `.env.example` (now documents `TRUSTED_PROXY_IPS`, which it lacked).
  Two inaccuracies carried over from the D-040 docs fixed: the session
  cookie's `Secure` flag is a fixed setting, not derived from
  `X-Forwarded-Proto`; and client IPs are checked in `audit_log.ip_address`,
  not on `/admin`. History kept: D-035 marked superseded, D-037/D-038/D-040
  amended; older progress-log entries below describe the proxy as it was.
- **Verified**: ran the new `docker-compose.prod.yml` for real (local
  image): missing `TRUSTED_PROXY_IPS` refuses to start; app/worker healthy;
  only `app` published; health 204 on `APP_PORT`. Forwarded-header trust
  tested end to end through a real sign-in: a forged `X-Forwarded-For` from
  an untrusted peer was ignored (audit log: real peer IP), and the same
  header from a peer listed in `TRUSTED_PROXY_IPS` was honoured. CI's
  compose step passes as written; `actionlint` clean; 594 tests pass;
  `ruff`/`mypy --strict` clean. Test stack and volumes removed.

### 2026-10-01 — Production deployment option without the bundled proxy
- **On request** ("a production deployment option without proxy ... use an
  enterprise WAF or proxy"): new `docker-compose.prod.no-proxy.yml`, a
  second self-contained production file alongside `docker-compose.prod.yml`
  (same rationale as D-038) — same hardening (read-only root fs, dropped
  capabilities, resource limits, internal `backend` network, one-shot
  `migrate`), minus the bundled nginx `proxy`; `app` publishes its own port
  directly instead. New `.env.production.no-proxy.example`. D-040.
- **The one real design decision**: `FORWARDED_ALLOW_IPS` can no longer be
  `*`. That default is safe in the bundled-proxy file only because nothing
  but the proxy container can ever reach `app`; here `app`'s port is
  directly reachable, so trusting every peer would let anyone forge
  `X-Forwarded-For`/`-Proto` and corrupt the audit log or fake HTTPS over
  plain HTTP. New required compose variable `TRUSTED_PROXY_IPS` (no `*`
  default, no CIDR — literal WAF/proxy address(es) only) closes that gap;
  the operator's firewall is still responsible for keeping the port
  unreachable from anywhere else, documented as such since the stack can't
  enforce it.
- Considered and rejected: Compose `profiles:` to make the existing
  `proxy` service opt-in (would silently drop an already-deployed host's
  proxy — and its only published port — on the next `up -d` after
  upgrading, with no loud failure); an overlay on `docker-compose.prod.yml`
  (Compose has no way to merge-delete a service). See D-040 for both.
- `scripts/https-setup.sh` (TLS-proxy-only) now refuses to run against the
  no-proxy file's `.env` with a message pointing at deployment.md §1b,
  rather than silently doing something meaningless to it; `--help` still
  works regardless of `COMPOSE_FILE`.
- Docs: docs/deployment.md new §1b (topology, prerequisites, install,
  troubleshooting rows); docs/operations.md (file/containers/configuration
  tables, §7 HTTPS intro); docs/architecture.md (production topology
  mention, a new threat-model row for the forwarded-header trust boundary).
- **Verified**: `docker compose config` resolves cleanly against the new
  file with synthetic secrets; `TRUSTED_PROXY_IPS` fails fast with a clear
  message when unset, matching every other required production secret;
  confirmed the existing bundled-proxy file's `https-setup.sh` behaviour is
  unchanged, and the new guard fires correctly for the no-proxy file while
  leaving `--help` usable. **Not verified**: a real deployment behind an
  actual enterprise WAF — none was available to test against; recheck the
  forwarded-header contract against whichever product is actually used
  before go-live.

### 2026-09-29 — CI mypy failure: SQLAlchemy 2.1 pulled in by an unbounded range
- First CI run failed `mypy` with 17 errors not seen locally. Reproduced in a
  clean `python:3.13` container: fresh installs resolve SQLAlchemy **2.1.1**
  (local had 2.0.52), whose new `Select`/`Row` typing breaks
  `core/services/advisories.py` and `iocs.py`; and `types-defusedxml` was
  only ever installed locally by hand.
- Fixed: `sqlalchemy>=2.0.36,<2.1`; `types-defusedxml` in the `dev` extra.
  Images built from the unbounded range were also running untested on 2.1 —
  the pin covers them too. Porting to 2.1 left as a deliberate follow-up.
  D-039.
- **Verified**: clean-container `mypy` clean (SQLAlchemy 2.0.54); 594 tests
  pass locally; `ruff` clean.
- **Next**: a lock file for CI and the Dockerfile — every other dependency
  still floats the same way.

### 2026-09-29 — Production compose file; worker pollers no longer die at start-up
- **On request**: `docker-compose.prod.yml` — self-contained production
  stack. HTTPS-only proxy as the sole published service; Postgres/Redis on
  an internal network; one-shot `migrate` service; required secrets and
  pinned `IMAGE_TAG` with no defaults; read-only root fs, `cap_drop: ALL`,
  `no-new-privileges`, resource limits, log rotation. New
  `.env.production.example` and **`docs/deployment.md`** (install, upgrade,
  rollback, troubleshooting). D-038. `scripts/https-setup.sh` recognises the
  production file and won't switch it to the overlay or `disable` it.
- **Real bug, pre-existing, found by running the production stack**: the
  worker's three poller threads each did the *first* import of
  `core.models` concurrently; the import raced and the **inbox and
  inventory-sync pollers died on start-up** (14/15 fresh interpreters),
  while the worker still reported healthy — so dropped emails were never
  auto-ingested. Fixed by `_preload_poller_dependencies()` on the main
  thread before the pollers start, and by moving each loop's imports inside
  its `try` so a failure is retried, not fatal. `tests/test_worker_startup.py`
  (fresh-interpreter tests; failed before the fix).
- **Real bug, pre-existing**: `docker-compose.yml` passed only a subset of
  variables to the containers — `VT_API_KEY`, `PDF_*`, `CSV_*`, poll
  intervals, `FERNET_KEY_PREVIOUS` set in `.env` did nothing. Now
  `env_file: .env` in every compose file.
- **Also**: the worker's inherited image HEALTHCHECK probed a port it
  doesn't serve (always unhealthy); the production file checks
  `cli check` instead. Tested that a failed migration during a plain
  `up -d` takes the site down, so upgrades run `run --rm migrate` first.
  Stale docs corrected: a `scheduler` container that never existed,
  README status ("implementation not started"), Tailwind/Python 3.14 in the
  stack line.
- **Verified**: 594 tests passing; `ruff`/`mypy --strict` clean. Ran the
  production file for real (local images, proxy excluded — no
  certificate): migrate → app/worker healthy in 8 s; a real advisory
  auto-ingested by the inbox poller with PDF extraction under read-only +
  no capabilities; postgres has no internet route, worker/app do; only the
  proxy publishes ports; `.env` values reach the containers; missing-secret
  guards fire. Test stack and volumes removed afterward.

### 2026-09-29 — CI publishes images to Docker Hub; compose pulls them
- **On request**: CI's `images` job (after `lint` + `test`) builds and
  pushes `<namespace>/advisory-hub` (app + worker, one image) and
  `<namespace>/advisory-hub-proxy` (nginx with the HTTPS site config baked
  in — new `docker/nginx/Dockerfile`). Pushes on `main` (`latest`, `main`,
  `sha-…`) and `v*` tags (`X.Y.Z`, `X.Y`); PRs build without pushing.
  Multi-arch, SBOM + provenance. docs/operations.md §8, D-037.
- `docker-compose.yml` / `docker-compose.https.yml` now reference images
  via `IMAGE_NAMESPACE`/`IMAGE_TAG` and never build; the dev override
  builds locally (`pull_policy: build`). Unset namespace → `localhost/…`,
  so a misconfigured host fails to pull rather than pulling a stranger's
  image. New `make images`.
- **Needs from the user**: `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`
  secrets (and optionally `DOCKERHUB_NAMESPACE` variable) on the GitHub
  repo; `IMAGE_NAMESPACE` in each host's `.env`.
- **Verified**: `actionlint` clean; compose resolves correctly in dev,
  production and production + HTTPS; both images build locally; proxy
  image renders its template; dev stack boots. **Not verified**: a real CI
  run/push (secrets not set yet).

### 2026-09-29 — Bug fix: empty values rendered as a literal "&mdash;"
- Every "no value" placeholder written as `{{ x or '&mdash;' }}` (21 places
  in 7 templates: advisory detail, scan panel, inventory list/detail, CSV
  preview, Affected Software, tracker) showed the text `&mdash;` in the
  browser. Jinja autoescapes string literals too, so the entity became
  `&amp;mdash;`. Now the character itself (`'—'`); no `| safe` needed.
- New `tests/test_templates.py`: renders `_inventory_detail.html` through
  the app's own Jinja environment, and scans every template for an HTML
  entity inside a `{{ }}`/`{% %}` string literal so the pattern can't come
  back. Both failed before the fix.
- **Verified**: 592 tests passing; `ruff` and `mypy --strict` clean.

### 2026-09-29 — Mediclinic light/dark theme
- **On request** ("dark and light theme according to Mediclinic design and
  colour language"): palette read from mediclinic.ae's own stylesheet, not
  approximated. Brand blue `#0094D4` fails AA as text (3.4:1), so it
  carries non-text accents only; links/buttons use Mediclinic's `#0072A3`.
  Dark theme is navy-based. Tokens are CSS `light-dark()` pairs — follows
  the OS by default; a header toggle (also on the sign-in page) pins
  System/Light/Dark per browser. Status/severity badges stay semantic, not
  branded. docs/architecture.md §3.3.2, D-036.
- **Fixed while verifying**: the tracker's "No comments yet" placeholder
  used the border colour as text (~1.3:1, effectively invisible).
- **Verified**: 590 tests passing. Real tracker/IOC/detail/sign-in pages
  rendered against the dev corpus in headless Chromium in both themes.
  `ah-test` no longer exists on disk, so it was not redeployed.

### 2026-09-29 — HTTPS deployment option
- **On request** ("HTTPS option … don't generate any certificates now …
  create a script I can use during deployment"): new overlay
  `docker-compose.https.yml` adds an nginx `proxy` that terminates TLS
  (1.2/1.3, HSTS, HTTP→HTTPS redirect) and stops publishing `app`'s plain
  port. `scripts/https-setup.sh` (`install`/`csr`/`self-signed`/`check`/
  `enable`/`disable`) validates a certificate (parses, key matches, not
  expired, covers `SERVER_NAME`, optional chain check), installs it into
  git-ignored `certs/`, and writes `COMPOSE_FILE` etc. into `.env`. **No
  certificate was generated.** docs/operations.md §7, D-035.
- Side benefit: with the overlay, uvicorn trusts `X-Forwarded-For`
  (`FORWARDED_ALLOW_IPS`), so sessions/audit record the real client IP,
  not the proxy's — safe only because `app` is no longer published.
- **Verified**: overlay renders via `docker compose config`; nginx template
  renders and parses up to the (absent) cert; script's error paths and
  `.env` editing exercised on a scratch `.env`. **Not verified**: an actual
  TLS handshake — needs a certificate, deliberately not created.

### 2026-08-26 — IOC-type indicator on the tracker, and sorting by IOC mix
- **New, on request** ("sort the advisories based [on] the number of
  different kind of IOCs in them ... add indicator for the types of IOCs"):
  the tracker's existing "N IOCs" badge now carries a chip per distinct
  kind of indicator beside it (`Domain` `MD5` `IP` `SHA256`), and the
  filter bar gained a sort picker offering **Most/Fewest IOC types** and
  **Most/Fewest IOCs** alongside date and severity.
- **The two IOC sorts rank differently, deliberately.** Against the real
  corpus, "Most IOC types" tops out at an advisory with 38 indicators
  across 4 kinds, while "Most IOCs" tops out at a different one with 72
  across 3. Kind count predicts *effort* (four kinds is four separate
  controls to touch); raw total predicts *volume*. Offering only one would
  have answered only half the question. Documented as a table in
  docs/architecture.md §3.3.1.
- `core.services.advisories.ioc_counts_for()` (a flat `dict[UUID, int]`)
  is **replaced** by `ioc_breakdowns_for()` returning an `IocBreakdown`
  (`counts` per `IocType`, plus `total`/`type_count`/`by_count`) — still
  one batched query for a page, now grouped by `(advisory_id, ioc_type)`
  instead of `advisory_id` alone. `by_count` orders most-numerous-first
  with alphabetical tie-breaking so chip order is stable between renders.
- Sorting is a `LEFT JOIN` against a `GROUP BY advisory_id` aggregate over
  `advisory_ioc`, ordered on `COALESCE(…, 0)`. Three things that had to be
  right and are covered by tests: a **left** join (an inner one would drop
  every advisory with no IOCs — the large majority), `COALESCE` (Postgres
  sorts `NULL` *first* on `DESC`, so IOC-free advisories would have led the
  "most IOCs" page), and the aggregate being pre-grouped (an ungrouped join
  would fan one advisory out to one row per indicator, breaking pagination).
- Sort keys are validated through `normalise_sort()` against a fixed
  `SORT_OPTIONS` table — an unknown or hostile `?sort=` value falls back to
  the default and never reaches SQL as anything but a dict lookup.
- No new REST API surface: `GET /api/v1/advisories` uses keyset pagination
  keyed on `(received_at, id)`, which a non-`received_at` sort order can't
  be layered onto without a different cursor encoding. Left as a separate
  piece of work rather than half-done.
- **One defect caught in rendering, not by a test**: the chip tooltips were
  built with Jinja's `| title` filter, which renders `MD5`/`IPV4`/`SHA256`
  as `Md5`/`Ipv4`/`Sha256`. Replaced with an explicit
  `IOC_TYPE_LABELS` mapping in `_macros.html` holding both the short chip
  label and the full name, so the two can't drift.
- **Verified**: 590 tests passing project-wide (17 new — `ioc_breakdowns_for`
  incl. per-type counts, stable ordering and batch isolation; both IOC sorts
  incl. the no-IOC, no-duplicate-rows, tie-break and filters-still-apply
  cases; `normalise_sort()` rejection). `ruff` and `mypy --strict` clean.
  Rendered end-to-end against the real dev corpus through `TestClient` —
  every sort key 200s and keeps its selection, the two IOC sorts produce
  genuinely different orders from each other and from the default, a bogus
  `?sort=` falls back, and the HTMX partial path renders the chips too. The
  real corpus maxes out at 4 distinct kinds, so the `+N` overflow chip and
  the singular "1 indicator across 1 type" wording were verified separately
  by rendering the macro against synthetic breakdowns. The verification
  session rows were removed from the dev database afterward.

### 2026-08-24 — "Scan inbox now" button on the tracker page
- **New, on request** ("a scan button to trigger a job to scan the emails
  from the directory"): `POST /inbox/scan` (ANALYST+) calls the existing
  `ingest.pipeline.process_inbox()` synchronously — the same function the
  worker's background poller and `advisory-hub watch` already call — so an
  analyst can pull in whatever's sitting in the watched inbox directory
  right now instead of waiting for the next poll interval
  (`INBOX_POLL_SECONDS`).
- **No new ingestion logic** — this is a thin trigger over an
  already-implemented, already-tested pipeline (Phase 1a). Safe to run
  concurrently with the background poller: `Inbox.claim()`'s atomic rename
  (the same mechanism that already makes multiple workers safe) means only
  one caller ever wins a given file, so a manual scan and the poller
  racing on the same inbox can't double-ingest.
- Outcome (ingested/duplicate/failed counts) is carried across the
  `HX-Redirect` as query params and rendered as a one-time notice banner on
  reload — chosen over a full inline result panel because ingesting new
  advisories changes the dashboard KPI tiles and the tracker table too, and
  a full-page reload (matching `change_advisory_status`'s existing
  `HX-Refresh` pattern) is the simplest way to keep everything consistent.
- **Verified**: 573 tests passing project-wide (no new service-layer tests
  needed — `process_inbox()` itself already has full pipeline coverage from
  Phase 1a; this route only wires an existing, tested function to a
  button). `ruff` and `mypy --strict` clean.

### 2026-08-24 — IOC CSV export, and a lightweight "Refresh" reload on Affected Software / IOCs
- **New, on request**: a CSV export on the IOC tab (`GET /iocs/export`) that
  includes every VirusTotal result field alongside each indicator's
  defanged value — honours whatever filters (type/status/search) are
  currently applied to the tab, not just the visible page, so an analyst
  can hand a filtered subset to someone without UI access. `core.services.iocs.list_all_iocs()`
  is the unpaginated counterpart to `list_iocs()`, sharing the same
  `_matching_rows()` filtering helper so the export and the on-screen table
  can never drift out of sync with each other.
- **New, on request**: a plain "Refresh" button on both `/affected-software`
  and `/iocs` that just reloads the current view (an HTMX `GET` against the
  same route, no side effects) — distinct from "Refresh all (re-scan)"
  (ANALYST-only, actually re-runs every scan) and "Check on VirusTotal"
  (queues jobs). Useful specifically because both bulk VT checks and
  inventory scans complete asynchronously in the background; "Refresh" is
  how an analyst picks up results without an ad hoc browser reload.
- Export deliberately never includes the raw IOC value, only
  `defanged_value` — the same never-render-a-clickable-indicator discipline
  the rest of the UI already follows (CLAUDE.md §2.3).
- **Verified**: 573 tests passing project-wide (3 new for `list_all_iocs()`
  — unpaginated, same filters as `list_iocs()`, defaults to everything with
  no filter). `ruff` and `mypy --strict` clean.

### 2026-08-23 — Affected Software tab, IOC tab, and rate-limited bulk VirusTotal checks
- **New feature, not on the roadmap** — added on request: an "Affected
  Software" tab (Product · Version · Affected hosts · Severity · Advisory ·
  Status, plus a "Refresh all" scan action) and an "IOC" tab (every
  indicator across every advisory, a remediation status, and a multi-select
  bulk VirusTotal check). See D-034.
- New: `IocRemediationStatus` enum (`DUE`/`BLOCKED`/`IN_PROGRESS`/`RESOLVED`)
  and `AdvisoryIoc.remediation_status` (nullable — migration `65629d602d24`),
  `core/services/iocs.py` (`effective_status()`, `list_iocs()`,
  `set_remediation_status()`), `core.services.scan.list_affected_software()`
  / `refresh_all_scans()`, `core.services.vt_lookup.enqueue_bulk_check()`,
  `worker/jobs.py` (`check_ioc_job`, a Redis sorted-set sliding-window rate
  limiter shared across queued jobs — an in-memory limiter can't work here
  since RQ forks a fresh process per job), new `vt_check` RQ queue, web
  routes/templates for `/affected-software` and `/iocs`, plus a remediation-
  status column wired into the existing advisory detail page's IOC table
  (same column, same service function, so an override made in either place
  is immediately visible in the other).
- **IOC status is a nullable override, not a synced copy** — defaults to
  tracking the parent advisory's own status via a fixed
  `ADVISORY_STATUS_TO_IOC_STATUS` mapping, overridable per indicator. Asked
  the user directly whether a fourth terminal state was needed beyond the
  three named in the request (due/blocked/in progress); confirmed adding
  `RESOLVED` for closed/remediated advisories.
- **Bulk VirusTotal checks are queued, never synchronous** — the user was
  explicit that the deployment uses a free-tier VT API key and the rate
  limit must be respected. A multi-select posts once and returns
  immediately; each selected IOC becomes one RQ job that blocks on a
  Redis-backed rate-limit slot before calling VT, so a whole batch drains
  at the same pace a single interactive check already respects.
- **Two Alembic/enum quirks, the second new this session**: (1) the
  already-known D-023 pattern (explicit `DROP TYPE IF EXISTS` in
  `downgrade()`); (2) `op.add_column()` with a plain `sa.Enum(...)` does
  *not* implicitly `CREATE TYPE` the way `op.create_table()` does —
  confirmed against the dev database, fixed by creating the type
  explicitly first and referencing it with `create_type=False`.
- **Verified**: 570 tests passing project-wide (14 new for
  `core.services.iocs`, 4 for `enqueue_bulk_check()`, extended
  `test_scan_service.py` for the two new scan-service functions incl. a
  refresh using currently-active snapshots rather than a scan's original
  ones, and one advisory's failure not blocking another's refresh).
  `ruff` and `mypy --strict` clean. Manually verified end-to-end against
  the real `ah-test` deployment: both tabs render against the real
  227-IOC/135-advisory corpus, a per-IOC status override set on the IOC tab
  correctly showed as "overridden" on the same advisory's detail page, and
  a real 3-IOC bulk VT-check batch queued through the web UI drained
  through the actual worker container against a real configured VT key,
  with results landing back in the table afterward.

### 2026-08-22 — Structured version-range parsing + text-derived scan matching
- **New feature, not on the roadmap** — added on request ("parse the
  affected version and fixed version, look for the affected version in
  the inventory"). Closes the gap Phase 2d's `inventory.matcher` module
  docstring explicitly deferred: `AdvisoryProduct.version_expression` was
  extracted verbatim since Phase 1a but never turned into anything a scan
  could compare against.
- New: `ingest/version_range.py` (`parse_version_range()` — comparator
  patterns `< X`/`<= X`/`>= X`/`> X`, word patterns "below/prior to/X and
  earlier/X and later", anchored and unanchored simple ranges, bare exact
  versions; honestly returns `None` for anything ambiguous: semicolons,
  comma-separated discrete lists, more than one comparator clause, pure
  prose). Wired into `ingest/parser.py` right after products are
  extracted; `PARSER_VERSION` bumped `1` → `2` so `reparse` backfills
  every already-ingested advisory. See D-032.
- **Deliberately conservative, measured against the real corpus**: only
  28% of `version_expression` rows (35/124) parse into a clean structured
  range. That's the intended outcome, not a shortfall — the other 72% is
  genuinely ambiguous real-world text, and guessing at it would violate
  CLAUDE.md §2.2 ("evidence, not truth").
- `core.services.scan._affected_specs()` now also builds `AffectedSpec`s
  from `AdvisoryProduct.parsed_range` (`inventory.matcher.AffectedSpec.text_derived
  = True`), alongside the existing NVD CPE specs — both are matched in the
  same scan. Every text-derived match is capped at `POSSIBLE` confidence
  regardless of match quality, and `cve_id` is always `None` (a product
  claim isn't attributed to one specific CVE in a multi-CVE advisory) —
  `scan_match.cve_id` was already `nullable=True` for exactly this case
  since Phase 2a.
- **Two real bugs found by the parser's own test suite, not by
  inspection**: (1) a "Versions X - Y" pattern with a leading word failed
  the original whole-clause-length heuristic (the word itself ate the
  length budget) — fixed with a `versions?/builds?/releases?`-anchored
  pattern, mirroring the already-proven anchor `ingest/patterns.py` uses.
  (2) A string with two separate comparator clauses for two product
  variants was silently resolved to the first one — fixed by rejecting
  outright when more than one comparator match is found, not picking a
  winner.
- **Verified**: 34 new parser unit tests (every trusted pattern, plus
  explicit non-match cases for the ambiguous majority — synthetic but
  real-shaped, since the actual corpus is restricted and never committed),
  4 new scan-service integration tests (text-derived match found and
  capped at `POSSIBLE`, out-of-range claim correctly excluded, an
  unparsed claim contributes no spec, NVD and text-derived matches coexist
  in one scan). All existing matcher/scan tests still pass unchanged.
- **Real bug #2, found only by inspecting the real `ah-test` corpus at the
  SQL level after backfilling via `reparse`, not by any unit test**:
  `AdvisoryProduct.parsed_range` was storing an unparsed claim's Python
  `None` as a literal JSON `null` (`'null'::jsonb`), not a true SQL
  `NULL` — a SQLAlchemy `JSONB` default-behavior pitfall. Every unit test
  read the value back through the ORM, which silently deserialises JSON
  `null` to Python `None` and never exposed it; only a direct
  `SELECT ... WHERE parsed_range IS NOT NULL` against the real 253-row
  corpus did (it wrongly matched all 253, not the real 35). Fixed with
  `JSONB(none_as_null=True)` plus a data-fix migration (`2d99ec3309e7`)
  converting every already-stored bad literal. See D-033.

### 2026-08-22 — Admin panel: GUI configuration for NVD and VirusTotal
- **New feature, not on the roadmap** — added on request ("GUI configuration
  for all API integrations"), scoped to NVD + VirusTotal after confirming
  with the user: Desktop Central/Azure ARM/MS Graph already have full GUI
  management under the Inventory tab, so folding that in too would have
  been a reorganization, not new capability. See D-031.
- New: `core/models/system.py` (`SystemIntegration` — a singleton, at most
  one row per `SystemIntegrationKind`, reusing `integration_credential`/
  Fernet encryption rather than a new mechanism), `core/services/system_integrations.py`
  (`resolve_credential()` — admin-panel key beats env var beats nothing;
  explicit `enabled=False` overrides the env var too), `web/admin.py` +
  `admin_index.html` (new `/admin` nav tab, ADMIN role, per-integration
  enable toggle and write-only "set/rotate key" form — the key is never
  displayed back after saving). Migration `67293c94f22d`.
- **Resolved fresh on every call, no restart needed** — `core.services.enrichment.enrich_pending()`
  and `core.services.vt_lookup.check_ioc()` both call `resolve_credential()`
  instead of reading `settings.nvd_*`/`settings.vt_*` directly. The
  worker's enrichment poller had its own `if settings.nvd_enabled:` gate
  removed for the same reason — gating there too would make an admin-panel
  "enable" silently ineffective until the worker process restarted.
- **Ordering fix in `vt_lookup.check_ioc()`**: the new `enabled` check was
  initially placed before the cache-freshness check, which would have made
  an already-cached result inaccessible the moment VT was disabled —
  caught before it shipped, not by a test. Reordered so disabling only
  blocks *new* lookups; reads of a still-fresh cached result are
  unaffected.
- **Also fixed while investigating a separate report that "IOCs aren't
  displaying" in `ah-test`**: turned out to be correct behavior, not a bug
  — only 11 of the real 135-message corpus's advisories carry any IOCs, so
  most correctly show nothing. Added a small discoverability fix anyway:
  an IOC-count badge in the tracker table (`core.services.advisories.ioc_counts_for()`,
  one batched query, same pattern as `last_comments_for()`) so it's visible
  before clicking into an advisory.
- **Verified**: 12 new service tests (resolution precedence — env fallback,
  admin-panel override, explicit-disable-wins, re-enable-without-a-key
  falls back to env), manually verified end-to-end against the real dev
  database (set a key, saw "Set here"; toggled off, saw "Disabled";
  confirmed the IOC badges render with correct counts on the tracker page).
  507 tests passing project-wide; `ruff` and `mypy --strict` clean.

### 2026-08-22 — VirusTotal IOC reputation checks
- **New feature, not on the original roadmap** — added on request. IOC
  parsing/display already existed (Phase 1a); this adds an analyst-
  triggered "Check on VirusTotal" action per indicator.
- New: `enrich/virustotal.py` (VT API v3 client — IP/domain/URL/hash
  lookups, reuses `enrich.nvd.RateLimiter`, `x-apikey` auth, 404→not-found),
  `core/services/vt_lookup.py` (`check_ioc()` — cache-first with a
  staleness window per outcome, `cached_lookups_for()` for N+1-free table
  rendering), `core/models/advisory.VtLookup` (new `vt_lookup` table,
  migration `cdd4c6b91707`), `api/routers/iocs.py`
  (`POST /iocs/{ioc_id}/check-vt`), web route + `_vt_result.html` partial
  wired into the IOC table on the advisory detail page.
- **Deliberately never an automatic sweep, unlike NVD** — VT's public tier
  is 4 requests/minute; the real corpus alone has 227 IOCs. See D-030.
  Cached globally by `(ioc_type, value)`, not per `advisory_ioc` row, so
  the same indicator across multiple advisories shares one check.
- **The raw IOC value never crosses the API** — callers pass an
  `AdvisoryIoc` id, never a value; `VtLookupOut` has no `value` field,
  matching `IocOut`'s existing defanging discipline. `permalink` safely
  embeds the value inside VT's own trusted report URL.
- **Two real bugs found, both by tests, not inspection**: (1) a migration
  bug — autogenerate's `sa.Enum(..., create_type=False)` did not actually
  suppress `CREATE TYPE` for the two reused enum types (`ioctype_enum`,
  `enrichmentstatus_enum`) in this SQLAlchemy version; fixed by using
  `postgresql.ENUM(..., create_type=False)` explicitly instead, verified
  directly against the dev database before trusting it. (2)
  `VtUnauthorizedError` subclasses `VtError`, so `check_ioc()`'s original
  `except (VtError, ...)` clause silently caught it too, persisting a
  misleading `ERROR` cache row for what was actually a missing/bad
  `VT_API_KEY`, not a per-lookup failure — fixed with an explicit
  `except VtUnauthorizedError: raise` before the broader catch.
- New env vars `VT_API_KEY`/`VT_ENABLED` (`.env.example`,
  docs/operations.md) — unset key leaves the check action visible but
  returns a clear "not configured" error rather than hiding it.
- **Verified**: 47 new tests (VT client against `httpx.MockTransport`,
  service-layer caching/staleness/error-handling, REST API auth/scope/
  error-mapping). 495 tests passing project-wide; `ruff` and
  `mypy --strict` clean.

### 2026-08-22 — Bug fix: cross-device inbox claim (`INBOX_HOST_PATH`)
- Added `INBOX_HOST_PATH` (docker-compose.yml) earlier the same day to let
  the watched inbox bind-mount a real host folder instead of the internal
  named volume. Verifying it against a real 135-message corpus dropped
  into a real folder in the `ah-test` environment found it was completely
  broken: `Inbox.claim()`'s plain `os.rename()` can't cross a filesystem
  boundary, and the resulting `OSError` was being swallowed as "another
  worker won" — nothing was ever claimed, archived, or logged, for as long
  as the worker ran.
- Fixed in `ingest/watcher.py`: `claim()` now falls back, on `EXDEV`, to a
  same-filesystem claim-in-place (rename within `inbox/` into
  `inbox/.claiming/<worker_id>/`) followed by a cross-device copy into
  `processing/`. `recover_orphans()` now sweeps that staging directory too.
  See D-029.
- 3 new regression tests in `tests/test_ingest_pipeline.py` (fallback
  claims correctly, stays exclusive across the fallback, orphans recover
  from the staging dir). Full suite green, `ruff`/`mypy --strict` clean.

### 2026-08-22 — Phase 2e complete (scan from advisory)
- **"Scan inventory" is now a real button on the advisory detail page**,
  plus the equivalent REST API — the last piece of Phase 2, sitting
  entirely on top of Phase 2d's already-complete `core.services.scan.run_scan()`.
- **Deliberately synchronous, not a background job** — diverging from the
  original design's "background `scan_run`; panel polls" sketch, for the
  same reason the inventory "Sync now" button already is: there's no job
  queue behind `run_scan()`, and matching completes in well under a second
  against every real snapshot this project has scanned. The web panel's
  `POST` gets the finished result in one request/response cycle and swaps
  it in via HTMX; no polling. Revisit if a real deployment's inventory size
  ever makes that stop being true.
- New: `advisory_hub/api/routers/scans.py` (`POST /advisories/{id}/scan`,
  `GET /scans/{run_id}`, `GET /advisories/{id}/scans`, all under `scan:run`),
  `_scan_panel.html` + routes in `web/tracker.py`
  (`GET .../scan-panel`, `POST .../scan`). `core.services.scan` gained
  `scan_history()`, `get_scan_run()`, and `coverage_gaps()` — the last
  computed on demand rather than persisted (no `scan_run`/`scan_match`
  column for it, and recomputation is cheap). `core.services.inventory`
  gained `latest_snapshots()` for the source-selection checkbox list.
- **Device drill-down for `DETAILED` sources deliberately not built** — no
  `DETAILED`-mode source has real device-identifier data ingested yet to
  develop it against; `ScanMatch.device_ids` is already populated by the
  matcher, just not read by anything in the UI yet.
- **Two real bugs found while wiring this up, not by inspection**: (1)
  `core.services.scan.AdvisoryNotFoundError` is a distinct class from
  `core.services.advisories.AdvisoryNotFoundError` despite the identical
  name — FastAPI's exception-handler registry matches by exact type, so
  the existing advisories handler would silently never have fired for a
  scan route's 404; fixed with the scan module's own handler registration.
  (2) `scan_history()`'s `ORDER BY created_at DESC` was non-deterministic
  for two scans in the same transaction — Postgres's `now()` (what
  `created_at`'s `server_default` uses) is transaction-scoped and returns
  the identical value for every row in one transaction; fixed by ordering
  on `started_at`, a Python-side `utcnow()` call made fresh per `run_scan()`
  invocation. See D-028.
- **Verified against the real dev database**: logged in as a real session
  user, opened the real DOH-2026539 advisory, triggered a scan through the
  actual HTML form against a temporary vulnerable-version 7-Zip snapshot,
  and confirmed the rendered result — `POSSIBLE` confidence, "open-ended
  range with no lower bound, manual check advised" (NVD's CVE-2026-14266
  CPE row has no `version_start`) — matched the service layer exactly;
  confirmed a VIEWER-role session can read the panel but gets `403`
  attempting to trigger a scan. All temporary verification data (including
  a leftover `ScanRun` row from Phase 2d's own real-data verification) was
  removed from the dev database afterward.
- **Verified**: 17 new tests (scan-service `scan_history()`/`get_scan_run()`/
  `coverage_gaps()`, REST API auth/trigger/get/history). 448 tests passing
  project-wide; `ruff` and `mypy --strict` clean.
- **Phase 2 is now fully complete** (2a inventory sources → 2b CSV ingest →
  2c API integrations → 2d normalisation/matching → 2e scan from advisory).
  Next: Phase 3 (API surface, MCP, and reporting) per `docs/roadmap.md`.

### 2026-08-22 — Phase 2d complete (normalisation and matching)
- **Grounded against two real inventory exports the user placed in
  `Inventory/`** — an Endpoint Central "Software Summary" CSV (11,481 rows)
  and a Lansweeper "web50" CSV (6,749 rows) — not synthetic fixtures.
  Ingesting them corrected both CSV column profiles (real headers differed
  from the Phase 2b design guess) and revealed a second OS-row-detection
  convention distinct from Azure's: `ColumnProfile` gained
  `os_indicator_value: str | None` so Endpoint Central's "`Software Type`
  column equals `Operating System` exactly, reusing the regular
  product/version columns" convention sits alongside Azure's existing
  "any non-blank value, separate os-name/os-version columns" one. Also
  added CSV delimiter auto-detection (`csv.Sniffer`) — the real Lansweeper
  export is semicolon-delimited, which the Phase 2b parser hadn't handled.
- New: `advisory_hub/inventory/normalise.py` (`normalise_vendor()`/
  `normalise_product()`, ~60-entry seed alias list), `advisory_hub/core/services/vendor_alias.py`
  (`seed_vendor_aliases()`, `load_vendor_alias_map()` — one query, loaded
  once per operation), `advisory_hub/inventory/version.py` extended with a
  real tiered comparator (`compare_versions()`/`version_in_range()`: PEP
  440 first via `packaging.version`, zero-padded numeric-tuple fallback,
  honest `None` when neither tier is confident), `advisory_hub/inventory/matcher.py`
  (pure `match_candidates()` — `CONFIRMED`/`LIKELY`/`POSSIBLE` with a
  plain-English rationale per match), `advisory_hub/core/services/scan.py`
  (`run_scan()` — synchronous, persists `scan_run`/`scan_match`, filters
  `CveCpe.vulnerable`, spans multiple snapshots per scan). `sync_source()`
  and `commit_csv_snapshot()` now call the real normalisation functions,
  replacing the Phase 2b/2c "lowercase-trim only" documented placeholder.
- **Only NVD CPE data is matched against** — `AdvisoryProduct.version_expression`
  (PDF-parsed free text) has no structured range to compare against
  (`parsed_range` is a reserved column nothing in `ingest/` populates —
  confirmed by grep), and matching ungrounded free text would be guessing,
  not evidence, per §2.2. Every match is therefore NVD-CPE-sourced.
- **Two real bugs found and fixed, both only by running the real files
  through the actual pipeline, not by inspection**: (1) a corrupted
  195-digit version string on a real "Asure ID" row overflowed the int32
  `inventory_software.version_parts` column — fixed with an explicit
  magnitude bound in `normalise_version()`, see D-026; (2) a genuinely
  bizarre 245-character Microsoft-Store "app name" overflowed
  `vendor`/`product`'s `VARCHAR(200)`, which turned out to be a systematic
  doc-vs-code mismatch across 9 columns on 4 tables — `docs/data-model.md`
  had always specified unbounded `text`, but the Phase 2a models used
  `String(200)`. Fixed by widening all 9 to `Text` in migration
  `c4ccff4d5c82`, verified with a full `downgrade base` → `upgrade head`
  cycle on the disposable test database. See D-027.
- **Real-data end-to-end verification**: cross-referencing the newly-
  ingested inventory against the already-enriched Phase 1 corpus found
  exactly one genuine overlap — 7-Zip, tying together a real advisory
  (DOH-2026539), a real NVD CPE range (CVE-2026-14266, `< 26.02`), and a
  real installed row (version `26.02` exactly, one device, across two real
  snapshots simultaneously). Running `run_scan()` against both real
  snapshots at once returned `match_count == 0` — the correct answer: the
  installed version sits exactly on the range's exclusive upper bound,
  i.e. it's the patched release, confirming the comparator handles a real
  boundary case without an off-by-one false positive. The two verification-
  only `InventorySource` rows and their cascaded data were removed from the
  dev database afterward.
- **Verified**: 48 new tests (version comparator incl. the int32-overflow
  regression, normalisation, matcher — including two self-caught test-
  authoring mistakes fixed before they ever reached a passing state, not
  matcher bugs — vendor-alias service, scan service incl. the
  vulnerable-filter and multi-snapshot attribution). 441 tests passing
  project-wide; `ruff` and `mypy --strict` clean.
- Deliberately deferred to 2e, per the roadmap's own phase split: the
  "Scan inventory" button and any route/UI calling `run_scan()` at all —
  the engine is complete and callable, but nothing calls it yet. The
  future caller must commit the flushed `FAILED` state on the exception
  path before/instead of letting it propagate uncaught — the same D-024
  pattern `sync_source()` established in Phase 2c — documented in
  `scan.py`'s module docstring for whoever writes that route.

### 2026-08-22 — Phase 2c complete (API integrations)
- **`test_connection()` and inventory sync are real now** — the 2a stub
  ("connectivity check not implemented yet") is gone; API-kind sources
  actually talk to their vendor now.
- New: `advisory_hub/inventory/api_client.py` (SSRF-validated-before-every-
  call HTTP helpers, shared Entra OAuth2 client-credentials token fetch),
  `advisory_hub/inventory/adapters/` — a Protocol (`base.py`) plus three
  adapters (`azure_arm.py`, `ms_graph.py`, `desktop_central.py`) and a
  kind→adapter `registry.py`. `core/services/inventory.py` gained
  `sync_source()`: pulls the full inventory via the adapter, writes a
  `DETAILED` snapshot (`inventory_device` + `inventory_device_software` +
  the `inventory_software` aggregate view, same table CSV ingest populates),
  demotes the previous latest snapshot — all only on success. A failed
  fetch never touches `inventory_snapshot` at all.
- **Confidence is not uniform across the three adapters, and the docs say
  so explicitly.** Azure ARM and MS Graph are stable, versioned, publicly
  documented Microsoft APIs, tested against their documented
  request/response contract via `httpx.MockTransport`. Desktop Central's
  REST API shape varies across on-prem versions and the newer Endpoint
  Central Cloud product; no sandbox was available to validate against
  (unlike NVD in Phase 1b, which *was* checked against the live API), so
  that adapter is built from commonly documented ManageEngine conventions
  as a reviewed-but-unverified starting point — stated as such in its
  module docstring and in D-025, not presented with false confidence.
- Per-device software calls (`MS Graph.detectedApps`,
  `Desktop Central.installedSoftware`) are one call per device and capped
  at 500 — a fleet larger than that gets device rows for everyone but
  software only for the first 500, marked `SyncStatus.PARTIAL` with the
  reason recorded, never silently reported as complete.
- Scheduled sync is a worker background-thread poller (matching the
  existing inbox/enrichment pollers' pattern, not RQ jobs) —
  `_start_inventory_sync_poller()` checks `schedule_cron` via `croniter`
  every `INVENTORY_SYNC_POLL_SECONDS`. A source with no `schedule_cron` is
  never auto-synced.
- REST API: `POST .../sources/{id}/sync`. Web UI: a "Sync now" button next
  to "Test connection" on API-kind sources.
- **Real bug found and fixed**: `sync_source()` deliberately writes its own
  failure state (`last_sync_status=ERROR`, `last_sync_error`, an audit
  entry) via `db.flush()` before re-raising `ApiAdapterError` — but both
  the REST route and the web route originally let that exception propagate
  uncaught without ever calling `db.commit()`, so the failure record would
  have been silently rolled back on session close. The one thing an
  operator most needs after a failed sync — why it failed — would have
  vanished. Fixed in both routes; see D-024.
- **Verified**: 10 new adapter tests against mocked HTTP (pagination,
  OAuth token fetch, per-device-call failure isolation), 22 new
  service-layer tests (successful sync, cross-device aggregation into
  `inventory_software`, the failed-sync-preserves-latest-snapshot
  guarantee — checked at the DB level, not just asserted — partial-fetch
  handling), 5 new REST API tests, plus a manual end-to-end run against
  the real dev database with a mocked adapter (through both the API and
  the actual HTML "Sync now" button) confirming the exact device/software
  rows landed correctly and a simulated failure left the prior snapshot
  untouched. 380 tests passing project-wide; `ruff` and `mypy --strict`
  clean.
- Deliberately deferred to 2d: vendor-alias-backed canonicalisation and the
  tiered version comparator — `sync_source()` uses the same lowercase-trim
  placeholder and tier-1 version normalisation CSV ingest does.

### 2026-08-21 — Phase 2b complete (CSV inventory ingest)
- **First feature that actually populates inventory data** — 2a only
  managed sources. Upload flow: `POST .../csv/preview` (multipart) stores
  the file as a blob and parses it for review, writing nothing to
  `inventory_snapshot`/`inventory_software`; `POST .../csv/commit` re-reads
  that same blob by ID with the (possibly analyst-edited) mapping and
  commits. No server-side session state needed between the two requests —
  the blob ID and mapping travel as ordinary form/JSON fields.
- New: `advisory_hub/inventory/` package (distinct from
  `core/services/inventory.py`, mirroring the existing `ingest/` vs
  `core.services.ingestion` split) — `csv_profiles.py` (built-in column
  profiles for Desktop Central/Lansweeper/Azure, matching
  docs/inventory-matching.md §2 exactly, including Azure's OS-row
  detection), `csv_parser.py` (header sniffing, profile-based auto-mapping,
  per-row parsing with line-numbered errors), `version.py` (tier-1 numeric-
  tuple version normalisation — deliberately partial, see below).
  `core/services/inventory.py` gained `preview_csv()` and
  `commit_csv_snapshot()`; the latter aggregates rows sharing `(vendor,
  product, version, kind)` by summing `device_count`, so aggregated exports
  (a count column) and raw per-device exports (no count column) produce
  identical results, and flips the previous snapshot's `is_latest` off
  before inserting the new one — ordered correctly against the partial
  unique index (verified, not assumed).
- Web UI: CSV-kind sources' detail panel gained an "Upload inventory CSV"
  section — file picker → mapping-editor preview (editable `<select>`s,
  defaulting to auto-detected columns) with a live row preview and error
  table → "Confirm import" button.
- **Two deliberate simplifications, not oversights** — both noted in code
  and both actually Phase 2d's job: vendor/product canonicalisation is
  lowercase-trim only (the real `vendor_alias`-backed normalisation isn't
  needed until matching exists); version normalisation is tier 1 only
  (leading-digit-run extraction) — a version that doesn't yield a numeric
  tuple is honestly stored as `None`, never guessed. See
  docs/inventory-matching.md's "As built" note.
- **Verified**: 23 unit tests for the parser/normaliser (every row-error
  class, Azure OS-row detection, the row-count limit), 16 for the
  preview/commit service orchestration, 15 new REST API tests, plus a
  manual end-to-end run against the real dev database — through both the
  API and the actual HTML form — using a real Lansweeper-shaped CSV with
  deliberate parse errors (blank product, non-numeric count), confirming
  exact row counts, error messages, and aggregated device counts. 360 tests
  passing project-wide; `ruff` and `mypy --strict` clean.
- Deliberately deferred: API sync so "Test connection" means something for
  API sources (2c); vendor-alias-backed normalisation and the tiered
  version comparator (2d); scan-from-advisory (2e).

### 2026-08-21 — Phase 2a complete (inventory sources tab)
- **Full Phase 2 schema landed in one migration** — `inventory_source`,
  `integration_credential`, `inventory_snapshot`, `inventory_software`,
  `inventory_device`, `inventory_device_software`, `vendor_alias`,
  `scan_run`, `scan_match` — matching docs/data-model.md exactly, so 2b–2e
  are feature work, not schema work (same approach as Phase 0).
- New: `core/security/crypto.py` (Fernet encrypt/decrypt with
  `FERNET_KEY`/`FERNET_KEY_PREVIOUS` rotation via `MultiFernet`),
  `core/security/ssrf.py` (host allowlist + DNS-resolved-address checks
  against loopback/link-local/private/multicast/reserved ranges and the
  cloud-metadata IP by name, per CLAUDE.md §2.3), `core/services/inventory.py`
  (source CRUD, `test_connection()` — honest about not having real adapters
  yet, since those are Phase 2c), `api/routers/inventory.py`,
  `web/inventory.py` plus templates and a new "Inventory" nav tab in
  `base.html`.
- **Real bug found and fixed**: `op.drop_table()` doesn't drop the
  PostgreSQL native `ENUM` types a table's columns used, so running
  `downgrade()` then `upgrade()` on the new migration collided on `CREATE
  TYPE ... already exists`. Checking further, the **original Phase 0
  migration had the identical bug in all 14 of its enum types** — latent
  since 2026-08-20, never caught because no prior verification ran a full
  `downgrade base` → `upgrade head` cycle (only a targeted `downgrade -1` on
  a migration that didn't touch enums). Both migrations fixed by appending
  explicit `DROP TYPE IF EXISTS` loops to their `downgrade()`. See D-023 —
  this is now a standing rule in CLAUDE.md §2.4 for every future enum-adding
  migration.
- **Verified**: 20 new unit tests for crypto/SSRF (key rotation, malformed
  keys, every non-routable address class, a split-DNS case where only one of
  several resolved addresses is private), 13 for the inventory service, 10
  API integration tests, and a manual end-to-end run against the real dev
  database exercising the full create → test-connection → toggle-active →
  history flow through both the REST API and the actual HTML form (not just
  the API). Migration reversibility verified with two full down/up cycles
  against the disposable test database — deliberately not the dev database,
  which holds real corpus data and correctly fails on a *different*, expected
  downgrade issue (narrowing the CVSS-vector column over data too wide for
  it). 316 tests passing project-wide; `ruff` and `mypy --strict` clean.
- Deliberately deferred to later Phase 2 sub-phases: actual CSV upload (2b),
  actual API adapters so "Test connection" means something for API sources
  (2c), normalisation/matching (2d), scan-from-advisory (2e). Source
  CRUD/list/detail is functional now; nothing downstream of a source exists
  yet.

### 2026-08-21 — Phase 1e complete (REST API)
- **`/api/v1` is live**: `api/routers/advisories.py` and `api/routers/sources.py`,
  both thin adapters over `core.services.advisories`/`sources` — no route
  contains a rule, only a service call and a schema. `POST
  /advisories/{id}/status` and `POST /advisories/{id}/comments` are the
  second and third callers of `change_status()`/`add_comment()` (the web UI
  was the first), proving the single-chokepoint architecture actually holds
  across adapters, not just in theory.
- New: `api/schemas.py` (Pydantic request/response models — IOCs expose only
  `defanged_value`, never `value`, matching CLAUDE.md §2.3), `api/problems.py`
  (RFC 9457 problem-details exception handlers, scoped to `/api/` paths only
  so the web UI's redirect-via-`HTTPException(303)` trick is untouched).
  Cursor (keyset) pagination on `(received_at, id)` added to
  `core.services.advisories` as `list_advisories_cursor()` — separate from
  the web tracker's existing page-number `list_advisories()`, which is
  unaffected.
- **Real authorization bug found and fixed**: `Principal.require_scope()`
  let any logged-in *session* user through a scope check unconditionally —
  short-circuited on `ActorKind.USER` before checking role at all. A VIEWER
  would have passed an `advisories:write` check purely by being
  authenticated. Only API tokens were actually being scope-checked. This had
  been latent since Phase 0 but never exercised, because no route called
  `require_scope()` on a session user until this phase's first scope-gated
  endpoint. Fixed via `SCOPE_MIN_ROLE` (D-022); regression tests added.
- **Verified**: 16 new integration tests hitting the real FastAPI app via
  `TestClient` with `db_session` overridden to a transactional test session
  (auth, cursor pagination, all four RFC 9457 error shapes, comments, PATCH
  semantics, IOC defanging) plus a manual end-to-end run against the real dev
  database with minted tokens. Confirmed the `db` fixture's
  external-transaction pattern correctly isolates test data even when routes
  call `db.commit()` — checked by inspecting the test database directly
  after two consecutive full suite runs, not just trusting green output.
  270 tests passing project-wide; `ruff` and `mypy --strict` clean.
- Scope deliberately trimmed from the original design doc, not silently
  dropped — see docs/api-and-mcp.md's "As built" note: `has_cve`, `cve_id`,
  `received_after`/`received_before` filters; `GET
  /advisories/{id}/attachments/raw` (original email — only the per-attachment
  download exists); `POST /sources` (Phase 2a scope, since inventory-source
  CRUD lives there anyway).
- Deliberately deferred: MCP server (Phase 3); inventory/scan/stats endpoints
  (Phase 2/3, design-only so far).

### 2026-08-21 — Phase 1d complete (status + audit chokepoint)
- **`core.services.advisories.change_status()` is now implemented** — the
  chokepoint CLAUDE.md §2.2 has referenced since Phase 0. No migration was
  needed: `status_change.comment_id NOT NULL` and the append-only `audit_log`
  trigger were already in place from Phase 0's full-schema migration; Phase
  1d was pure service + UI work.
- What it does, in one transaction: row-locks the advisory
  (`SELECT ... FOR UPDATE`) so two concurrent status changes on the same
  advisory serialise instead of racing; validates the transition against
  `ALLOWED_TRANSITIONS`; rejects a blank comment; rejects acknowledging
  without an `ack_channel`; writes the `comment` and `status_change` rows and
  an `audit_log` entry; updates `advisory.status` and, on acknowledgement,
  `acknowledged_at`/`acknowledged_by_id`/`ack_channel`. See D-021.
- Web UI: the Phase 1c detail panel's disabled "Change status" placeholder
  button is now a real form (`_status_form.html`) — a status picker scoped to
  legal next-states (`next_statuses()`), a required comment textarea, and a
  conditionally-shown acknowledgement-channel picker. `POST
  /advisories/{id}/status` requires ANALYST role or higher; a successful
  change responds with `HX-Refresh: true` so the table, dashboard tiles, and
  detail panel all stay consistent rather than partially updating.
- **Deliberate divergence, recorded as D-021**: web-route validation failures
  (blank comment, illegal transition, missing ack channel) return HTTP 200
  with the form re-rendered and an inline error, not a 4xx — HTMX only swaps
  response bodies on 2xx by default and the app doesn't yet configure
  `htmx.config.responseHandling`. The REST API (1e) will return proper 4xx
  for the same conditions; the status code choice here is a UI-layer
  convenience, not a weakening of enforcement — `core` still owns every rule.
- 10 new unit tests for `change_status()`, covering the happy path, every
  rejection path, reopening a closed advisory (regulators re-issue — nothing
  is a dead end), and status-history reflection. Also manually verified
  end-to-end with `TestClient` against the real dev database: all four form
  outcomes plus a VIEWER-role 403. 252 tests passing project-wide; `ruff` and
  `mypy --strict` clean.
- Deliberately deferred: bulk acknowledgement (architecture.md notes
  `NEW → ACKNOWLEDGED` as the one transition that *may* eventually be
  bulk-performed, but nothing bulk exists yet — every transition currently
  goes through the single-advisory form); REST API (1e).

### 2026-08-21 — Phase 1c complete (tracker + dashboard UI)
- **Verified end-to-end against the real dev database**, not just unit tests:
  used FastAPI's `TestClient` to make actual authenticated HTTP requests
  (`GET /`, the HTMX-partial variant, an expanded advisory detail row, a raw
  email download) and confirmed 200s with correct content, on top of 18 new
  unit tests for the read-only query service. 242 tests passing project-wide;
  `ruff` and `mypy --strict` clean.
- New: `core/services/advisories.py` (all tracker/dashboard reads — filtering,
  full-text search, pagination, batched last-comment lookup via a
  `row_number()` window function to avoid N+1, dashboard stats). New route
  module `web/tracker.py`. Five new/rewritten Jinja templates
  (`_macros.html`, `_dashboard.html`, `_tracker_table.html`,
  `_advisory_detail.html`, `index.html`) plus a CSS status-badge system in
  `base.html` following the `dataviz` skill's palette methodology (fixed
  status colors never reused for series identity, icon+label pairing, dark
  mode via `@media (prefers-color-scheme: dark)`).
  `Comment.author` and `StatusChange.actor` relationships added to support
  attributing comments/status changes in the UI.
- **Two real mistakes caught during verification, not before:**
  - The first route-registration check iterated `app.routes` and filtered on
    `hasattr(r, "path")` — this FastAPI version (0.141) represents an
    `include_router()`-included router as an `_IncludedRouter` wrapper rather
    than flattened `APIRoute` objects, so the filter silently hid every
    tracker/health/web route and produced a false "routes aren't registered"
    reading. `app.routes` introspection is not reliable for this; use
    `TestClient` requests to verify routing.
  - The first authenticated-request test set a cookie named `session`; the
    real cookie name is `advisory_hub_session` (`api/deps.py:SESSION_COOKIE`).
    Every request silently 303'd to `/login` and the test still "passed" its
    naive assertions because `TestClient` follows redirects by default and
    the login page also returns 200 — asserting on response *content*
    (`"Tracker" in r.text`), not just status code, is what caught it.
- The "Change status" button in the detail panel is present but **deliberately
  disabled** — it depends on `change_status()`, which is Phase 1d.
- Deliberately deferred: inline status editing (1d), REST API (1e).
- `docs/roadmap.md` §1c marked complete with verification notes.

### 2026-08-20 — Phase 1b complete (NVD enrichment)
- **Validated against the live NVD API, not mocks.** Real corpus CVEs enrich
  with 0 errors; CPE ranges land per vendor/product, normalised and ready for
  Phase-2 matching. 222 tests passing; `ruff` and `mypy --strict` clean.
- New: `enrich/nvd.py` (client, rate limiter, backoff), `enrich/cpe.py` (CPE 2.3
  parsing/normalisation), `enrich/cache.py` (Redis), and
  `core/services/enrichment.py` (persistence + re-scoring). CLI: `enrich`.
  The worker sweeps every 5 minutes.
- Findings from the live API that the code now handles:
  - **`metrics` carries `ssvcV203`**, which has no `cvssData` and a null score.
    Iterating metrics blindly produces junk rows; only `cvssMetric*` is read.
  - **CVSS v4.0 vectors run past 170 characters** with threat/environmental
    metrics. `String(160)` failed on live data — both vector columns are now
    `TEXT` (migration `f9d471469add`).
  - NVD timestamps carry **no timezone**; normalised to UTC.
  - Several metrics can share a CVSS version — `Primary` from `nvd@nist.gov`
    is preferred over secondary sources.
  - Negated configuration nodes are **skipped, not inverted**.
- **Rate limit is the real constraint**: 4 req/30s anonymous vs 45 with a key,
  so a 404-CVE backfill is ~50 min vs ~5 min. `NVD_API_KEY` is worth having.
- Enrichment can **raise** severity and both SLA clocks, never lower them
  (D-019). Guarded by a test.
- `ERROR` and `NOT_FOUND` are deliberately distinct: transport failures are
  retried for 30 days, genuine absences are not retried at all.

### 2026-08-20 — Phase 1a complete (ingestion pipeline)
- **The pipeline runs end-to-end on the real corpus**: 135/135 parsed and
  persisted, 0 failures, 0 PDF extraction failures, ~0.19s per advisory.
  404 distinct CVEs, 227 IOCs, 253 product claims, 12 re-issue links.
  Re-ingesting yields 135 duplicates and zero new rows.
- 183 tests passing; `ruff` and `mypy --strict` clean.
- New modules under `ingest/`: `watcher`, `message`, `pdf` + `pdf_worker`
  (sandbox), `sections`, `extractors`, `sidecars`, `classify`, `coerce`,
  `parser`, `pipeline`. Services: `sources`, `ingestion`, `reparse`.
- Bugs found and fixed while validating against the corpus:
  - **The IOC section heading is literally `IOCs`** — lowercase `s`. A strict
    ALL-CAPS heading regex silently skipped every PDF IOC table; all IOCs were
    coming from sidecars alone. Recovered 188 → 227.
  - **`ATTACK VECTOR` is not a threat-landscape signal.** Ordinary CVE
    advisories describe their attack vector (DOH-2026551, a SharePoint RCE),
    so it was misfiling them. Only `ATTACK CHAIN OVERVIEW` / `CAMPAIGN
    OVERVIEW` imply a campaign narrative.
  - **`CVE_ADVISORY` could win with zero CVEs**, because the regulator's
    blanket `Vulnerability` label was scored unconditionally. That misfiled
    IoT botnets and ransomware-affiliate reports. Now suppressed.
  - **Confidence was `winner/total`**, so a single weak signal read as 1.00 and
    nothing was ever flagged for review. Replaced with a two-horse margin
    scaled by evidence mass; 20/135 now flagged, all genuinely ambiguous.
  - **`classify.py` duplicated the heading set owned by `patterns.py`**, so a
    fix in one didn't reach the other. Now reads the `Section.is_campaign`
    property.
  - **XLSX sidecars were parsed with the stdlib `xml`** — XXE and entity
    expansion on an attachment from outside the org. Switched to `defusedxml`.
- Deliberately deferred: NVD enrichment (1b), tracker UI (1c),
  `change_status()` (1d), REST API (1e).
- Corpus fixtures in `tests/fixtures/corpus_samples.json` are **redacted** —
  IOCs replaced with RFC 5737/`.invalid` values, contact block and
  recipient-identifying SafeLinks stripped. Verified no leaks.

### 2026-08-20 — Phase 0 complete
- **Scaffold, schema, auth, storage, audit, and CI are in place and verified
  end-to-end.** 82 tests passing; `ruff` and `mypy --strict` clean; container
  builds; migration applies; admin logs in; audit trail records it.
- The initial migration lands the **full Phase-1 schema (18 tables)**, so Phase 1
  is pipeline work rather than schema work.
- Three real bugs were found and fixed during the build, all worth knowing about:
  - **`structlog` misconfiguration** — `add_logger_name` paired with
    `PrintLoggerFactory` raised `AttributeError` on *every* non-health request
    log line. Health endpoints are excluded from request logging, which is why it
    hid until the first UI route was exercised. Regression test added.
  - **API tokens: ~1 in 8 were unusable.** `secrets.token_urlsafe` can emit `_`,
    and `split_token` splits on `_`, so an underscore in the prefix made the
    token unparseable and permanently unauthenticatable. Prefix is now hex.
    Surfaced as a ~25% test flake; found by running the suite 8×. Regression
    test mints 500 tokens.
  - **`migrations/env.py` clobbered any caller-supplied URL**, so programmatic
    migrations always targeted `DATABASE_URL`. Fixed to defer to the caller.
- Test fixtures build the schema by **running Alembic**, not `create_all()` —
  otherwise the migration is untested and drift is invisible. CI additionally
  checks migration reversibility and model drift.
- `advisory_hub.config.settings` is a lazy proxy: `from .config import settings`
  would otherwise bind a permanent snapshot, breaking test isolation and any
  future config reload.
- Deferred to Phase 1: no `Advisory` service yet, so `change_status()` — the
  mandatory-comment chokepoint — is **not yet implemented**. Its schema-level
  guarantee (`status_change.comment_id NOT NULL`) and the transition table are.
- Next: Phase 1a, the ingestion pipeline. Parser design is in `docs/ingestion.md`.

### 2026-08-20 — Corpus analysed, parser design grounded in real data
- User supplied 135 real DOH SOC advisories (`Advisory/`, 2026-07-13 → 2026-08-19).
  All 135 parsed with zero errors. Full findings in `docs/ingestion.md`.
- **`docs/ingestion.md` rewritten from scratch** — the previous version was
  assumption-based and wrong in three material ways (see D-013, D-014, D-017).
- Key measurements: PDF yields 384 distinct CVEs vs the email's 63; 135/135 PDFs
  have a text layer (no OCR needed); the regulator's `Type` field says
  `Vulnerability` for 128/135 and cannot be trusted; all 135 emails embed a
  two-clock SLA table.
- New decisions **D-013 … D-020**. Status model gained `ACKNOWLEDGED`
  (`docs/architecture.md` §5); schema gained SLA/ack columns, `advisory_flag`,
  `related_advisory`, and CVE provenance (`docs/data-model.md`).
- **Open questions 1, 2, and 3 are now answered** — see §5 below.
- Analysis scripts are in `/tmp/adv/` (scratch, not committed). The corpus itself
  is **not** committed — see §6.
- Still nothing implemented. Next: Phase 0 scaffold.

### 2026-08-20 — Planning complete
- Architecture, data model, ingestion pipeline, inventory matching, API/MCP
  design, roadmap, decisions, and operations docs written.
- Stack settled: FastAPI + HTMX + PostgreSQL, on-prem Docker Compose, local auth
  with SSO-ready abstraction, NVD as the sole enrichment source. See
  `docs/decisions.md`.
- Requirement added by user after the initial questions: the tool must expose a
  REST API **and** an MCP server for future dashboard/agent integrations. This
  drove the `core/`-services-as-single-source-of-truth rule in §2.2.
- **Nothing is implemented yet.** Next: Phase 0 scaffold (see
  `docs/roadmap.md`).

---

## 5. Open questions

Tracked here until answered. Answer them in `docs/decisions.md` when resolved.

### Answered

| # | Question | Answer |
|---|---|---|
| 1 | Sample emails? | **135 supplied.** Single sender `cyber.advisory@doh.gov.ae`, one PDF each, 100% subject-pattern match. |
| 2 | Text-layer or scanned PDFs? | **100% text layer.** OCR not built — D-015. |
| 3 | Remediation SLA? | **Embedded in every email.** Two clocks: ack 8/16/72/72 h, resolve 24/48/120/120 h by P1–P4 — D-018. |

### Still open

| # | Question | Blocking | Default if unanswered |
|---|---|---|---|
| 4 | Desktop Central: on-prem UEMS or cloud endpoint, and API version? | Phase 2 API adapter | Build CSV path first, adapter behind an interface |
| 5 | Expected estate size (endpoints) and inventory refresh cadence? | Inventory table sizing | Assume <50k endpoints, daily sync |
| 6 | Working-day calendar for P3/P4 SLA — UAE Sat–Sun weekend, and which public holidays? | Accurate P3/P4 due dates | Sat–Sun weekend, no holiday calendar |
| 7 | Is acknowledgement sent *from* this tool (email/API to DOH), or recorded here after being sent manually? | Phase 1 ack workflow scope | **Record-only** — analyst marks it acknowledged after replying by their own means |
| 8 | Will the historical 135 be backfilled at go-live? | Phase 1 launch data | Yes — backfill, since they are already archived and re-parseable |

---

## 6. Handling the corpus

`Advisory/` holds 135 real advisories classified **"Restricted by Department of
Health"**.

- **Never commit it.** `Advisory/` is in `.gitignore`. It stays on disk as local
  reference data.
- Test fixtures derived from it must be **redacted** before committing: strip
  recipient addresses, internal hostnames, and the DOH contact block. IOC values
  in fixtures should be replaced with RFC 5737 documentation IPs and
  `example.invalid` domains unless the specific value is what's under test.
- The fixture list is in `docs/ingestion.md` §14.

`Inventory/` holds real software-inventory exports from our estate (Endpoint
Central, Lansweeper) used to ground Phase 2d. Same rule: **never commit it** —
it is in `.gitignore`. Inventory test fixtures must be synthetic or redacted
(no real hostnames, users, or device identifiers).
