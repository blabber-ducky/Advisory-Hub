# Operations

Deployment, configuration, and runbooks. Update this doc whenever a container,
volume, environment variable, or operational step changes.

> **Deploying to production?** Follow [deployment.md](deployment.md) —
> `docker-compose.prod.yml`, step by step. This doc is the reference it
> links into: configuration, backups, runbooks, images.

## 0. Running it (development)

```bash
cp .env.example .env
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
docker compose up -d
docker compose exec app alembic upgrade head
docker compose exec app python -m advisory_hub.cli create-admin
```

**`SECRET_KEY` is mandatory** — compose refuses to interpolate without it, and
the app refuses to start in production if it is still a placeholder. Both
failures are deliberate: the alternative is issuing forgeable session cookies.

`docker-compose.override.yml` is picked up automatically and adds development
conveniences: **builds the image from your working tree**, published
Postgres/Redis ports, live reload, console logging, non-secure cookies.

**Production uses its own file, `docker-compose.prod.yml`** — pulls
pinned images from Docker Hub (§8), hardened, migrations run automatically,
behind your enterprise WAF / reverse proxy for TLS (§7). See
[deployment.md](deployment.md). A production host needs only that file and
`.env` — not the source tree.

| File | Purpose |
|---|---|
| `docker-compose.yml` | Base stack. Pulls images; plain HTTP on `APP_PORT` |
| `docker-compose.override.yml` | Auto-applied in development: builds from the working tree, reload, published DB/Redis ports |
| `docker-compose.prod.yml` | **Production.** Self-contained; used alone. `app` publishes its own port; TLS is terminated upstream (§7, D-040) |

Every file passes the whole `.env` into `app`/`worker`, so any variable in
§3 can be set there. (Until 2026-09-29 the base file passed only a
hand-picked subset — `VT_API_KEY`, `PDF_*`, `CSV_*`, the poll intervals and
`FERNET_KEY_PREVIOUS` set in `.env` silently had no effect under Compose.)

`APP_PORT` (default `8080`), `POSTGRES_PORT`, and `REDIS_PORT` are overridable
when a port is already taken.

**For anything users will actually log in to, put it behind HTTPS** — the
stack itself only speaks HTTP; see §7.

### CLI

| Command | Does |
|---|---|
| `create-admin` | Create an administrator (prompts for the password) |
| `create-token` | Mint a scoped API token — **shown once** |
| `list-users` | List accounts and roles |
| `check` | Verify database, blob volume, inbox, and schema |
| `duplicates` | Read-only. Lists advisories stored more than once — copies of one email (same Message-ID) or re-sends (same reference + identical PDF), grouped, oldest first (the one the import gates keep now), with each copy's status and comment count. Changes nothing: pick the copy to keep, carry over any status/comments, and close the others (e.g. as Not applicable with a comment naming the kept one). See ingestion.md §4 |
| `status-export [-o file.csv]` | Write every advisory's status + history as an importable CSV — the same file the daily job writes. Default: into `STATUS_EXPORT_DIR` as `status-export-<date>.csv` |
| `tracker-to-csv <file.xlsx> [-o out.csv]` | Convert the manual tracker workbook into the editable import CSV (status + comment per advisory). No database needed. See architecture.md §3.3.3 |

Outside a container, **`scripts/tracker-to-csv.sh <file.xlsx> [out.csv]`**
runs that same conversion from a repo checkout (using `.venv`) or on any
machine with Docker (the published image, no network, read-only, as your own
user). Docker image: `IMAGE=…`, or `IMAGE_NAMESPACE`/`IMAGE_TAG` from the
environment or `./.env`. The output defaults to the workbook's name with
`.csv`.

## 1. Containers

| Service | Image | Role |
|---|---|---|
| `app` | `<IMAGE_NAMESPACE>/advisory-hub` (`docker/Dockerfile`) | FastAPI: UI, REST API, MCP HTTP transport |
| `worker` | same image, different command | RQ worker: ingestion, enrichment, inventory sync, scans |
| `migrate` | same image | **Production file only.** Runs `alembic upgrade head` and exits; `app`/`worker` start only after it succeeds |
| `init-data` | same image | One-shot, first. Creates the `./data/<volume>` folders and gives the app's ones to the image's non-root user (uid 10001); exits. See §2 |
| `postgres` | `postgres:16-alpine` | System of record |
| `redis` | `redis:7-alpine` | Job queue, NVD cache, rate limiting |

Inventory syncs are scheduled by a poller thread inside `worker` — there is
no separate scheduler container.

**One project name per stack on a host.** Containers are named after the
Compose project (`name: advisory-hub` in the compose files). Two stacks on
one machine with the same project name share container names, so `up` in one
replaces the other's containers. Give each extra stack its own
`COMPOSE_PROJECT_NAME` in its `.env` (e.g. `advisory-hub-test`). A
development checkout is already separate: `docker-compose.override.yml`
names it `advisory-hub-dev`.

## 2. Data folders

**Every compose file keeps all persistent data in host folders under
`./data/<volume>`** next to the compose file — not in Docker named volumes —
so backing up and restoring is a file operation on one directory (§4).

| Host folder | Mounted in containers at | Purpose | Back up |
|---|---|---|---|
| `./data/pgdata` | `postgres:/var/lib/postgresql/data` | PostgreSQL | **Yes — critical** |
| `./data/blobs` | `app`, `worker`: `/data/blobs` | Content-addressed store (originals, attachments) | **Yes — critical** |
| `./data/archive` | `/data/archive` | Successfully ingested originals | **Yes** |
| `./data/failed` | `/data/failed` | Failed ingests + `.error.json` sidecars | **Yes** |
| `./data/redisdata` | `redis:/data` | Job queue (AOF/RDB) | Optional — queued jobs only |
| `./data/inbox` | `/data/inbox` | Watched inbox (unless `INBOX_HOST_PATH` is set) | No — transient |
| `./data/processing` | `/data/processing` | Worker claim area | No — transient |
| `./data/certs` | `app` only: `/data/certs` | HTTPS certificate + key when `HTTPS_ENABLED=true` (§7) | **Yes** for a provided certificate (a generated one is simply remade) |
| `./data/exports` | `/data/exports` | Daily status-export CSVs, kept 30 days (§4) | **Yes** — and copy the latest off the host too |

**Ownership is handled for you.** The app runs as uid 10001. On Linux,
Docker creates a missing bind-mount folder owned by root, which the app
can't write to. The one-shot `init-data` container runs before
`app`/`worker`, creates every folder, and gives `blobs`, `inbox`,
`processing`, `archive`, `failed`, `exports` and `certs` to uid 10001. It also fixes anything
not owned by uid 10001, such as files a restore copied back as root.
Postgres and Redis fix their own folders at startup. On the host you'll
see uid 10001 (or a raw number) as the owner of those folders on Linux;
that's expected.

**`./data/` is git-ignored and excluded from Docker builds**
(`.dockerignore`), so a development checkout can hold real data safely.

**The inbox can live elsewhere.** Set `INBOX_HOST_PATH` (compose-level, not
read by the app itself — see §3) to an absolute host path to mount another
folder at `/data/inbox` instead of `./data/inbox` — e.g. one a Power
Automate flow or a mail rule on this host writes `.msg` files into
directly. `init-data` only manages `./data`, so uid 10001 must be able to
write that folder yourself. `inbox/` being on a different filesystem than `processing/` this
way is handled transparently by `Inbox.claim()` (a cross-device fallback,
same-filesystem claim-in-place then a copy — see `ingest/watcher.py`'s
module docstring and docs/decisions.md D-029); no operational difference
either way. Both `app` and `worker` mount whichever one is active; `app`'s
`/health` endpoint reports the mount as unhealthy if the host folder is
missing or inaccessible, so a misconfigured path is visible immediately
rather than silently dropping emails.

## 3. Configuration

Every variable belongs in `.env.example` with a dummy value and a comment.

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | yes | `postgresql+psycopg://…` |
| `REDIS_URL` | yes | |
| `SECRET_KEY` | yes | Session signing. Rotating logs everyone out. |
| `FERNET_KEY` | yes (Phase 2) | Integration-credential encryption. **Losing this means re-entering every credential.** Back it up separately from the database. |
| `FERNET_KEY_PREVIOUS` | no | Set during key rotation — `MultiFernet` tries both keys on decrypt, so rows encrypted under the old key keep working until re-encrypted; remove once rotation is complete |
| `BLOB_ROOT` | yes | Default `/data/blobs` |
| `INBOX_PATH` | yes | In-container path, default `/data/inbox` — what the app/worker actually read |
| `INBOX_HOST_PATH` | no | **Compose-level only, not read by the app.** Absolute host path mounted at `/data/inbox` in place of `./data/inbox` — set this to point the watcher at a folder another system writes emails into. Must be writable by uid 10001. |
| `COMPOSE_PROJECT_NAME` | no | **Compose-level.** Overrides the project name (`advisory-hub`). Set it when more than one stack runs on the same host, or they replace each other's containers (§1) |
| `INBOX_POLL_SECONDS` | no | Default `30` |
| `UPLOAD_MAX_BYTES` | no | Default `52428800` (50 MB) — per-file cap for `.eml`/`.msg` uploaded from the tracker page ("Upload email") |
| `UPLOAD_MAX_FILES` | no | Default `20` — files per upload from the tracker page |
| `NVD_API_KEY` | recommended | Raises the rate limit from 5 → 50 requests per 30s. **Overridden by an admin-panel-configured key** (`/admin`, ADMIN role) if one is set — see docs/decisions.md D-031. Either way works; the admin panel takes effect immediately, no restart. |
| `NVD_ENABLED` | no | Default `true`; `false` for air-gapped operation. Also overridable per D-031 — disabling from `/admin` wins over this. |
| `VT_API_KEY` | no | VirusTotal API key for the analyst-triggered "Check on VirusTotal" IOC action. Same admin-panel override as `NVD_API_KEY`. Unset (both here and in the admin panel): the button/endpoint still exists, but returns a clear "not configured" error (`502`) rather than being hidden. |
| `VT_ENABLED` | no | Default `true`. Overridable from `/admin` per D-031. |
| `PDF_MAX_BYTES` | no | Default `52428800` (50 MB) |
| `PDF_MAX_PAGES` | no | Default `500` |
| `PDF_TIMEOUT_SECONDS` | no | Default `120` |
| `OCR_ENABLED` | no | Default `false` — turn on only if scanned PDFs actually appear |
| `PUBLIC_BASE_URL` | for Microsoft sign-in | The address people reach the app at, e.g. `https://advisoryhub.example.com`. The Entra redirect URI is `<PUBLIC_BASE_URL>/auth/entra/callback`. Set, not derived from request headers (spoofable behind a proxy). §9 |
| `OUTBOUND_ALLOWLIST` | yes (Phase 2) | Comma-separated hostnames the SSRF guard permits. For the Azure ARM and MS Graph adapters this must include **both** the API host (`management.azure.com` / `graph.microsoft.com`) **and** `login.microsoftonline.com` — the OAuth token endpoint is a separate outbound call, also SSRF-checked. Microsoft sign-in needs `login.microsoftonline.com`; mailbox sync needs it and `graph.microsoft.com` (§9). |
| `CSV_MAX_BYTES` | no | Default `20971520` (20 MB) — inventory CSV upload size cap |
| `CSV_MAX_ROWS` | no | Default `200000` — inventory CSV row cap, enforced while parsing |
| `INVENTORY_SYNC_POLL_SECONDS` | no | Default `300` — how often the worker checks active API sources for a due `schedule_cron` |
| `IMAGE_NAMESPACE` | yes (production) | **Compose-level.** Docker Hub user/org the images are pulled from, e.g. `acme` → `acme/advisory-hub`. Unset → `localhost/…`: only locally built images work, and a pull fails loudly rather than fetching from someone else's namespace. See §8. |
| `IMAGE_TAG` | recommended | **Compose-level.** Image tag for `app`/`worker`/`migrate`. Default `latest`; pin a release (`1.4.0`) or commit (`sha-1a2b3c4`) in production. |
| `WEB_CONCURRENCY` | no | **Production files.** uvicorn processes for `app`. Default `1`; each extra costs ~100 MB — raise `app`'s memory limit in the compose file to match |
| `BIND_ADDRESS` | no | **Compose-level, production file.** Host interface `app`'s port is bound to. Default `0.0.0.0`; set the address of the NIC facing the WAF to keep it off other interfaces |
| `APP_PORT` | no | **Compose-level.** Host port `app` listens on. Default `8080` in the base/dev file; default `8000` in `docker-compose.prod.yml`, where it's the only published port |
| `TRUSTED_PROXY_IPS` | behind a proxy | **Compose-level**, maps to `FORWARDED_ALLOW_IPS` for uvicorn. Comma-separated literal IP address(es) of your WAF/reverse proxy — **not** `*` and **not** a CIDR. Default `127.0.0.1` (no external peer trusted) — right when the app serves HTTPS itself. Behind a proxy, set it, or the audit log shows the proxy's IP for everyone. See D-040, D-045 |
| `POSTGRES_PASSWORD` | yes (production) | **Compose-level.** Database password, embedded in `DATABASE_URL` by compose — use hex (`openssl rand -hex 32`) so it's URL-safe. Only read when the database volume is first created |
| `STATUS_EXPORT_ENABLED` | no | Default `true`. The worker's daily status export (§4) |
| `STATUS_EXPORT_CRON` | no | Default `0 2 * * *` — 02:00 **UTC** (06:00 UAE). Standard 5-field cron. A worker that was down at the time catches up when it starts |
| `STATUS_EXPORT_DIR` | no | Default `/data/exports` (`./data/exports` on the host) |
| `STATUS_EXPORT_KEEP_DAYS` | no | Default `30`. Older `status-export-*.csv` files are deleted; nothing else in the folder is touched |
| `HTTPS_ENABLED` | no | Default `false`. `true`: the app port serves HTTPS itself, with `./data/certs/server.crt`+`server.key` if both exist, or a generated self-signed certificate if neither does (§7) |
| `TLS_HOSTNAMES` | with `HTTPS_ENABLED` | Comma-separated names/IPs users browse to (e.g. DNS name and NAT/LAN IP) — written into a generated certificate; `localhost`/`127.0.0.1` always added |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | no | Defaults `/data/certs/server.crt` / `/data/certs/server.key` (`./data/certs` on the host) |
| `SESSION_COOKIE_SECURE` | no | Default `true`; `false` only for HTTP on an isolated test network. The production file forces `true` — users must reach it over HTTPS (§7) or sign-in loops back to the login page. |
| `COMPOSE_FILE` | production | **Compose-level.** Which compose file plain `docker compose …` uses: `docker-compose.prod.yml` in production (set by `.env.production.example`). Also stops `docker-compose.override.yml` being applied. |
| `LOG_LEVEL` | no | Default `INFO` |

## 4. Backup and restore

What to keep: **`./data/`** (see the table in §2 — `pgdata`, `blobs`,
`archive` and `failed` are the ones that matter) and **`.env`**. `.env`
holds `FERNET_KEY`, without which the integration credentials in the
database can't be decrypted, and `POSTGRES_PASSWORD`, which the restored
database will still expect. Store `.env` separately from the data backup,
e.g. in your secrets manager.

Run these from the folder holding the compose file. On Linux, use `sudo`:
Postgres's files are only readable by its own user.

### Cold backup — simplest, consistent, a minute of downtime

```bash
docker compose stop                                   # quiesce; containers are kept
sudo tar -czf /backup/advisory-hub-$(date +%F).tar.gz data/
docker compose start
```

Postgres's data files are only consistent while it's stopped, so copying
`./data/pgdata` from a *running* stack isn't a valid database backup.

### Hot backup — no downtime

```bash
# Database: a consistent logical dump while it runs
docker compose exec -T postgres pg_dump -U advisory_hub -Fc advisory_hub \
  > /backup/db-$(date +%F).dump
# Files: content-addressed, so incremental sync is safe and cheap
sudo rsync -a --delete data/blobs/   /backup/blobs/
sudo rsync -a          data/archive/ /backup/archive/
sudo rsync -a          data/failed/  /backup/failed/
```

### Restore

From a cold backup:

```bash
docker compose down
sudo mv data data.before-restore          # keep it until the restore is verified
sudo tar -xzf /backup/advisory-hub-2026-10-04.tar.gz
docker compose up -d                      # init-data re-applies ownership
```

From a hot backup: restore the files into `./data/blobs`, `./data/archive`
and `./data/failed`. Start the stack with an empty `./data/pgdata`, then
replace the database with the dump:

```bash
docker compose stop app worker
docker compose exec -T postgres pg_restore -U advisory_hub -d advisory_hub --clean --if-exists \
  < /backup/db-2026-10-04.dump
docker compose start app worker
```

Use the **same `.env`** as the backup. `POSTGRES_PASSWORD` is stored inside
`pgdata`, and `FERNET_KEY` decrypts the stored credentials.

**Restore is not backup.** Exercise a full restore into a scratch environment at
least once per quarter and record the date. A restore that has never been tried
is a hypothesis.

### Daily status export — the last line of defence

Every day (`STATUS_EXPORT_CRON`, 02:00 UTC by default) the worker writes
`./data/exports/status-export-<date>.csv`: every advisory's status,
acknowledgement and full comment history, in the format the import page
reads. 30 days are kept. The file is only readable by its owner (uid 10001;
use `sudo` on Linux). It's also on demand: **Export statuses (CSV)** on the
tracker page, or `advisory-hub status-export`.

It lives in `./data`, so a disaster that takes `./data` with it takes the
exports too. **Copy the latest one somewhere else** as part of your backup,
e.g. a nightly job:

```bash
sudo cp "$(ls -1 /opt/advisory-hub/data/exports/status-export-*.csv | tail -1)" /backup/elsewhere/
```

The worker logs `status_export.written` each day, and `status_export.failed`
with the reason if it couldn't write.

### Restoring from a status export (deployment lost, no usable backup)

The export restores **statuses, acknowledgements and comments** — not the
advisories themselves, which always come from the emails:

1. Stand up a fresh deployment (deployment.md §3).
2. Re-ingest the original emails: put the `.msg`/`.eml` files (e.g. from a
   copy of `archive/`, or re-exported from the mailbox) into the inbox, or
   `docker compose exec app python -m advisory_hub.cli ingest /path`.
3. Sign in, open **Import manual tracker**, upload the latest
   `status-export-<date>.csv`, check the preview ("Not in the tool yet"
   should be 0 if every email was re-ingested), and **Apply**.

What comes back, and what doesn't, is tabled in architecture.md §3.3.4.
Statuses come back through the normal status-change process, with a comment
at each step. Comments come back as one history block per advisory.
Importing an export into a healthy deployment is harmless: it changes
nothing.

### Moving an existing stack from named volumes to `./data`

Stacks started before 2026-10-04 kept their data in Docker named volumes
called `<project>_pgdata`, `<project>_blobs` and so on (`docker volume ls`).
Copy them across once, **before** starting the new compose file. Otherwise
the stack starts with an empty `./data` and an empty database:

```bash
docker compose down
for v in pgdata redisdata blobs inbox processing archive failed; do
  sudo mkdir -p data/$v
  docker run --rm -v advisory-hub_$v:/from:ro -v "$PWD/data/$v":/to \
    postgres:16-alpine sh -c 'cp -a /from/. /to/'
done
# now switch to the new compose file, then:
docker compose up -d
```

Check the data is there (sign in, count advisories), then remove the old
volumes with `docker volume rm advisory-hub_pgdata …` whenever you're
ready. Nothing deletes them automatically.

## 5. Runbooks

### Advisory didn't appear after Power Automate ran

1. Is the file in `/data/inbox`? If not, the problem is upstream in the flow.
2. Does it end in `.eml`/`.msg`? The watcher ignores anything else — check the
   flow is doing the `.tmp` → rename dance and not leaving the temp extension.
3. Check `/data/failed/` for the file plus its `.error.json` sidecar.
4. `docker compose logs worker --tail 200`. Look specifically for
   `Exception in thread inbox-poller` — a dead poller thread doesn't make the
   worker unhealthy, it just stops ingesting. `docker compose restart worker`
   recovers it; then report the traceback. (Start-up import races killed it
   on most starts until 2026-09-29.)
5. If it was ingested before, dedupe skipped it by design — search by
   `Message-ID` to find the existing advisory.

### PDF text extraction failed

Check `advisory_attachment.extraction_method` and `extraction_error`.

- `FAILED` with `NO_TEXT_LAYER` → scanned PDF. Set `OCR_ENABLED=true`, restart the
  worker, then `reparse` that advisory.
- `FAILED` with a timeout or limit breach → possibly hostile, possibly just
  enormous. Inspect the original in `/data/archive` before raising limits.
- The advisory still exists with its email content in both cases. Nothing is lost.

### Enriching a backlog (e.g. after go-live backfill)

`advisory-hub enrich` is safe to re-run and safe to interrupt: every CVE's
outcome is recorded, so a second run resumes where the first stopped.

**Throughput is bounded by NVD's rate limit, and the API key matters a great
deal.** Measured against the live API:

| | Requests / 30s | 404 CVEs (one corpus backfill) |
|---|---|---|
| Anonymous | 4 (of a documented 5) | **~50 minutes** |
| With `NVD_API_KEY` | 45 (of a documented 50) | **~5 minutes** |

Get a key from <https://nvd.nist.gov/developers/request-an-api-key>. Repeat
lookups are served from Redis (24h for hits, 1h for misses), so re-runs and
CVEs shared across advisories cost nothing.

```bash
docker compose exec app python -m advisory_hub.cli enrich          # everything due
docker compose exec app python -m advisory_hub.cli enrich --limit 100
docker compose exec app python -m advisory_hub.cli enrich --force  # ignore freshness
```

The worker also sweeps every 5 minutes in the background, so steady-state
operation needs no manual runs.

### NVD enrichment stuck on `PENDING`

1. `NVD_ENABLED` set? `NVD_API_KEY` present?
2. Can the container reach `services.nvd.nist.gov`? Check egress rules.
3. Rate limited? Look for `429` in worker logs; backoff is automatic.
4. Force a retry: `python -m advisory_hub.cli enrich --force`.
5. `ERROR` rows are retried automatically for 30 days, then left alone so a
   permanently broken record stops consuming the rate-limit budget.

### Rotate an integration credential

1. Admin → Inventory → source → *Rotate credential* → enter the new secret.
2. Run *Test connection* and confirm success.
3. The old ciphertext is overwritten; the rotation is audit-logged.

Values are never displayed — if the current secret is unknown, obtain a new one
from the upstream system rather than trying to recover it here.

### Rotate `FERNET_KEY`

1. Set `FERNET_KEY_PREVIOUS` to the current key, `FERNET_KEY` to the new one.
2. `python -m advisory_hub.cli rotate-credentials` — re-encrypts every row and
   bumps `key_version`.
3. Verify each source with *Test connection*, then remove `FERNET_KEY_PREVIOUS`.

### Reparse after a parser improvement

```bash
docker compose exec app python -m advisory_hub.cli reparse \
    --since 2026-01-01 --parser-version-below 3 --dry-run
```

Review the dry-run diff, then re-run without `--dry-run`. Status, assignee,
comments, and history are never touched.

## 6. Monitoring

Minimum viable signals:

| Signal | Alert when |
|---|---|
| `Exception in thread` in worker logs | Any — a background poller (inbox, enrichment, inventory sync) has died while the worker still reports healthy |
| Files in `/data/failed` | `> 0` for more than 1 hour |
| Oldest unprocessed file in `/data/inbox` | Older than 10 minutes |
| RQ queue depth | Growing over 30 minutes |
| `enrichment_status = PENDING` count | Rising over 6 hours (expected briefly after ingest; the worker sweeps every 5 min) |
| `enrichment_status = ERROR` count | Rising — usually NVD unreachable or a bad `NVD_API_KEY` |
| `inventory_source.last_sync_status = ERROR` | Any (Phase 2) |
| Disk free on the blob volume | `< 20%` |
| Postgres connection count | Near `max_connections` |

`/health` reports database, Redis, blob-volume writability, and inbox
reachability as separate checks — a single boolean would hide exactly the
failures worth alerting on.

## 7. HTTPS

**Sign-in only works over HTTPS.** The session cookie is always `Secure`
(`SESSION_COOKIE_SECURE=true`), and browsers won't send a `Secure` cookie
over plain `http://`. So signing in over HTTP accepts the password, then
lands back on the login page. The one exception is `http://localhost` /
`http://127.0.0.1`, which browsers treat as secure. That's why plain HTTP
works on your own machine but loops on a server reached by IP or name,
e.g. through NAT.

Two ways to provide HTTPS:

| | (a) The app serves HTTPS itself | (b) A WAF / reverse proxy in front |
|---|---|---|
| Set | `HTTPS_ENABLED=true` (+ `TLS_HOSTNAMES`) | `HTTPS_ENABLED=false`, `TRUSTED_PROXY_IPS` = the proxy's address(es) |
| Certificate | `./data/certs/server.crt` + `server.key`, yours or generated (below) | On the proxy |
| Users browse to | `https://<host>:<APP_PORT>` | Whatever the proxy serves |
| `http://` | No answer on that port — tell users to use `https://` | Proxy can redirect |
| HSTS | Not sent | Proxy's job |
| Best for | Internal deployments, NAT, no proxy available | Organisations with an existing WAF |

### (a) The app serving HTTPS

On start (`python -m advisory_hub.serve`, the image's default command),
with `HTTPS_ENABLED=true`:

| What's in `./data/certs/` | What happens |
|---|---|
| `server.crt` **and** `server.key` | Used as-is: parsed, the key checked against the certificate, expiry checked. **Never modified.** Warnings in the log if it expires within 30 days or doesn't cover a `TLS_HOSTNAMES` entry |
| Neither | A self-signed certificate (EC P-256, 397 days) is generated for `TLS_HOSTNAMES` + `localhost` + `127.0.0.1`, saved there, and reused on every later start. Renewed automatically 30 days before expiry — only ever *this* generated one |
| Only one of them | **Refuses to start**, saying which is missing. It's probably half of a real certificate, and generating would orphan it |
| Expired, unreadable, passphrase-protected key, or key that doesn't match | Refuses to start, with the reason and the fix |

The app log shows which happened (`tls.certificate` with `generated`,
`self_signed`, `names`, `expires`).

**Using your own certificate** (from your CA): before starting, or with the
app stopped, put the certificate in `./data/certs/server.crt` (leaf first,
then any intermediates, PEM) and the **unencrypted** key in
`./data/certs/server.key`. `init-data` makes them readable to the app.
Replacing it later works the same way: swap both files and run `docker
compose up -d`.

**Self-signed**: browsers warn the first time ("Your connection is not
private"). Accepting the warning, or importing `server.crt` into the
clients' trust store, lets sign-in work. Put every name and IP users type
in `TLS_HOSTNAMES` (e.g. `advisoryhub.corp,10.0.4.20`). If you change it
later, delete both files to regenerate.

```bash
# .env
HTTPS_ENABLED=true
TLS_HOSTNAMES=advisoryhub.corp,10.0.4.20
# then
docker compose up -d
docker compose logs app | grep tls.certificate
```

Development (`docker compose up` with the override, uvicorn `--reload`)
always serves HTTP — use `http://localhost`.

### (b) A WAF / reverse proxy in front

The app speaks HTTP to the proxy; requirements on the proxy, and how to
verify the boundary, are in [deployment.md](deployment.md) §1.

| Here | On the proxy |
|---|---|
| `TRUSTED_PROXY_IPS` = the proxy's own address(es) | Terminate TLS; forward `Host`, `X-Forwarded-For`, `X-Forwarded-Proto` |
| `SESSION_COOKIE_SECURE=true` (forced in production) | Serve users over HTTPS only |
| Firewall `APP_PORT` to the proxy only | HSTS, HTTP → HTTPS redirect, certificate renewal |

## 8. Images and publishing

CI (`.github/workflows/ci.yml`, job `image`) builds and publishes one image
to Docker Hub. Compose pulls it; only development builds locally.

| Image | Dockerfile | Runs as |
|---|---|---|
| `<namespace>/advisory-hub` | `docker/Dockerfile` | `app`, `worker` and `migrate` — same code, different command, so one image |

It's multi-arch (`linux/amd64`, `linux/arm64`) and carry an SBOM and
build provenance attestation.

### 8.1 When CI publishes, and which tags

Publishing happens only after `lint` and `test` pass.

| Trigger | Pushed? | Tags |
|---|---|---|
| Pull request | **No** — built only, to prove it still builds | `pr-<n>` (not pushed) |
| Push to `main` | Yes | `latest`, `main`, `sha-<7-char commit>` |
| Push tag `v1.4.0` | Yes | `1.4.0`, `1.4`, `sha-<commit>` |

To cut a release: `git tag v1.4.0 && git push origin v1.4.0`.

### 8.2 One-time setup (GitHub → Settings → Secrets and variables → Actions)

| Name | Kind | Value |
|---|---|---|
| `DOCKERHUB_USERNAME` | Secret | Docker Hub account CI logs in as |
| `DOCKERHUB_TOKEN` | Secret | A Docker Hub **access token** with *Read & Write* scope (Account settings → Personal access tokens) — not the account password |
| `DOCKERHUB_NAMESPACE` | Variable (optional) | Org to publish under, if not the username. Recommended even when it's the same: a value taken from a secret is masked as `***` in CI logs |

A push to `main` without the two secrets fails the job with a message
pointing here, rather than silently skipping the publish. The repository is
created on first push; **set it to private on Docker Hub** if the image
shouldn't be public — it contains the full application code.

### 8.3 Deploying, upgrading, rolling back

Covered step by step in [deployment.md](deployment.md) §3–5. In short: set
`IMAGE_NAMESPACE` and pin `IMAGE_TAG` in `.env`; upgrade with `docker compose
pull`, then `docker compose run --rm migrate`, then `docker compose up -d` —
in that order, so a failed migration never takes the running version down.

### 8.4 Building locally

`make images` builds the image under the name compose expects
(`${IMAGE_NAMESPACE:-localhost}/advisory-hub:${IMAGE_TAG:-latest}`) — useful
for trying the production file on a machine without pulling. Development
(`docker compose up` with the override) builds `app`/`worker` itself and
never pulls them.


## 9. Microsoft 365: sign-in and mailbox sync (Entra ID)

Both are optional and configured on **/admin → Microsoft 365**; nothing is
read from Entra except who someone is (sign-in) and the one mailbox folder
(sync). **Roles always come from /admin → Users, never from Entra groups**
(D-049). Use **two separate app registrations**: a leaked sign-in secret must
not be able to read mail.

Prerequisites on the server: `OUTBOUND_ALLOWLIST` includes
`login.microsoftonline.com` and `graph.microsoft.com`, and (for sign-in)
`PUBLIC_BASE_URL` is set. Both apps' **Test** buttons check exactly this.

### 9.1 Microsoft sign-in

1. **Entra admin center → App registrations → New registration**:
   name `Advisory Hub sign-in`, *Accounts in this organizational directory
   only* (single tenant), redirect URI **Web** =
   `<PUBLIC_BASE_URL>/auth/entra/callback` (shown on the card).
2. **Certificates & secrets → New client secret.** Copy the *Value*.
3. **API permissions:** the default `User.Read` (delegated) is enough —
   the app requests only `openid profile email`. No admin consent, no
   application permissions, **no group claims**.
4. On /admin: Directory (tenant) ID, Application (client) ID, client secret
   → **Save** → **Test** → **Enable**.
5. **Users:** add each person under Users with their **Microsoft sign-in name
   (UPN) as the email**, a role, and no password. Their first Microsoft
   sign-in links the account (`tenant:object id`); after that the email can
   change in Entra and it still matches. Anyone not added is refused (and the
   refusal is audited as `auth.entra_refused`).
6. **Keep one local admin without Microsoft** (password only) as a
   break-glass account for when Entra is unreachable. Linked accounts can't
   use a password.

| What happens | Behaviour |
|---|---|
| Someone not added signs in with Microsoft | Refused; audited with their UPN/object id |
| A deactivated user signs in | Refused, same message (no account-state leak) |
| A linked user tries a password | "Invalid email or password" |
| Entra account deleted and re-created (new object id) | Refused (`email_linked_to_other_entra_object`) — **Unlink Microsoft** on their row, they sign in again |
| Sign out | Ends the app session only; not a Microsoft sign-out |

### 9.2 Mailbox sync

Imports every new message in one folder (e.g. `Inbox/Security Advisories`
of a shared mailbox) into the inbox, where the normal pipeline ingests it
(sandboxed parsing, duplicate gates D-048, archive/failed). **Read-only**:
nothing in the mailbox is marked, moved or deleted.

1. **App registration** `Advisory Hub mailbox`, single tenant, **no
   redirect URI**. New client secret. **Do not add Mail.Read in Entra** —
   an Entra-consented application permission is tenant-wide and would open
   every mailbox. Note the app's *Application (client) ID* and, under
   **Enterprise applications**, its *Object ID*.
2. **Exchange Online PowerShell** (`Connect-ExchangeOnline` as an Exchange
   admin) — RBAC for Applications, scoped to the one mailbox:

   ```powershell
   New-ServicePrincipal -AppId <client id> -ObjectId <enterprise app object id> -DisplayName "Advisory Hub mailbox"
   New-ManagementScope -Name "Advisory Hub mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'advisories@contoso.com'"
   New-ManagementRoleAssignment -App <client id> -Role "Application Mail.Read" -CustomResourceScope "Advisory Hub mailbox"
   # Check: InScope = True for the mailbox, False for any other
   Test-ServicePrincipalAuthorization -Identity <client id> -Resource advisories@contoso.com
   Test-ServicePrincipalAuthorization -Identity <client id> -Resource someone.else@contoso.com
   ```

   Role assignments can take up to an hour to apply.
3. On /admin: tenant ID, client ID, secret, mailbox, folder (`/`-separated
   from the top: `Inbox/Security Advisories`; `Inbox`, `Archive` etc. work in
   any mailbox language), interval (≥ 60 s, default 120) → **Save** →
   **Test** (shows the folder's message count) → **Enable**.

The worker checks the folder on that interval; **Sync now** on the card
does it immediately and ingests. The first sync imports everything already
in the folder. The card shows the last sync, its status/error and counts.

| Situation | Behaviour |
|---|---|
| Message larger than `UPLOAD_MAX_BYTES` | Skipped and counted on the card; download stops at the limit |
| Same email also arrives by file drop / upload | One advisory — duplicate gates (D-048) |
| Folder renamed / moved | Error on the card; fix the folder setting (the position resets) |
| Sync position expired (Graph 410) | Starts over automatically; duplicates stopped by the gates |
| `Access denied (HTTP 403)` | Exchange role assignment missing or not yet applied — re-run the `Test-ServicePrincipalAuthorization` check |
| Changing mailbox or folder | Sync position and counters reset |
