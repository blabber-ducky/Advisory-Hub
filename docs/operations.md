# Operations

Deployment, configuration, and runbooks. Update this doc whenever a container,
volume, environment variable, or operational step changes.

> **Deploying to production?** Follow [deployment.md](deployment.md) —
> `docker-compose.prod.yml`, step by step. This doc is the reference it
> links into: configuration, backups, runbooks, TLS, images.

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
pinned images from Docker Hub (§8), HTTPS only, hardened, migrations run
automatically. See [deployment.md](deployment.md). A production host needs
only that file, `.env`, `scripts/https-setup.sh` and its certificates — not
the source tree.

| File | Purpose |
|---|---|
| `docker-compose.yml` | Base stack. Pulls images; plain HTTP on `APP_PORT` |
| `docker-compose.override.yml` | Auto-applied in development: builds from the working tree, reload, published DB/Redis ports |
| `docker-compose.https.yml` | Overlay adding the TLS proxy to the base stack — for trying HTTPS outside production (§7) |
| `docker-compose.prod.yml` | **Production.** Self-contained; used alone |

Every file passes the whole `.env` into `app`/`worker`, so any variable in
§3 can be set there. (Until 2026-09-29 the base file passed only a
hand-picked subset — `VT_API_KEY`, `PDF_*`, `CSV_*`, the poll intervals and
`FERNET_KEY_PREVIOUS` set in `.env` silently had no effect under Compose.)

`APP_PORT` (default `8080`), `POSTGRES_PORT`, and `REDIS_PORT` are overridable
when a port is already taken.

**For anything users will actually log in to, serve it over HTTPS** — see §7.
One script (`scripts/https-setup.sh`) installs the certificate and switches
the stack to the HTTPS overlay; nothing about certificates is baked into the
repo or the image.

### CLI

| Command | Does |
|---|---|
| `create-admin` | Create an administrator (prompts for the password) |
| `create-token` | Mint a scoped API token — **shown once** |
| `list-users` | List accounts and roles |
| `check` | Verify database, blob volume, inbox, and schema |

## 1. Containers

| Service | Image | Role |
|---|---|---|
| `app` | `<IMAGE_NAMESPACE>/advisory-hub` (`docker/Dockerfile`) | FastAPI: UI, REST API, MCP HTTP transport |
| `worker` | same image, different command | RQ worker: ingestion, enrichment, inventory sync, scans |
| `migrate` | same image | **Production file only.** Runs `alembic upgrade head` and exits; `app`/`worker` start only after it succeeds |
| `proxy` | `<IMAGE_NAMESPACE>/advisory-hub-proxy` (`docker/nginx/Dockerfile`) | **Production file and HTTPS overlay only**: nginx with the site config baked in; terminates TLS, redirects HTTP → HTTPS, proxies to `app`. See §7. |

Inventory syncs are scheduled by a poller thread inside `worker` — there is
no separate scheduler container.
| `postgres` | `postgres:16-alpine` | System of record |
| `redis` | `redis:7-alpine` | Job queue, NVD cache, rate limiting |

## 2. Volumes

| Mount | Purpose | Backed up |
|---|---|---|
| `/data/inbox` | Power Automate drop target (also mounted on the Windows/PA side) | No — transient |
| `/data/processing` | Worker claim area | No |
| `/data/archive` | Successfully ingested originals | **Yes** |
| `/data/failed` | Failed ingests + `.error.json` sidecars | **Yes** |
| `/data/blobs` | Content-addressed store | **Yes — critical** |
| `pgdata` | PostgreSQL | **Yes — critical** |

**`/data/inbox` is a named volume by default**, isolated inside Docker. Set
`INBOX_HOST_PATH` (compose-level, not read by the app itself — see §3) to an
absolute host path to bind-mount a real folder there instead — e.g. one a
Power Automate flow or a mail rule on this host writes `.msg` files into
directly. `inbox/` being on a different filesystem than `processing/` this
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
| `INBOX_HOST_PATH` | no | **Compose-level only, not read by the app.** Absolute host path bind-mounted at `/data/inbox` in place of the internal named volume — set this to point the watcher at a real folder of emails. Unset keeps the named volume. |
| `INBOX_POLL_SECONDS` | no | Default `30` |
| `NVD_API_KEY` | recommended | Raises the rate limit from 5 → 50 requests per 30s. **Overridden by an admin-panel-configured key** (`/admin`, ADMIN role) if one is set — see docs/decisions.md D-031. Either way works; the admin panel takes effect immediately, no restart. |
| `NVD_ENABLED` | no | Default `true`; `false` for air-gapped operation. Also overridable per D-031 — disabling from `/admin` wins over this. |
| `VT_API_KEY` | no | VirusTotal API key for the analyst-triggered "Check on VirusTotal" IOC action. Same admin-panel override as `NVD_API_KEY`. Unset (both here and in the admin panel): the button/endpoint still exists, but returns a clear "not configured" error (`502`) rather than being hidden. |
| `VT_ENABLED` | no | Default `true`. Overridable from `/admin` per D-031. |
| `PDF_MAX_BYTES` | no | Default `52428800` (50 MB) |
| `PDF_MAX_PAGES` | no | Default `500` |
| `PDF_TIMEOUT_SECONDS` | no | Default `120` |
| `OCR_ENABLED` | no | Default `false` — turn on only if scanned PDFs actually appear |
| `OUTBOUND_ALLOWLIST` | yes (Phase 2) | Comma-separated hostnames the SSRF guard permits. For the Azure ARM and MS Graph adapters this must include **both** the API host (`management.azure.com` / `graph.microsoft.com`) **and** `login.microsoftonline.com` — the OAuth token endpoint is a separate outbound call, also SSRF-checked. |
| `CSV_MAX_BYTES` | no | Default `20971520` (20 MB) — inventory CSV upload size cap |
| `CSV_MAX_ROWS` | no | Default `200000` — inventory CSV row cap, enforced while parsing |
| `INVENTORY_SYNC_POLL_SECONDS` | no | Default `300` — how often the worker checks active API sources for a due `schedule_cron` |
| `IMAGE_NAMESPACE` | yes (production) | **Compose-level.** Docker Hub user/org the images are pulled from, e.g. `acme` → `acme/advisory-hub`. Unset → `localhost/…`: only locally built images work, and a pull fails loudly rather than fetching from someone else's namespace. See §8. |
| `IMAGE_TAG` | recommended | **Compose-level.** Image tag for `app`/`worker`/`proxy`. Default `latest`; pin a release (`1.4.0`) or commit (`sha-1a2b3c4`) in production. |
| `WEB_CONCURRENCY` | no | **Production file.** uvicorn processes for `app`. Default `1`; each extra costs ~100 MB — raise `app`'s memory limit in `docker-compose.prod.yml` to match |
| `BIND_ADDRESS` | no | **Compose-level, production file.** Host interface the proxy listens on. Default `0.0.0.0`; set the internal NIC's address to keep it off other interfaces |
| `POSTGRES_PASSWORD` | yes (production) | **Compose-level.** Database password, embedded in `DATABASE_URL` by compose — use hex (`openssl rand -hex 32`) so it's URL-safe. Only read when the database volume is first created |
| `SESSION_COOKIE_SECURE` | no | Default `true`; `false` only for local HTTP dev. The HTTPS overlay forces `true`. |
| `COMPOSE_FILE` | production / HTTPS | **Compose-level.** Which compose file(s) plain `docker compose …` uses. `docker-compose.prod.yml` in production (set by `.env.production.example`); `docker-compose.yml:docker-compose.https.yml` for the HTTPS overlay (written by `scripts/https-setup.sh`, which leaves a production value alone). Either one also stops `docker-compose.override.yml` being applied. |
| `SERVER_NAME` | HTTPS only | **Compose-level.** Hostname users browse to; must be in the certificate's subjectAltName. |
| `HTTP_PORT` / `HTTPS_PORT` | no | **Compose-level.** Host ports for the proxy. Default `80` / `443`. |
| `TLS_CERT_DIR` | no | **Compose-level.** Host directory with `server.crt` + `server.key`, mounted read-only into the proxy. Default `./certs` (git-ignored). |
| `HSTS_MAX_AGE` | no | **Compose-level.** Seconds for `Strict-Transport-Security`. Default `31536000` (1 year); `0` disables. The script sets `0` for self-signed certificates. |
| `LOG_LEVEL` | no | Default `INFO` |

## 4. Backup

Critical set: `pgdata`, `/data/blobs`, `/data/archive`, `/data/failed`, and the
`FERNET_KEY` (stored separately — in your secrets manager, not next to the DB dump).

```bash
# Database
docker compose exec -T postgres pg_dump -U advisory_hub -Fc advisory_hub \
  > backup/db-$(date +%F).dump

# Blobs — content-addressed, so incremental sync is safe and cheap
rsync -a --delete /data/blobs/ /backup/blobs/
rsync -a /data/archive/ /backup/archive/
```

**Restore is not backup.** Exercise a full restore into a scratch environment at
least once per quarter and record the date. A restore that has never been tried
is a hypothesis.

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

**`docker-compose.prod.yml` always serves HTTPS** through its `proxy` — for
production you only need the certificate steps below (§7.1–7.3). Outside
production, `docker-compose.https.yml` adds the same proxy to the base stack
as an **overlay**. Either way, certificates are **never** stored in the repo
or generated at build time — they are installed per deployment with
`scripts/https-setup.sh`, into `./certs/` (git-ignored) by default.

```
browser ──HTTPS :443──▶ proxy (nginx, TLS) ──HTTP :8000──▶ app
browser ──HTTP  :80───▶ proxy ──301──▶ https://…
```

What the overlay changes:

| | Plain (`docker-compose.yml`) | HTTPS overlay |
|---|---|---|
| Entry point | `app` on `APP_PORT` (8080) | `proxy` on `HTTPS_PORT` (443); port 80 only redirects |
| `app`'s own port on the host | published | **not published** — reachable only through the proxy |
| Session cookie | `Secure` per `SESSION_COOKIE_SECURE` | always `Secure` |
| Client IP in audit log / sessions | the caller | the real caller, via `X-Forwarded-For` (uvicorn trusts it because `FORWARDED_ALLOW_IPS=*` — safe only because `app` isn't published) |
| TLS | — | TLS 1.2/1.3, Mozilla "intermediate" ciphers, HSTS, `nosniff`, `X-Frame-Options: DENY` |
| Upload limit | — | 25 MB (just above `CSV_MAX_BYTES`, so the app, not nginx, gives the error) |
| Proxy timeout | — | 300 s — "Scan inbox now", "Sync now" and scans are synchronous |

### 7.1 The script

Run from the repository root on the deployment host. Requires `openssl`
(1.1.1 or later) and an existing `.env`.

| Command | Does |
|---|---|
| `install --cert F --key F [--chain F] [--ca F] --server-name H [--reload]` | Validates, installs to `certs/server.crt` (leaf + chain, 644) and `certs/server.key` (600), backs up any existing pair as `*.bak-<timestamp>`, and runs `enable` |
| `csr --server-name H [--san LIST]` | Generates an RSA-3072 key and `certs/server.csr` to send to your CA. Refuses to overwrite an existing key |
| `self-signed --server-name H [--san LIST] [--days N]` | Testing / bridging only. Generates a pair, sets `HSTS_MAX_AGE=0`, runs `enable` |
| `check` | Re-validates the installed pair and confirms `.env` uses the overlay |
| `enable --server-name H` | Writes `SERVER_NAME`, `SESSION_COOKIE_SECURE=true`, `COMPOSE_FILE` to `.env` (cert must already be installed) |
| `disable` | Removes `COMPOSE_FILE` from `.env` (back to plain HTTP on `APP_PORT`) |

`--san` takes extra names in OpenSSL form, e.g. `"DNS:advisoryhub,IP:10.0.4.20"`.
`--cert-dir DIR` overrides `./certs`; `ENV_FILE=…` overrides `./.env`.

What `install` checks before touching anything — any failure stops it:

| Check | Fails when |
|---|---|
| Parse | Certificate isn't PEM, or key isn't PEM |
| Key is unencrypted | Key has a passphrase — nginx can't prompt. Decrypt with `openssl pkey -in enc.key -out server.key` |
| Key ↔ certificate | The key's public half doesn't match the certificate's |
| Expiry | Already expired (warns if under 30 days) |
| Hostname | `--server-name` isn't in the certificate's subjectAltName |
| Chain (only with `--ca`) | Leaf doesn't verify to the given root — usually a missing `--chain` |
| Self-signed | Warns only |

### 7.2 Deploying with a certificate from your CA (the normal path)

```bash
# 1. On the deployment host, create a key + CSR. The key never leaves the host.
scripts/https-setup.sh csr --server-name advisoryhub.corp.example \
    --san "DNS:advisoryhub"

# 2. Send certs/server.csr to your CA / PKI team. When the signed cert comes back:
scripts/https-setup.sh install --cert advisoryhub.crt --chain issuing-ca.crt \
    --key certs/server.key --server-name advisoryhub.corp.example \
    --ca corp-root-ca.crt

# 3. Start (or restart) the stack on the overlay.
docker compose up -d --remove-orphans
docker compose ps           # proxy should be "healthy"
```

If you were handed a certificate **and** key already (e.g. a wildcard), skip
step 1 and pass both to `install`.

Then check from a client:

```bash
curl -I https://advisoryhub.corp.example/health/live   # 200, strict-transport-security header
curl -I http://advisoryhub.corp.example/               # 301 to https://
```

### 7.3 Renewing / replacing the certificate

Same `install` command with the new files, plus `--reload` — nginx re-reads
the certificate without dropping connections; no app restart. The previous
pair is kept as `certs/server.*.bak-<timestamp>`.

```bash
scripts/https-setup.sh install --cert new.crt --chain issuing-ca.crt \
    --key certs/server.key --server-name advisoryhub.corp.example --reload
scripts/https-setup.sh check     # add to a monthly reminder — warns under 30 days
```

(To reuse the existing key, point `--key` at `certs/server.key`; to rotate
the key, move it aside and run `csr` again first.)

### 7.4 Before a CA certificate is available

`scripts/https-setup.sh self-signed --server-name advisoryhub.corp.example`
gets TLS working immediately. Browsers will warn until the certificate is
trusted on each client, and HSTS is left **off** (`HSTS_MAX_AGE=0`) so users
can still click through. When the real certificate arrives, run `install`
and delete the `HSTS_MAX_AGE=0` line from `.env`.

### 7.5 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `SERVER_NAME must be set` on `docker compose up` | `.env` has `COMPOSE_FILE` but no `SERVER_NAME` — run `enable --server-name …` |
| `proxy` restarting, log says `cannot load certificate` | Nothing in `TLS_CERT_DIR`, or the key isn't readable. With rootless Docker or user-namespace remapping, `chmod 640 certs/server.key` and give the container's group read access |
| Login redirects straight back to the login page | You're on plain HTTP (e.g. after `disable`, via `APP_PORT`) — the `Secure` cookie isn't sent. Use the `https://` URL |
| Browser: `NET::ERR_CERT_COMMON_NAME_INVALID` | Browsing by a name/IP not in the SAN. Re-issue with that name in `--san` |
| Browser: "incomplete chain" on some clients only | `server.crt` lacks the intermediate — re-run `install` with `--chain` |
| Audit log shows the proxy's IP for every user | `app` started without the overlay's `FORWARDED_ALLOW_IPS` — check `docker compose config` includes `docker-compose.https.yml` |
| Port 80/443 already in use | Set `HTTP_PORT` / `HTTPS_PORT` in `.env` |

## 8. Images and publishing

CI (`.github/workflows/ci.yml`, job `images`) builds and publishes two
images to Docker Hub. Compose pulls them; only development builds locally.

| Image | Dockerfile | Runs as |
|---|---|---|
| `<namespace>/advisory-hub` | `docker/Dockerfile` | `app` **and** `worker` — same code, different command, so one image |
| `<namespace>/advisory-hub-proxy` | `docker/nginx/Dockerfile` | `proxy` (HTTPS overlay) — `nginx:1.27-alpine` + `docker/nginx/advisory-hub.conf.template`. Certificates are never in the image. |

Both are multi-arch (`linux/amd64`, `linux/arm64`) and carry an SBOM and
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
pointing here, rather than silently skipping the publish. The repositories
are created on first push; **set them to private on Docker Hub** if the
images shouldn't be public — the image contains the full application code.

### 8.3 Deploying, upgrading, rolling back

Covered step by step in [deployment.md](deployment.md) §3–5. In short: set
`IMAGE_NAMESPACE` and pin `IMAGE_TAG` in `.env`; upgrade with `docker compose
pull`, then `docker compose run --rm migrate`, then `docker compose up -d` —
in that order, so a failed migration never takes the running version down.

### 8.4 Building locally

`make images` builds both under the names compose expects
(`${IMAGE_NAMESPACE:-localhost}/…:${IMAGE_TAG:-latest}`) — useful for
trying the HTTPS overlay on a machine without pulling. Development
(`docker compose up` with the override) builds `app`/`worker` itself and
never pulls them.
