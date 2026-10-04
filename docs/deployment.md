# Production deployment

How to stand up, upgrade, and roll back Advisory Hub on a production host
with `docker-compose.prod.yml`. For configuration reference, backups and
runbooks see [operations.md](operations.md); for how the image is built and
tagged, [operations.md §8](operations.md#8-images-and-publishing).

> **Which compose file?**
>
> | File | Use for |
> |---|---|
> | `docker-compose.prod.yml` | **Production.** Self-contained; this guide. |
> | `docker-compose.yml` + `docker-compose.override.yml` | Development — builds from the working tree, plain HTTP on 8080. |

**TLS is not part of this stack.** The app speaks plain HTTP; HTTPS, HSTS,
the HTTP→HTTPS redirect and certificates are the job of the enterprise WAF
or reverse proxy in front of it (F5 BIG-IP, Citrix ADC, Imperva, Azure
Application Gateway, …). Don't put the app in front of users without one —
the session cookie is always `Secure`, so sign-in only works over HTTPS.

## 1. What the production stack looks like

```
                 HTTPS — terminated by your WAF / reverse proxy (outside this stack)
 users ─────────────────────────┐
                                ▼
                    enterprise WAF / reverse proxy
                                │ plain HTTP :<APP_PORT>  (firewalled: WAF only)
                     ┌──────────▼──────────┐        network: frontend
                     │ app   (FastAPI)     │   ─────► VirusTotal, inventory APIs
                     └──────────┬──────────┘
          network: backend      │           (internal — no route out)
        ┌───────────────────────┼─────────────────────────┐
        │   ┌──────────────┐  ┌─▼────────────┐  ┌───────┐ │
        │   │ postgres     │  │ redis        │  │worker │─┼──► NVD, VirusTotal,
        │   └──────────────┘  └──────────────┘  └───────┘ │    inventory APIs
        │   migrate (runs `alembic upgrade head`, exits)  │    (network: egress)
        └─────────────────────────────────────────────────┘
```

| Service | Image | Published | Notes |
|---|---|---|---|
| `app` | `<namespace>/advisory-hub` | **`APP_PORT`** (default 8000) — the only published port | uvicorn, `WEB_CONCURRENCY` processes (default 1) |
| `worker` | same image | no | Inbox, NVD and inventory-sync pollers + RQ jobs |
| `init-data` | same image | no | One-shot, first: creates `./data/<volume>` and sets ownership; no network, only file-ownership privileges |
| `migrate` | same image | no | One-shot, every `up`; app/worker wait for it to succeed |
| `postgres` | `postgres:16-alpine` | no | Backend network only — cannot reach the internet |
| `redis` | `redis:7-alpine` | no | Queue, not cache: AOF persistence, `noeviction` |

### Hardening, and why

| Control | Applied to | Why |
|---|---|---|
| Read-only root filesystem, `/tmp` as 512 MB tmpfs | app, worker, migrate | These parse hostile PDFs and email. A compromise can't persist or modify code. Data volumes stay writable |
| All Linux capabilities dropped | app, worker, migrate | They run as a non-root user and need none (verified: `CapEff: 0`) |
| `no-new-privileges` | every service | Blocks privilege gain through setuid binaries |
| Internal `backend` network | postgres, redis | Database and queue have no route in or out except via their clients |
| Only `app` published | all others | Nothing else is reachable from the host network |
| Forwarded headers trusted only from `TRUSTED_PROXY_IPS` | app | `app`'s port is reachable by whatever the firewall allows; trusting every peer (`*`) would let anyone who can reach it spoof `X-Forwarded-For`/`-Proto` and poison the audit log. See D-040 |
| Memory/CPU limits | every service | One runaway PDF can't starve the database. Worker 2 GB, app 1 GB, postgres 2 GB, redis 512 MB |
| Log rotation (20 MB × 5 per container) | every service | Logs can't fill the disk |
| All data in `./data/<volume>` host folders | every service | Backup and restore are file operations on one directory (operations.md §4) |
| Required values, no defaults | `SECRET_KEY`, `POSTGRES_PASSWORD`, `FERNET_KEY`, `IMAGE_NAMESPACE`, `IMAGE_TAG`, `TRUSTED_PROXY_IPS` | The stack refuses to start rather than run with a development value |
| Pinned image tag, no `latest` default | app, worker, migrate | Every host runs a known build; upgrades are deliberate |

### What your WAF / reverse proxy must do

The stack can't enforce any of this — it's the operator's side of the
boundary:

| Requirement | Why |
|---|---|
| Terminate TLS, forward plain HTTP to `http://<host>:<APP_PORT>` | `app` has no TLS listener |
| Forward `Host`, `X-Forwarded-For` and `X-Forwarded-Proto` unmodified | So the audit log and sessions record the real client IP |
| Set HSTS and redirect HTTP → HTTPS | Not done by the stack |
| Be the **only** thing that can reach `APP_PORT` | Firewall it to the WAF's network path. A missing or too-broad rule — not a bug in the stack — is what would let someone bypass the WAF |

## 2. Prerequisites

| Need | Detail |
|---|---|
| Linux host with Docker Engine + Compose plugin | Compose **≥ 2.24**. `docker compose version` |
| CPU / RAM / disk | 2 vCPU, 4 GB RAM minimum. Disk: `./data/` (database, blobs, archive) grows with every advisory — put the deployment folder on a disk with room, start with 50 GB and monitor (operations.md §6) |
| WAF / reverse proxy | Terminating TLS for the users' hostname (e.g. `advisoryhub.corp.example`), with this host as its backend |
| The WAF's own IP address(es) | For `TRUSTED_PROXY_IPS` — every address it connects *from*, e.g. both nodes of an HA pair |
| Inbound | `APP_PORT` from the WAF only — firewalled from everything else |
| Outbound | Docker Hub (image pulls); `services.nvd.nist.gov`; `www.virustotal.com` if used; inventory API hosts |
| Docker Hub access | If the image repository is private: a read-only access token for `docker login` |
| Published image | CI must have pushed the tag you'll deploy (operations.md §8) |

## 3. First install

Only two files are needed on the host — not the source tree. The data
folders are created on first start:

```
/opt/advisory-hub/
  docker-compose.prod.yml
  .env                       ← from .env.production.example
  data/                      ← created by init-data: pgdata, redisdata, blobs,
                               inbox, processing, archive, failed
```

**Everything the stack stores is in `/opt/advisory-hub/data/`.** Back it up
together with `.env` (operations.md §4).

If this host ran an older version that used Docker named volumes, copy them
into `./data` first (operations.md §4, "Moving an existing stack").
Otherwise the stack starts with an empty database.

```bash
# 1. Fetch the files for the release you're deploying (tag v1.4.0 here).
sudo mkdir -p /opt/advisory-hub && cd /opt/advisory-hub
REL=https://raw.githubusercontent.com/blabber-ducky/Advisory-Hub/v1.4.0
curl -fsSLO $REL/docker-compose.prod.yml
curl -fsSL  $REL/.env.production.example -o .env
chmod 600 .env
```

If the GitHub repository is private, `curl` needs a token
(`-H "Authorization: token …"`) — or copy the two files over with `scp`.

```bash
# 2. Fill in .env — replace each CHANGE_ME:
openssl rand -base64 48 | tr -d '\n'     # SECRET_KEY
openssl rand -hex 32                     # POSTGRES_PASSWORD (hex: it's embedded in a URL)
openssl rand -base64 32 | tr '+/' '-_'   # FERNET_KEY
#    …and IMAGE_NAMESPACE, IMAGE_TAG=1.4.0,
#    TRUSTED_PROXY_IPS (the WAF's own address(es), comma-separated, not a CIDR),
#    OUTBOUND_ALLOWLIST, and INBOX_HOST_PATH if Power Automate writes to a
#    folder on this host.
```

**Store `FERNET_KEY` and `POSTGRES_PASSWORD` in your secrets manager now.**
A database backup is useless for credentials without the Fernet key.

```bash
# 3. Pull and start. Migrations run automatically before app/worker.
docker login                 # only if the image repository is private
docker compose pull
docker compose up -d
docker compose ps            # all "healthy"; migrate "Exited (0)"

# 4. First administrator, and reference data.
docker compose exec app python -m advisory_hub.cli create-admin
docker compose exec app python -m advisory_hub.cli seed-sources
docker compose exec app python -m advisory_hub.cli seed-vendor-aliases
```

Then point the WAF's backend pool at `http://<this-host>:<APP_PORT>`.

### Verify

```bash
# Through the WAF — not directly against the host, which should be unreachable:
curl -sI https://advisoryhub.corp.example/health/live   # 204
# On the host:
docker compose exec app python -m advisory_hub.cli check
docker compose logs worker | grep -c "Exception in thread"   # must be 0
```

Then:

- Sign in from two different machines, and confirm the audit log recorded
  two distinct client IPs, not the WAF's own address:
  `docker compose exec postgres psql -U advisory_hub -c "select distinct ip_address from audit_log order by 1"`.
- From a machine that isn't the WAF, confirm `http://<this-host>:<APP_PORT>/`
  does **not** answer — the firewall is doing its job.
- Drop one `.msg` into the inbox folder: it should appear on the tracker
  within `INBOX_POLL_SECONDS` (30 s) without pressing "Scan inbox now".

## 4. Upgrading

```bash
cd /opt/advisory-hub
# Back up first — operations.md §4.
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=1.5.0/' .env
# Replace docker-compose.prod.yml too if the release notes say it changed.
docker compose pull
docker compose run --rm migrate   # migrate FIRST, while the old version keeps serving
docker compose up -d              # only then swap app/worker (migrate re-runs as a no-op)
docker compose ps
```

**Don't skip the separate `run --rm migrate`.** A plain `up -d` also migrates
first, but if the migration fails, Compose has *already removed* the old app
and worker containers and won't start the new ones — the site is down until
it's fixed (verified). Running it on its own means a failed migration leaves
the old version serving untouched: read the output, fix or roll back
`IMAGE_TAG`, and nothing else has changed.

## 5. Rolling back

| Situation | Do |
|---|---|
| New release had **no migration** | Set `IMAGE_TAG` back, `docker compose up -d` |
| New release **ran a migration** | First, *with the new image still running*: `docker compose exec app alembic downgrade <previous revision>` — the old image doesn't know the new revision. Then set `IMAGE_TAG` back and `docker compose up -d` |
| Migration can't be reversed cleanly | Restore the database from the pre-upgrade backup (operations.md §4) |

## 6. Day to day

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f app worker` (JSON; rotated at 20 MB × 5) |
| CLI | `docker compose exec app python -m advisory_hub.cli <command>` (operations.md, CLI table) |
| Restart one service | `docker compose restart worker` |
| Stop everything | `docker compose down` — data in `./data/` is untouched |
| Back up | Stop, archive `./data/`, start — or a no-downtime `pg_dump` + file sync (operations.md §4) |
| Restore | operations.md §4 — same `.env` as the backup |

Certificates, renewals and TLS settings are managed on the WAF, not here.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `required variable X is missing a value` | `.env` still has `CHANGE_ME` or lacks the variable — every required one is listed in `.env.production.example` |
| `pull access denied for …/advisory-hub` | Wrong `IMAGE_NAMESPACE`/`IMAGE_TAG`, tag never published, or private repo without `docker login` |
| `app` never healthy / "Created" not "Up"; `migrate` exited non-zero | Migration failed and app/worker were not started — `docker compose logs migrate`. Fix, or set `IMAGE_TAG` back and `docker compose up -d`. (Upgrade with `run --rm migrate` first to avoid this — §4) |
| `password authentication failed` | `POSTGRES_PASSWORD` changed after the database volume was created. Postgres only reads it on first start — change it inside Postgres (`ALTER USER`) or restore the old value |
| Sign-in loops back to the sign-in page | You're reaching the app over plain HTTP (directly, or via a WAF listener without TLS). The session cookie is always `Secure` and browsers won't send it over HTTP — go through the WAF's HTTPS address |
| Audit log / sessions show the WAF's own IP for every user | `TRUSTED_PROXY_IPS` doesn't match the address the WAF actually connects from (an HA pair with two egress IPs, or the WAF behind its own NAT) — add every address it can appear as |
| `app` reachable directly, bypassing the WAF | Firewall gap, not a stack bug — `APP_PORT` must be unreachable except from the WAF's network path |
| Emails sit in the inbox folder | Check the worker log for `Exception in thread`. If `INBOX_HOST_PATH` is set, it must be an absolute path the container user (uid 10001) can write — `init-data` only manages `./data` |
| `Permission denied` under `/data/...` in app/worker logs | `init-data` didn't run or failed — `docker compose logs init-data`. It needs to start as root with the `CHOWN` capability; check nothing (e.g. rootless Docker or a user-namespace remap) prevents that |
| Database empty after an upgrade | The host used Docker named volumes before; `./data/pgdata` started fresh. Stop, copy the old volumes in (operations.md §4, "Moving an existing stack"), start |
| Integrations fail with SSRF errors | Host not in `OUTBOUND_ALLOWLIST` |
| `Read-only file system` in a log | Something wrote outside `/tmp` or `/data/*` — a bug worth reporting, not a reason to drop `read_only` |
