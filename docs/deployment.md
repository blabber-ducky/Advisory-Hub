# Production deployment

How to stand up, upgrade, and roll back Advisory Hub on a production host
with `docker-compose.prod.yml`. For configuration reference, backups and
runbooks see [operations.md](operations.md); for the TLS script in depth,
[operations.md §7](operations.md#7-https); for how images are built and
tagged, [operations.md §8](operations.md#8-images-and-publishing).

> **Which compose file?**
>
> | File | Use for |
> |---|---|
> | `docker-compose.prod.yml` | **Production.** Self-contained; this guide. |
> | `docker-compose.yml` + `docker-compose.override.yml` | Development — builds from the working tree, plain HTTP on 8080. |
> | `docker-compose.yml` + `docker-compose.https.yml` | Trying HTTPS on a dev/staging stack. Not hardened like the production file. |

## 1. What the production stack looks like

```
                 :443 HTTPS  (:80 → 301 redirect)
 users ─────────────────────────┐
                                ▼
                     ┌─────────────────────┐        network: edge
                     │ proxy  (nginx, TLS) │
                     └──────────┬──────────┘
                                │ HTTP :8000 (not published on the host)
                     ┌──────────▼──────────┐   ─────► VirusTotal, inventory APIs
                     │ app   (FastAPI)     │
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
| `proxy` | `<namespace>/advisory-hub-proxy` | **80, 443** — the only published ports | TLS 1.2/1.3, HSTS, HTTP → HTTPS |
| `app` | `<namespace>/advisory-hub` | no | uvicorn, `WEB_CONCURRENCY` processes (default 1) |
| `worker` | same image | no | Inbox, NVD and inventory-sync pollers + RQ jobs |
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
| No host ports except the proxy | all others | Plain HTTP can't bypass TLS; `FORWARDED_ALLOW_IPS=*` is only safe because of this |
| Memory/CPU limits | every service | One runaway PDF can't starve the database. Worker 2 GB, app 1 GB, postgres 2 GB, redis 512 MB, proxy 256 MB |
| Log rotation (20 MB × 5 per container) | every service | Logs can't fill the disk |
| Required secrets, no defaults | `SECRET_KEY`, `POSTGRES_PASSWORD`, `FERNET_KEY`, `IMAGE_NAMESPACE`, `IMAGE_TAG`, `SERVER_NAME` | The stack refuses to start rather than run with a development value |
| Pinned image tag, no `latest` default | app, worker, proxy | Every host runs a known build; upgrades are deliberate |

The proxy keeps nginx's default capabilities (it binds 80/443 and drops to
an unprivileged user itself).

## 2. Prerequisites

| Need | Detail |
|---|---|
| Linux host with Docker Engine + Compose plugin | Compose **≥ 2.24**. `docker compose version` |
| CPU / RAM / disk | 2 vCPU, 4 GB RAM minimum. Disk: the blob, archive and database volumes grow with every advisory — start with 50 GB and monitor (operations.md §6) |
| DNS name | e.g. `advisoryhub.corp.example`, resolving to the host |
| TLS certificate for that name | From your internal CA, or created with `scripts/https-setup.sh csr` |
| Inbound | 443 (and 80 for the redirect) from users' network |
| Outbound | Docker Hub (image pulls); `services.nvd.nist.gov`; `www.virustotal.com` if used; inventory API hosts |
| Docker Hub access | If the image repositories are private: a read-only access token for `docker login` |
| Published images | CI must have pushed the tag you'll deploy (operations.md §8) |

## 3. First install

Only these files are needed on the host — not the source tree:

```
/opt/advisory-hub/
  docker-compose.prod.yml
  .env                       ← from .env.production.example
  scripts/https-setup.sh
  certs/                     ← created by the script
```

```bash
# 1. Fetch the files for the release you're deploying (tag v1.4.0 here).
sudo mkdir -p /opt/advisory-hub/scripts && cd /opt/advisory-hub
REL=https://raw.githubusercontent.com/blabber-ducky/Advisory-Hub/v1.4.0
curl -fsSLO $REL/docker-compose.prod.yml
curl -fsSL  $REL/.env.production.example -o .env
curl -fsSL  $REL/scripts/https-setup.sh -o scripts/https-setup.sh
chmod 600 .env && chmod +x scripts/https-setup.sh
```

If the GitHub repository is private, `curl` needs a token
(`-H "Authorization: token …"`) — or copy the three files over with `scp`.

```bash
# 2. Generate secrets into .env — replace each CHANGE_ME:
openssl rand -base64 48 | tr -d '\n'     # SECRET_KEY
openssl rand -hex 32                     # POSTGRES_PASSWORD (hex: it's embedded in a URL)
openssl rand -base64 32 | tr '+/' '-_'   # FERNET_KEY
#    …and set IMAGE_NAMESPACE, IMAGE_TAG=1.4.0, OUTBOUND_ALLOWLIST,
#    and INBOX_HOST_PATH if Power Automate writes to a folder on this host.
```

**Store `FERNET_KEY` and `POSTGRES_PASSWORD` in your secrets manager now.**
A database backup is useless for credentials without the Fernet key.

```bash
# 3. Certificate. Normal path: CSR → your CA → install.
scripts/https-setup.sh csr --server-name advisoryhub.corp.example
#    send certs/server.csr to the CA, then:
scripts/https-setup.sh install --cert advisoryhub.crt --chain issuing-ca.crt \
    --key certs/server.key --server-name advisoryhub.corp.example
#    (sets SERVER_NAME; leaves COMPOSE_FILE=docker-compose.prod.yml alone)

# 4. Pull and start. Migrations run automatically before app/worker.
docker login                 # only if the image repositories are private
docker compose pull
docker compose up -d
docker compose ps            # all "healthy"; migrate "Exited (0)"

# 5. First administrator, and reference data.
docker compose exec app python -m advisory_hub.cli create-admin
docker compose exec app python -m advisory_hub.cli seed-sources
docker compose exec app python -m advisory_hub.cli seed-vendor-aliases
```

### Verify

```bash
curl -sI https://advisoryhub.corp.example/health/live   # 204, strict-transport-security present
curl -sI http://advisoryhub.corp.example/               # 301 → https://
docker compose exec app python -m advisory_hub.cli check
docker compose logs worker | grep -c "Exception in thread"   # must be 0
```

Then sign in, and drop one `.msg` into the inbox folder: it should appear on
the tracker within `INBOX_POLL_SECONDS` (30 s) without pressing "Scan inbox
now".

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
| Renew certificate | `scripts/https-setup.sh install … --reload` (operations.md §7.3) |
| Certificate expiry check | `scripts/https-setup.sh check` — warns under 30 days |
| Restart one service | `docker compose restart worker` |
| Stop everything | `docker compose down` — **never `down -v`**, which deletes the database and blob volumes |

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `required variable X is missing a value` | `.env` still has `CHANGE_ME` or lacks the variable — every required one is listed in `.env.production.example` |
| `pull access denied for …/advisory-hub` | Wrong `IMAGE_NAMESPACE`/`IMAGE_TAG`, tag never published, or private repo without `docker login` |
| `app` never healthy / "Created" not "Up"; `migrate` exited non-zero | Migration failed and app/worker were not started — `docker compose logs migrate`. Fix, or set `IMAGE_TAG` back and `docker compose up -d`. (Upgrade with `run --rm migrate` first to avoid this — §4) |
| `password authentication failed` | `POSTGRES_PASSWORD` changed after the database volume was created. Postgres only reads it on first start — change it inside Postgres (`ALTER USER`) or restore the old value |
| Emails sit in the inbox folder | Check the worker log for `Exception in thread`; `INBOX_HOST_PATH` must be an absolute path the container user (uid 10001) can write |
| Integrations fail with SSRF errors | Host not in `OUTBOUND_ALLOWLIST` |
| `Read-only file system` in a log | Something wrote outside `/tmp` or `/data/*` — a bug worth reporting, not a reason to drop `read_only` |
| Proxy restarting | Certificate missing/unreadable — `scripts/https-setup.sh check`; see operations.md §7.5 |
