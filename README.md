# CertMgr — Enterprise SSL Certificate Lifecycle Management Platform

**CertMgr** is a production-grade, self-hosted platform for issuing, renewing,
revoking, importing, deploying, monitoring and auditing SSL/TLS certificates at
enterprise scale — thousands of certificates across hundreds of Linux servers.

It is **not** a simple Certbot frontend. It is a complete certificate lifecycle
management platform with a plugin-based provider architecture (Let's Encrypt
today; DigiCert, GoDaddy, Sectigo, GlobalSign, Entrust, MS ADCS and internal PKI
plug in without core changes), a remote deployment engine, automatic discovery,
compliance, reporting, RBAC, audit, notifications, webhooks, background job
processing and an AI-assisted troubleshooter.

---

## Highlights

| Capability | Implementation |
|---|---|
| **Issuance** | Let's Encrypt via Certbot (ACME v2) + Internal PKI (OpenSSL CA) providers; HTTP-01, DNS-01, manual, standalone, webroot, custom hooks |
| **Key types** | RSA 2048/4096, ECDSA P-256/P-384 |
| **Renewal** | Daily Celery sweep within configurable thresholds, automatic retries, staging/dry-run support |
| **Revocation** | Provider-native revoke + local material cleanup |
| **Import** | PEM/CRT/CER/PFX with automatic metadata extraction (issuer, SAN, fingerprint, algorithm, key size) |
| **Private key safety** | Keys are **never stored in the database** — always Fernet-encrypted at rest on disk |
| **Database** | PostgreSQL 12+ (primary), **MariaDB/MySQL** (supported fallback — reuse an existing instance, see `docs/installation.md`), SQLite (dev/tests) |
| **Deployment engine** | SSH/SFTP/SCP/rsync; Apache/Nginx/HAProxy/OpenVPN/Tomcat/Jetty/Node/IIS/custom templates; backup → replace → reload → TLS verify → automatic rollback |
| **Discovery** | Scheduled scans of `/etc/letsencrypt`, `/etc/pki`, `/etc/nginx`, custom paths; auto-import |
| **Server management** | Inventory, connectivity checks, restricted remote command center (allowlist), service control |
| **Monitoring** | Health scores (expiry, chain, hostname, key strength, TLS), compliance engine |
| **Notifications** | SMTP, Slack, Microsoft Teams, generic signed webhooks; thresholds 60/30/15/7/3/1 days + lifecycle events |
| **RBAC** | 4 roles × granular permission codes; JWT + refresh tokens + API tokens + TOTP MFA |
| **Audit** | Every action recorded with user, IP, browser, duration, result |
| **Background jobs** | Celery workers + beat; issuance/renewal/deployment/notifications/discovery/health/compliance/backup/retention |
| **Backup & restore** | Daily backup (material + DB dump via `pg_dump`/`mysqldump`), weekly verification, `certmgr restore` |
| **Data retention** | Configurable purge of execution/audit/notification history — bounded DB growth |
| **Observability** | Prometheus metrics, Grafana dashboard, `/health/live`, `/health/ready`, structured JSON logs |
| **REST API** | Full OpenAPI + Swagger UI (`/docs`), rate limiting, CSRF protection |
| **CLI** | `certmgr issue|renew|revoke|deploy|import|verify|inventory|discover|status|backup|restore|verify-backups|retention` |

---

## Architecture

```
                    ┌──────────────────────────┐
                    │  React SPA (TypeScript)  │   dark/light, MUI + Tailwind
                    └────────────┬─────────────┘
                                 │ HTTPS
                    ┌────────────▼─────────────┐
                    │  Nginx (TLS termination) │
                    └────────────┬─────────────┘
                                 │ /api/v1
                    ┌────────────▼─────────────┐        ┌──────────────────────────┐
                    │  FastAPI (stateless)     │───────▶│  PostgreSQL / MariaDB    │
                    │  JWT / RBAC / audit      │        │  (metadata only)         │
                    └──────┬───────────────┬───┘        └──────────────────────────┘
                           │ enqueue       │ read/write
                    ┌──────▼──────┐  ┌─────▼───────────────┐
                    │ Redis       │  │ Encrypted file store│  private keys (Fernet)
                    └──────┬──────┘  └─────────────────────┘
                           │
        ┌──────────────────┼───────────────────┐
   ┌────▼─────┐      ┌─────▼──────┐      ┌─────▼──────┐
   │ worker   │      │ beat       │      │ APScheduler│ (optional in-process)
   │ (Celery) │      │ (Celery)   │      └────────────┘
   └────┬─────┘      └────────────┘
        │ executes via subprocess (shell=False, argv lists)
   ┌────▼─────────────────────────────────────────────┐
   │ certbot │ OpenSSL CA │ SSH/SFTP to managed servers │
   └───────────────────────────────────────────────────┘
```

**Layers (Clean Architecture):**
`api/` (HTTP) → `services/` (business logic, providers, engines) → models
(SQLAlchemy) — schemas (`schemas/`) sit at the boundary; `tasks/` (Celery) and
`cli/` are secondary entry-points into the same services. No business logic in
routes.

```
backend/
├── app/
│   ├── api/            # FastAPI routers + deps (auth, RBAC, audit, CSRF)
│   ├── core/           # config, logging, database, security, middleware, scheduler
│   ├── models/         # SQLAlchemy 2.0 models (30 tables)
│   ├── schemas/        # Pydantic v2 contracts
│   ├── services/       # certificate lifecycle, certbot, deployment, discovery,
│   │   │               # health, compliance, notifications, webhooks, ai,
│   │   │               # backups/restore/verify, retention…
│   │   └── providers/  # plugin registry: letsencrypt, openssl-ca (+ future CAs)
│   └── tasks/          # Celery workers + beat schedule
├── alembic/            # migrations (incl. MySQL/MariaDB MEDIUMTEXT)
├── cli/                # certmgr CLI (typer)
├── scripts/            # seed-demo (evaluation only, opt-in)
├── tests/              # 130+ unit + integration + API tests
├── Dockerfile*         # api / worker / beat images
└── requirements.txt
frontend/               # React + TypeScript SPA
infra/                  # nginx, prometheus, grafana
deploy/                 # systemd units + server-setup-ol8.sh (bare metal)
deploy/systemd/         # api/worker/beat + backup/verify/retention timers
docs/                   # full documentation set
.github/workflows/      # CI (Postgres + MariaDB + Py3.11/3.13) + deploy
```

See [docs/architecture.md](docs/architecture.md) for the detailed architecture and
[docs/database.md](docs/database.md) for the ER model.

---

## Quick start

### Option A — Docker Compose

```bash
cp backend/.env.example .env
# edit .env — MUST set CERTMGR_SECRET_KEY and CERTMGR_SECRETS_MASTER_KEY
docker compose up -d --build
```

### Option B — Bare metal (Oracle Linux 8 / RHEL 8) — recommended for this stack

```bash
# Upload certmgr-deploy.tar.gz, then as root:
tar -xzf certmgr-deploy.tar.gz && cd certmgr
sudo bash deploy/server-setup-ol8.sh                                    # PostgreSQL 16
sudo DB_ENGINE=mariadb bash deploy/server-setup-ol8.sh                  # installs MariaDB
sudo DB_ENGINE=external-mariadb bash deploy/server-setup-ol8.sh         # reuse an EXISTING MariaDB
sudo DB_ENGINE=external-mariadb MYSQL_ADMIN_PASSWORD='<admin-pw>' \
     CERTMGR_DB_PASSWORD='<app-pw>' bash deploy/server-setup-ol8.sh     # fully automated
sudo CERTMGR_DATABASE_URL='mysql+pymysql://certmgr:pw@host:3306/certmgr' \
     bash deploy/server-setup-ol8.sh                                    # DB already prepared
```

Environment overrides: `APP_USER=secauto` (run services as that user),
`CERTMGR_DOMAIN=certmgr.hyd.int.untd.com` (hostname for nginx/cert/CORS),
`CERTMGR_EMAIL=...`, `PYTHON_BIN=/usr/bin/python3.11`.

The script: installs/verifies prerequisites (epel, nginx, certbot, rsync),
sets up the DB (installs PG16/MariaDB **or** connects to an existing MariaDB
and creates the `certmgr` DB+user idempotently), ensures Redis + Python
3.11–3.13 (uses an existing interpreter, only builds 3.13 from source if none
exists), creates the service user + storage dirs + venv + deps, writes
`/etc/certmgr/certmgr.env` with generated secrets, runs Alembic migrations,
configures nginx (self-signed TLS) for your domain, installs systemd units
(`api`/`worker`/`beat`) + daily backup / weekly backup-verify / daily retention
timers, applies SELinux/firewall policy, and prints the bootstrap admin
password. It is idempotent and preserves existing secrets/DB.

### Local development (no Docker)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # Python 3.11 – 3.13
pip install -r requirements-dev.txt
cp .env.example .env           # point DATABASE_URL at sqlite, mysql or postgres
alembic upgrade head
uvicorn app.main:app --reload --port 8000
# separate terminal (if using Redis for tasks):
celery -A app.tasks.celery_app:celery_app worker --loglevel=INFO
```

> In development with `CERTMGR_CELERY_TASK_ALWAYS_EAGER=true`, operations run
> synchronously inside the API process — no Redis/worker required.

### First login

- Bootstrap admin: username `admin`, with a randomly generated one-time
  password logged once at startup — retrieve it from the API logs
  (`docker compose logs api` or `journalctl -u certmgr-api`, search for
  "Bootstrap admin").
- **The UI forces a password change on first login** — change it immediately.

### CLI

```bash
certmgr status                       # platform state (DB type, providers, storage)
certmgr issue -d example.com,www.example.com -m ops@corp.com -v dns-01 -k rsa4096
certmgr inventory --status expiring --json
certmgr renew -c 42 --force
certmgr revoke -c 42 --reason keycompromise
certmgr deploy -c 42 -s 3 --service nginx
certmgr import-cert --cert-path /tmp/cert.pem --key-path /tmp/key.pem
certmgr verify -c 42
certmgr discover --paths /etc/nginx,/custom/path
certmgr backup                          # full backup + retention cleanup
certmgr verify-backups                  # verify archives + DB dumps
certmgr restore --backup <archive> [--cert <id>] [--dry-run]
certmgr retention [--dry-run]           # purge old history
```

---

## Database support

| Engine | Status | URL | Notes |
|---|---|---|---|
| **PostgreSQL 12+** | **Primary (tested in CI)** | `postgresql+psycopg://user:pass@host:5432/db` | JSONB, `NULLS LAST`, `pg_dump` backups |
| **MariaDB 10.3+ / MySQL 8** | **Supported fallback** | `mysql+pymysql://user:pass@host:3306/db` | `pymysql`, dialect-safe SQL, `MEDIUMTEXT` log columns, `mysqldump` backups. 10.3 works; 10.5+ recommended (10.3 EOL) |
| **SQLite** | Dev/tests only | `sqlite:///./certmgr-dev.db` | single-writer — not for production |

Moving MariaDB → PostgreSQL later: see
[docs/migration-mariadb-to-postgres.md](docs/migration-mariadb-to-postgres.md)
(pgloader one-liner; keys live on disk so they're untouched).

---

## Security model

- **No `shell=True` anywhere** — every command is `subprocess.run(argv_list)` with
  per-argument metacharacter validation (lint + tests enforce).
- **Private keys encrypted at rest** (Fernet, master key from env/file/Vault) and
  **never** written to the database; DB credentials/secrets also encrypted.
- **JWT** (access + refresh, rotation, revocation), **API tokens** (hashed at rest),
  **TOTP MFA**, account lockout, password policy.
- **RBAC** with granular permission codes (`certificate:issue`,
  `certificate:download_key`, …).
- **CSRF** double-submit cookie (public `GET /auth/csrf` establishes the token;
  login and state-changing requests carry `X-CSRF-Token`; Bearer-authenticated
  requests are exempt by design).
- **Rate limiting** (Redis-backed); secure cookies (SameSite, Secure, HttpOnly).
- **Remote command center** executes only an allowlist of maintenance commands.
- **Log redaction** — private keys, passwords and tokens stripped from every log.
- **Input validation** at the schema layer (domains, emails, paths, uploads, sizes).

See [docs/security.md](docs/security.md).

---

## Operations

- **Backups** run daily (systemd `certmgr-backup.timer` or Celery beat): every
  certificate's material (encrypted keys) + DB dump (`pg_dump`/`mysqldump`),
  with retention cleanup. **Verify** weekly (`certmgr-backup-verify.timer`):
  archive integrity, checksums, DB-dump readability. **Restore** per certificate
  via `certmgr restore` or the admin API.
- **Data retention** runs daily (`certmgr-retention.timer`): purges execution
  history / audit / notifications older than
  `CERTMGR_EXECUTION_RETENTION_DAYS` (365) / `CERTMGR_AUDIT_RETENTION_DAYS`
  (730) / `CERTMGR_NOTIFICATION_RETENTION_DAYS` (365) — bounds DB growth
  (~150–400 MB @ 1k certs, ~1–3 GB @ 5k certs, stable year over year).
- **Maintenance mode** (Settings) pauses renewals/deployments/notifications/
  imports/background jobs.
- Details: [docs/administration.md](docs/administration.md).

---

## Demo data (evaluation only)

```bash
certmgr seed-demo --reset        # 10 certs, 6 servers, hooks, deployments,
                                 # notifications, audit, users (example.com namespace)
```

Never runs automatically; the platform starts empty in production. Delete demo
rows before going live (or use `--no-reset` to preserve real data).

---

## Testing

```bash
cd backend && source .venv/bin/activate
pytest -q                 # 130+ tests: unit, integration, API, RBAC, security, CSRF, dialects
ruff check app/           # lint
bandit -r app/            # security scanner
```

CI (`.github/workflows/ci.yml`): lint → tests against real **PostgreSQL 16** and
**MariaDB 11** on **Python 3.11 + 3.13** → docker build + Trivy vulnerability
scan. E2E flows: [docs/testing.md](docs/testing.md).

---

## Documentation

| Document | Purpose |
|---|---|
| [document.md](document.md) | **Complete reference** — overview, features, installation, all configuration, CLI, API, operations runbook, troubleshooting, FAQ |
| [architecture.md](architecture.md) | System architecture, components, data model, flows, security, HA, extensibility |
| [changelog.md](changelog.md) | Release history and fixes |
| [docs/installation.md](docs/installation.md) | Installation (Docker & bare-metal/OL8), configuration reference, DB matrix |
| [docs/migration-mariadb-to-postgres.md](docs/migration-mariadb-to-postgres.md) | Move from MariaDB to PostgreSQL later |
| [docs/administration.md](docs/administration.md) | Admin guide: settings, roles, providers, maintenance, backups/restore, retention |
| [docs/user-guide.md](docs/user-guide.md) | Operator guide: wizard, inventory, import, deploy, discovery |
| [docs/api.md](docs/api.md) | REST API overview + auth flows (full spec at `/docs`) |
| [docs/database.md](docs/database.md) | ER diagram and table reference |
| [docs/security.md](docs/security.md) | Security architecture and hardening checklist |
| [docs/deployment.md](docs/deployment.md) | HA deployment, systemd, observability, upgrade paths |
| [docs/roadmap.md](docs/roadmap.md) | Delivery phases & future CA/SSO integrations |

---

## License

Proprietary — internal enterprise use.
