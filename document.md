# CertMgr — Complete Reference Document

> **Version:** 1.0.0 · **Last updated:** 2026-08-12
> **Audience:** administrators, operators, developers and security teams who
> deploy, run or extend the CertMgr platform.

This is the **single complete reference** for the CertMgr enterprise SSL
certificate lifecycle management platform. It covers what the platform is, how
to install and configure it, every configuration option, the CLI, the REST API,
day-to-day operations, security, troubleshooting and frequently asked questions.
Architecture and design details live in [architecture.md](architecture.md);
release history in [changelog.md](changelog.md).

---

## Table of contents

1. [Overview](#1-overview)
2. [Feature inventory](#2-feature-inventory)
3. [System requirements](#3-system-requirements)
4. [Installation](#4-installation)
5. [Configuration reference](#5-configuration-reference)
6. [Database setup](#6-database-setup)
7. [First run & bootstrap](#7-first-run--bootstrap)
8. [CLI reference](#8-cli-reference)
9. [REST API](#9-rest-api)
10. [Operations runbook](#10-operations-runbook)
11. [Security](#11-security)
12. [Troubleshooting](#12-troubleshooting)
13. [Frequently asked questions](#13-frequently-asked-questions)

---

## 1. Overview

CertMgr is a self-hosted, production-grade platform that automates the full
lifecycle of SSL/TLS certificates — issuing, renewing, revoking, importing,
deploying, monitoring and auditing — at enterprise scale (thousands of
certificates across hundreds of Linux servers).

It is **not** a Certbot frontend. It is a complete certificate lifecycle
management platform:

- **Provider abstraction** — Let's Encrypt (via Certbot/ACME v2) ships today;
  DigiCert, Sectigo, GlobalSign, Entrust, Microsoft ADCS and internal PKI plug
  in without core changes (see [architecture.md](architecture.md)). GoDaddy
  has a separate, narrower integration already built — pulling an
  already-issued certificate by domain or certificate ID (Import page) —
  since GoDaddy's own API doesn't support ACME-style issue/renew automation.
- **Metadata only in the database** — private keys are **never** stored in the
  database; they are Fernet-encrypted at rest on disk.
- **Runs on PostgreSQL (primary), MariaDB/MySQL (fully supported fallback) or
  SQLite (dev/tests only).**

## 2. Feature inventory

| Area | Features |
|---|---|
| **Issuance** | Let's Encrypt via Certbot + internal PKI (OpenSSL CA); HTTP-01, DNS-01, manual HTTP/DNS, standalone, webroot, custom auth/cleanup hooks; staging & dry-run; single / multi-SAN / wildcard |
| **Keys** | RSA 2048 / RSA 4096 / ECDSA P-256 / ECDSA P-384 |
| **Lifecycle** | Renew (manual + automatic), revoke (with reason + cleanup), clone, import (PEM/CRT/CER/PFX with auto metadata extraction), bulk renew/revoke/deploy, favorites, tags, ownership |
| **Deployment** | SSH / SCP / SFTP / rsync to remote servers; templates for Nginx, Apache, HAProxy, OpenVPN, Tomcat, Jetty, NodeJS, IIS, PKCS12, custom; pre/post-deploy hooks; **automatic rollback** on failure; TLS verification after deploy |
| **Servers** | Inventory (hostname, IP, env, OS, SSH auth, cert dir, web server, owner, tags), connectivity testing, **restricted remote command center** (allowlist), service control (status/restart/reload/stop/start) |
| **Discovery** | Scheduled scans of `/etc/letsencrypt`, `/etc/pki`, `/etc/nginx`, custom paths; auto-parse and import certificates |
| **Monitoring** | Health scores (expiry, signature, key size, TLS handshake), compliance engine (key length, curves, SHA, lifetime, duplicates, unused) |
| **Notifications** | SMTP, Slack, Microsoft Teams, generic signed webhooks; expiry thresholds 60/30/15/7/3/1 days + lifecycle events (issued, renewed, failed, deployed, revoked, imported) |
| **Webhooks (outbound)** | HMAC-SHA256 signed; events for issue/renew/expire/revoke/import/deploy; delivery history |
| **RBAC** | 4 roles (administrator, certificate_manager, operator, read_only) × granular permission codes |
| **Auth** | JWT access+refresh (rotation/revocation), API tokens (hashed at rest), TOTP MFA, account lockout, password policy, **CSRF protection** |
| **Audit** | Every action logged with user, IP, browser, device, duration, result |
| **Jobs** | Celery workers + beat (renewal, discovery, health, compliance, backup, retention, notifications, summary); APScheduler in-process mode |
| **Backup & restore** | Daily backup (certificate material incl. encrypted keys + DB dump via `pg_dump`/`mysqldump`), weekly verification, per-certificate restore, retention cleanup |
| **Data retention** | Configurable purge of execution/audit/notification history — bounds DB growth |
| **Reports** | CSV / XLSX / PDF / JSON: inventory, expiry, renewal history, deployment history, failures, audit |
| **Search** | Enterprise search across certificates, servers, users by domain/issuer/SAN/fingerprint/serial/owner/env/tags |
| **AI assistant** | Explain Certbot failures, troubleshoot, recurring-failure detection, renewal-failure prediction |
| **Observability** | Prometheus metrics, Grafana dashboard, `/health/live`, `/health/ready`, structured JSON logs |
| **CLI** | `issue`, `renew`, `revoke`, `deploy`, `import-cert`, `verify`, `inventory`, `discover`, `server-test`, `status`, `backup`, `restore`, `verify-backups`, `retention` |
| **Maintenance mode** | Pause renewals / deployments / notifications / imports / background jobs |

## 3. System requirements

| Component | Requirement |
|---|---|
| **OS** | Oracle Linux 8 / RHEL 8 / Rocky 8 (bare metal), any Linux (Docker), Ubuntu 22.04+ tested |
| **Python** | 3.11 – 3.13 (tested on 3.11 and 3.13 in CI; OL8 AppStream `python311` works out of the box) |
| **Database** | PostgreSQL 12+ (primary) **or** MariaDB 10.3+ / MySQL 8 (fallback; 10.5+ recommended — 10.3 is EOL) **or** SQLite (dev/tests only) |
| **Redis** | 6.2+ (7.x recommended) — broker for Celery + rate limiting |
| **Certbot** | 1.17+ (1.22 tested) — installed on the host that runs CertMgr |
| **Network** | Outbound 443 to `acme-v02.api.letsencrypt.org`; DNS/HTTP reachability for managed domains; SSH 22 to managed servers |
| **Disk** | Small: DB ≈ 150–400 MB @ 1k certs (with retention defaults); encrypted keys ≈ 10–100 MB @ 5k certs; logs small with logrotate |

## 4. Installation

### 4.1 Docker Compose (recommended where Docker is allowed)

```bash
cp backend/.env.example .env
# MUST set: CERTMGR_SECRET_KEY, CERTMGR_SECRETS_MASTER_KEY (>=32 chars)
docker compose up -d --build
```

Stack: `postgres:16`, `redis:7`, `api` (uvicorn ×4), `worker` (Celery),
`beat` (Celery beat), `nginx` (TLS termination + UI). Migrations run
automatically on API start.

### 4.2 Bare metal — Oracle Linux 8 / RHEL 8 (one command)

```bash
tar -xzf certmgr-deploy.tar.gz && cd certmgr
sudo bash deploy/server-setup-ol8.sh                                          # PostgreSQL 16
sudo DB_ENGINE=mariadb bash deploy/server-setup-ol8.sh                        # installs MariaDB
sudo DB_ENGINE=external-mariadb bash deploy/server-setup-ol8.sh               # reuse existing MariaDB
sudo CERTMGR_DATABASE_URL='mysql+pymysql://certmgr:pw@host:3306/certmgr' \
     bash deploy/server-setup-ol8.sh                                          # DB already prepared
```

Useful overrides: `APP_USER=secauto` (run services as a specific OS user),
`CERTMGR_DOMAIN=certmgr.example.com` (nginx/cert/CORS hostname),
`CERTMGR_EMAIL=ssl-admin@example.com`, `PYTHON_BIN=/usr/bin/python3.11`,
`MYSQL_HOST/PORT/ADMIN_USER/ADMIN_PASSWORD` (non-interactive external MariaDB),
`CERTMGR_DB_PASSWORD`.

The script (idempotent): installs prerequisites → sets up DB (installs or
connects to existing) → ensures Redis + Python 3.11–3.13 → creates service
user + storage dirs + venv + deps → writes `/etc/certmgr/certmgr.env` with
generated secrets → runs Alembic migrations → configures nginx (self-signed
TLS) → installs systemd units + daily backup / weekly verify / daily retention
timers → applies SELinux/firewall → prints the bootstrap admin password.

### 4.3 Manual (any distro)

```bash
sudo useradd --system --create-home certmgr
sudo mkdir -p /etc/certmgr /var/lib/certmgr/{certificates,backups,tmp} /var/log/certmgr /etc/letsencrypt
cd /opt/certmgr/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .               # installs the `certmgr` CLI entry point (pyproject.toml)
cp .env.example /etc/certmgr/certmgr.env     # fill values
sudo cp ../deploy/systemd/certmgr-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certmgr-api certmgr-worker certmgr-beat
# + nginx using infra/nginx/ configs
```

> **Corporate-server notes:** if `/home` is NFS-mounted, create the service
> user with `-M -d /var/lib/certmgr` (no home). If `sudo` blocks running
> shells directly, use `sudo /bin/sh -c '...'` (allowed by typical sudoers).

### 4.4 Update / upgrade

```bash
# Docker: git pull && docker compose up -d --build
# Bare metal: extract the new bundle, rebuild venv, restart:
sudo /bin/sh -c 'cd /opt/certmgr && tar -xzf ~/certmgr-deploy.tar.gz'
sudo /bin/sh -c 'cd /opt/certmgr/backend && rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt && .venv/bin/pip install -q -e .'
sudo /bin/sh -c 'chown -R secauto:secauto /opt/certmgr && systemctl restart certmgr-api certmgr-worker certmgr-beat'
```

## 5. Configuration reference

All settings come from environment variables prefixed `CERTMGR_` (read from
`/etc/certmgr/certmgr.env` by systemd, or `.env`/environment in Docker).
Values may be overridden in the admin UI (Settings) where applicable.

### 5.1 Core application

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_ENVIRONMENT` | `development` | `development` / `staging` / `production` / `testing` |
| `CERTMGR_DEBUG` | `false` | FastAPI debug mode |
| `CERTMGR_API_V1_PREFIX` | `/api/v1` | API prefix |
| `CERTMGR_ALLOWED_HOSTS` | `["*"]` | Host allowlist |
| `CERTMGR_CORS_ORIGINS` | localhost list | JSON array, bracket/comma form, or plain comma list (all accepted) |
| `CERTMGR_TRUST_PROXY_HEADERS` | `true` | Honor X-Forwarded-* |

### 5.2 Security

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_SECRET_KEY` | random | JWT signing key — **set a strong value in production** |
| `CERTMGR_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `CERTMGR_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `CERTMGR_REFRESH_TOKEN_EXPIRE_DAYS` | `14` | Refresh token lifetime |
| `CERTMGR_COOKIE_SECURE` | `true` | Secure cookies (HTTPS only) |
| `CERTMGR_COOKIE_SAMESITE` | `lax` | SameSite policy |
| `CERTMGR_CSRF_ENABLED` | `true` | CSRF protection (auth endpoints exempt by design) |
| `CERTMGR_PASSWORD_MIN_LENGTH` | `12` | Password policy |
| `CERTMGR_MAX_LOGIN_ATTEMPTS` | `5` | Lockout threshold |
| `CERTMGR_LOCKOUT_MINUTES` | `15` | Lockout duration |
| `CERTMGR_MFA_REQUIRED` | `false` | Force TOTP MFA |
| `CERTMGR_SECRETS_MASTER_KEY` | — | **Fernet master key (>=32 chars) encrypting keys & secrets at rest — REQUIRED in production** |
| `CERTMGR_SECRETS_ENCRYPTION_FILE` | — | Path to a key file (preferred over env) |

### 5.3 Database / Redis / Celery

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_DATABASE_URL` | sqlite dev | `postgresql+psycopg://…`, `mysql+pymysql://…`, `mariadb+pymysql://…`, `sqlite:///…` |
| `CERTMGR_REDIS_URL` | `redis://localhost:6379/0` | Redis for Celery + rate limits |
| `CERTMGR_DB_POOL_SIZE` / `CERTMGR_DB_MAX_OVERFLOW` | 10 / 20 | Connection pool |
| `CERTMGR_CELERY_BROKER_URL` / `CERTMGR_CELERY_RESULT_BACKEND` | redis | Celery broker/backend |
| `CERTMGR_CELERY_TASK_ALWAYS_EAGER` | `false` | Run tasks synchronously (dev/tests) |

### 5.4 Storage

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_STORAGE_ROOT` | `/var/lib/certmgr/certificates` | Encrypted keys + cert material |
| `CERTMGR_BACKUP_ROOT` | `/var/lib/certmgr/backups` | Backups |
| `CERTMGR_LOG_ROOT` | `/var/log/certmgr` | Structured logs |
| `CERTMGR_TEMP_WORKDIR` | `/var/lib/certmgr/tmp` | Temp working dir |
| `CERTMGR_STORAGE_BACKEND` | `encrypted-filesystem` | `filesystem` / `encrypted-filesystem` / `nfs` |

### 5.5 Certbot / Let's Encrypt

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_CERTBOT_BINARY` | `certbot` | Certbot executable |
| `CERTMGR_CERTBOT_WORKDIR` | `/etc/letsencrypt` | Certbot live dir |
| `CERTMGR_CERTBOT_TIMEOUT_SECONDS` | `900` | Command timeout |
| `CERTMGR_DEFAULT_LETSENCRYPT_EMAIL` | `ssl-admin@example.com` | ACME contact |
| `CERTMGR_DEFAULT_STAGING` | `false` | Default staging |

### 5.6 Scheduler / renewal

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_RENEWAL_THRESHOLD_DAYS` | `30` | Auto-renew within N days |
| `CERTMGR_RENEWAL_RETRY_MAX` | `3` | Renewal retries |
| `CERTMGR_RENEWAL_CRON` | `0 3 * * *` | Renewal sweep time |
| `CERTMGR_DISCOVERY_CRON` | `30 2 * * *` | Discovery time |
| `CERTMGR_HEALTH_CRON` | `0 */4 * * *` | Health scan |

Expiry notification thresholds are configured at runtime via Settings →
`notification.expiry_warning_days` (comma-separated days-before-expiry,
e.g. `14,7,1`), not an environment variable — editable without a
restart/redeploy.

### 5.7 Data retention (bounded DB growth)

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_EXECUTION_RETENTION_DAYS` | `365` | Purge `job_executions` older than N days (0 = keep forever) |
| `CERTMGR_AUDIT_RETENTION_DAYS` | `730` | Purge `audit_logs` |
| `CERTMGR_NOTIFICATION_RETENTION_DAYS` | `365` | Purge `notifications` |

### 5.8 Notifications / SMTP

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_SMTP_HOST/PORT/USERNAME/PASSWORD/USE_TLS/FROM/FROM_NAME` | localhost:587 | SMTP defaults (channels configured in UI) |

### 5.9 Observability

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_PROMETHEUS_ENABLED` | `true` | Expose `/metrics` |
| `CERTMGR_METRICS_AUTH_TOKEN` | — | Protect `/metrics` |
| `CERTMGR_JSON_LOGGING` | `true` | JSON log lines |
| `CERTMGR_LOG_LEVEL` | `INFO` | Log level |

### 5.10 Rate limiting

| Variable | Default |
|---|---|
| `CERTMGR_RATE_LIMIT_ENABLED` | `true` |
| `CERTMGR_RATE_LIMIT_LOGIN` | `10/minute` |
| `CERTMGR_RATE_LIMIT_API` | `300/minute` |

### 5.11 Deployment engine

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_SSH_CONNECT_TIMEOUT` | `10` | SSH connect timeout (s) |
| `CERTMGR_SSH_COMMAND_TIMEOUT` | `120` | SSH command timeout (s) |
| `CERTMGR_DEPLOYMENT_VERIFY_ENABLED` | `true` | Verify TLS after deploy |
| `CERTMGR_DEPLOYMENT_ROLLBACK_ENABLED` | `true` | Auto-rollback on failure |
| `CERTMGR_MAX_UPLOAD_BYTES` | `10MiB` | Upload size limit |

### 5.12 AI assistant (optional)

| Variable | Default |
|---|---|
| `CERTMGR_AI_ENABLED` | `false` |
| `CERTMGR_AI_PROVIDER` | `local` (heuristics; `openai`/`anthropic` optional) |
| `CERTMGR_AI_API_KEY` | — |
| `CERTMGR_AI_BASE_URL` / `CERTMGR_AI_MODEL` | — / `gpt-4o-mini` |

### 5.13 Optional integrations (off by default)

| Variable | Purpose |
|---|---|
| `CERTMGR_VAULT_ENABLED` / `_URL` / `_TOKEN` / `_KV_PATH` | HashiCorp Vault secret backend |
| `CERTMGR_OIDC_ENABLED` / `_DISCOVERY_URL` / `_CLIENT_ID` / `_CLIENT_SECRET` | OpenID Connect (roadmap) |
| `CERTMGR_LDAP_ENABLED` / `_URL` / `_BIND_DN` / `_BIND_PASSWORD` / `_SEARCH_BASE` / `_USER_FILTER` | LDAP/AD (roadmap) |

### 5.14 Backups

| Variable | Default | Purpose |
|---|---|---|
| `CERTMGR_BACKUP_ENABLED` | `true` | Enable backups |
| `CERTMGR_BACKUP_KEEP_DAYS` | `30` | Retention |
| `CERTMGR_BACKUP_CRON` | `0 1 * * *` | Daily backup time |
| `CERTMGR_PG_DUMP_BINARY` | `pg_dump` | PostgreSQL dump binary |
| `CERTMGR_MYSQLDUMP_BINARY` | `mysqldump` | MariaDB/MySQL dump binary |

## 6. Database setup

### 6.1 PostgreSQL (primary)

```sql
CREATE USER certmgr WITH PASSWORD '<pw>';
CREATE DATABASE certmgr OWNER certmgr;
```
`CERTMGR_DATABASE_URL=postgresql+psycopg://certmgr:<pw>@127.0.0.1:5432/certmgr`

### 6.2 MariaDB/MySQL (fallback — reuse existing instance)

```sql
CREATE DATABASE certmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'certmgr'@'127.0.0.1' IDENTIFIED BY '<pw>';
GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'127.0.0.1';
FLUSH PRIVILEGES;
```
`CERTMGR_DATABASE_URL=mysql+pymysql://certmgr:<pw>@127.0.0.1:3306/certmgr`

> Use only letters/digits/`_`/`-` in passwords, or URL-encode special chars
> (`@`→`%40`, `:`→`%3A`, `/`→`%2F`, `#`→`%23`).

### 6.3 Migrations

```bash
cd /opt/certmgr/backend && set -a && source /etc/certmgr/certmgr.env && set +a
.venv/bin/alembic upgrade head
```
Migrations are dialect-safe: the MySQL/MariaDB `MEDIUMTEXT` migration is a
no-op on PostgreSQL/SQLite. The API systemd unit runs migrations automatically
on every start (`ExecStartPre`).

### 6.4 Migrating MariaDB → PostgreSQL later

See `docs/migration-mariadb-to-postgres.md` — pgloader one-liner; keys live on
disk so they are untouched.

## 7. First run & bootstrap

1. Bootstrap admin is created on first boot: username **`admin`**, with a
   randomly generated one-time password logged once at startup — retrieve it
   from the API logs (`docker compose logs api` or
   `journalctl -u certmgr-api`, search for "Bootstrap admin").
2. **The UI forces a password change on first login** — set a strong password.
3. Optional: seed demo data for evaluation: `certmgr seed-demo` (never runs
   automatically; delete rows before going live).
4. Configure in **Settings**: notification channels (SMTP/Slack/Teams),
   Let's Encrypt email, maintenance mode, retention.
5. Add **Servers**, configure **Hooks** (DNS-01 scripts etc.), then issue your
   first certificate via the wizard.

## 8. CLI reference

Run with `certmgr <command>` (venv: `.venv/bin/python -m cli.certmgr <command>`
or the installed `certmgr` entry point). All commands output JSON.

| Command | Description | Examples |
|---|---|---|
| `issue` | Issue a certificate | `certmgr issue -d example.com,www.example.com -m ops@corp.com -v dns-01 -k rsa4096` |
| `renew` | Renew a certificate | `certmgr renew -c 42 --force` |
| `revoke` | Revoke a certificate | `certmgr revoke -c 42 --reason keycompromise` |
| `deploy` | Deploy to a server | `certmgr deploy -c 42 -s 3 --service nginx --method sftp` |
| `import-cert` | Import from files | `certmgr import-cert --cert-path /tmp/c.pem --key-path /tmp/k.pem` |
| `verify` | Verify SAN coverage + validity | `certmgr verify -c 42` |
| `inventory` | List certificates | `certmgr inventory --status expiring --json` |
| `discover` | Run discovery | `certmgr discover --paths /etc/nginx,/custom` |
| `server-test` | Test SSH connectivity | `certmgr server-test -s 3` |
| `status` | Platform state | `certmgr status` |
| `backup` | Full backup + retention cleanup | `certmgr backup [--keep-days N]` |
| `restore` | Restore from archive | `certmgr restore --backup <archive> [--cert <id>] [--dry-run]` |
| `verify-backups` | Verify archives + DB dumps | `certmgr verify-backups [--sample]` |
| `retention` | Purge old history | `certmgr retention [--dry-run]` |
| `seed-demo` | Demo data (evaluation only) | `certmgr seed-demo [--no-reset]` |

## 9. REST API

Interactive docs at `/docs` (Swagger) and `/redoc`; OpenAPI at
`/api/v1/openapi.json`. All endpoints under `/api/v1`.

**Authentication:** `POST /auth/login` → `{access_token, refresh_token}`.
Send `Authorization: Bearer <token>` (or `X-CertMgr-Token`; API tokens via
`X-API-Key`). Refresh via `POST /auth/refresh`. **CSRF:** auth endpoints are
exempt; other state-changing requests send `X-CSRF-Token` (token from
`GET /auth/csrf`).

**Error envelope:** `{"error":{"code":"...","message":"...","details":{...}}}`.
Common codes: `UNAUTHORIZED`, `FORBIDDEN`, `VALIDATION_ERROR`, `NOT_FOUND`,
`CONFLICT`, `RATE_LIMITED`, `PROVIDER_ERROR`, `DEPLOYMENT_ERROR`,
`MAINTENANCE_MODE`.

**Main resources** (full list in `docs/api.md`):

| Resource | Paths |
|---|---|
| Auth | `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me`, `/auth/change-password`, `/auth/mfa/*`, `/auth/tokens` |
| Certificates | `/certificates` (list/CRUD), `/certificates/issue`, `/{id}/renew|revoke|clone`, `/import/upload|paths`, `/bulk`, `/{id}/download/{fmt}`, `/{id}/executions`, `/wizard/validate/*` |
| Servers | `/servers`, `/{id}/test`, `/{id}/command`, `/{id}/service/{svc}/{action}` |
| Deployments | `/deployments`, `/{id}/rollback`, `/deployments/templates` |
| Hooks | `/hooks` |
| Discovery | `/discovery/run`, `/discovery/runs` |
| Health | `/health/certificate/{id}/scan`, `/health/certificate/{id}/checks` |
| Compliance | `/compliance/dashboard`, `/compliance/report` |
| Reports | `/reports/{type}.{csv\|xlsx\|pdf\|json}` |
| Notifications | `/notifications/settings`, `/notifications` |
| Webhooks | `/webhooks/endpoints`, `/webhooks/deliveries` |
| Jobs | `/jobs`, `/jobs/{id}/retry` |
| Audit | `/audit` |
| Dashboard | `/dashboard/*` |
| Search | `/search?q=` |
| AI | `/ai/*` |
| Backups | `/backups`, `/backups/verify`, `/backups/{id}/restore`, `/backups/run` |
| Users/Roles | `/users`, `/users/roles` |
| Settings | `/settings`, `/settings/{key}`, `/settings/retention`, `/settings/maintenance` |
| Providers | `/providers` |
| Scheduled jobs | `/scheduled-jobs` |

**Pagination/filters:** lists accept `page`, `page_size` (≤500), `sort_by`,
`sort_dir`, `search`, and field filters; responses include
`{items,total,page,page_size,pages,summary}`.

## 10. Operations runbook

### 10.1 Daily health checks

```bash
curl -k https://127.0.0.1/health/ready            # {"status":"ready"}
systemctl is-active certmgr-api certmgr-worker certmgr-beat
systemctl list-timers certmgr-backup.timer certmgr-backup-verify.timer certmgr-retention.timer
```

### 10.2 Backups

- **Daily** (01:00, `certmgr-backup.timer` / Celery beat): every certificate's
  material (encrypted keys) → `CERTMGR_BACKUP_ROOT/certificates/<id>/`, DB
  dump (`pg_dump`/`mysqldump`) → `.../database/`, retention cleanup.
- Certificates with no material on disk are skipped (never empty archives).
- Logs: `/var/log/certmgr/backup.log`.

### 10.3 Backup verification (weekly)

- **Sunday 02:30** (`certmgr-backup-verify.timer` / beat): archive integrity,
  required members, SHA-256 vs DB record, DB-dump readability.
- Logs: `/var/log/certmgr/backup-verify.log`. Non-zero exit on failure.

### 10.4 Restore

```bash
certmgr restore --backup /var/lib/certmgr/backups/certificates/42/cert-42-<ts>.tar.gz --cert 42
certmgr restore --backup <archive> --dry-run          # preview
# API: POST /api/v1/backups/{id}/restore (admin)
```
Restores into the matching certificate (fingerprint must match) or imports a
new row. Keys remain encrypted at rest.

### 10.5 Data retention

- **Daily 04:00** (`certmgr-retention.timer` / beat): purges execution/audit/
  notification history older than the configured days.
- `certmgr retention --dry-run` previews; `GET /api/v1/settings/retention`
  shows config + row counts; `POST /api/v1/settings/retention/run` (admin)
  runs it.

### 10.6 Maintenance mode

Settings → Maintenance (or `PUT /api/v1/settings/maintenance`): pause
renewals/deployments/notifications/imports/background jobs, optionally until a
scheduled end time.

### 10.7 Scheduled jobs

Fixed beat schedule + user-defined jobs via `/scheduled-jobs` (used when the
API runs with `CERTMGR_RUN_SCHEDULER=1` in-process mode).

### 10.8 Moving to PostgreSQL later

`docs/migration-mariadb-to-postgres.md` — pgloader one-liner; keys on disk are
untouched.

## 11. Security

See `docs/security.md` for the full threat model. Highlights:

- **No `shell=True`** anywhere — every command is `subprocess.run(argv_list)`
  with per-argument metacharacter validation.
- **Private keys encrypted at rest** (Fernet) — never in the database.
- **JWT** access+refresh with rotation & revocation; **API tokens** hashed at
  rest; **TOTP MFA**; account lockout; password policy.
- **RBAC** granular permission codes.
- **CSRF** double-submit cookie; auth endpoints exempt by design; Bearer-auth
  requests exempt (header auth is not CSRF-able).
- **Rate limiting** (Redis), **secure cookies** (Secure/SameSite/HttpOnly),
  **remote command allowlist**, **log redaction**, **input validation**.
- **Secrets management**: env → optional Vault (`SecretManager` abstraction).

**Master key management:** `CERTMGR_SECRETS_MASTER_KEY` (env) or
`CERTMGR_SECRETS_ENCRYPTION_FILE` (file). Production refuses to boot without
one. Rotation is an offline procedure — plan for it.

## 12. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `CSRF token missing or invalid` at login | Old JS bundle → hard refresh (Ctrl+Shift+R). Auth endpoints are CSRF-exempt in current versions; the UI self-heals on stale cookies. |
| **502 Bad Gateway** through nginx | API down. Check `systemctl status certmgr-api`, `journalctl -u certmgr-api -n 50`, and `curl http://127.0.0.1:8000/health/ready`. |
| `Address already in use` on :8000 | Stale uvicorn from a previous install. `pkill -f "uvicorn app.main"` then `systemctl restart certmgr-api`. |
| systemd `status=203/EXEC` on ExecStartPre | Broken venv (alembic launcher can't exec). Rebuild: `rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e .`. |
| `certmgr: command not found` in `.venv/bin/` | `pip install -r requirements.txt` only installs dependencies — it doesn't install the local package, so the `certmgr` console-script entry point (`pyproject.toml`'s `[project.scripts]`) is never created. Run `.venv/bin/pip install -e .`, or invoke `.venv/bin/python -m cli.certmgr ...` directly without installing anything. |
| `error parsing value for field "cors_origins"` when sourcing env | bash `source` strips quotes. Current versions parse both forms; re-extract the bundle for the fix. |
| `useradd: cannot create directory /home/certmgr` | `/home` on NFS. Create user with `-M -d /var/lib/certmgr`. |
| `Command not found` after `VAR=x cmd` | Some shells reject inline env. Use `sudo /bin/sh -c 'VAR=x cmd'` or `export VAR=x`. |
| `line 21: 1: command not found` sourcing env | Old installer wrote `CERTMGR_BACKUP_CRON` unquoted. Re-extract the bundle (fixed). |
| Certbot `DNS problem: NXDOMAIN` | DNS record missing; use the AI assistant on the failed job. |
| `too many certificates (5)` from Let's Encrypt | Rate limit — test on staging, consolidate SANs. |
| Deployment `Connection refused` | Server unreachable / wrong SSH credentials in Server inventory. |
| "Loading platform…" forever | Old deadlock in token-refresh; hard refresh to load the fixed bundle. |
| DB growth concerns | Check `/settings/retention`; retention defaults bound size (~150–400 MB @ 1k certs). |
| pip cache warnings on NFS home | Harmless; add `-H` to sudo or ignore. |

## 13. Frequently asked questions

**Q: Which database should I use?**
PostgreSQL (primary). MariaDB/MySQL is a fully supported fallback — reuse an
existing instance to save disk. SQLite is dev/tests only.

**Q: Are private keys stored in the database?**
No. Keys are Fernet-encrypted at rest on disk under `CERTMGR_STORAGE_ROOT`;
the database holds paths + metadata only.

**Q: How big will the database get?**
With retention defaults: ~150–400 MB @ 1k certificates, ~1–3 GB @ 5k
certificates, stable year over year (execution logs are the biggest driver).

**Q: Can I add DigiCert / Sectigo / GlobalSign / etc.?**
Yes — implement `CertificateProvider`, register the entry point
`certmgr.providers`, restart. No core changes (see architecture.md).

**Q: What about GoDaddy?**
Already integrated, but narrower than the above: the Import page can fetch
an already-issued certificate directly from a GoDaddy account by domain or
certificate ID (`godaddy.api_key`/`godaddy.api_secret` in Settings). It
doesn't issue or renew — GoDaddy's API doesn't support that the way ACME
does, so this isn't a full `CertificateProvider`. Domain search is
best-effort (GoDaddy's own filter is unreliable for accounts with a long
certificate history); certificate ID lookup always works.

**Q: How do I renew automatically?**
Enable auto-renew on the certificate; the daily renewal sweep renews within
`CERTMGR_RENEWAL_THRESHOLD_DAYS` of expiry, with retries.

**Q: What happens if a deployment fails?**
The engine backs up remote files first and rolls back automatically on any
failure (service reload, TLS verification), restoring the previous
certificate material.

**Q: Can I disable CSRF?**
Yes — `CERTMGR_CSRF_ENABLED=false` — but it's recommended to keep it on;
current versions are designed so login can't be blocked by it.

**Q: How do I access the UI?**
`https://<host>/` — the first admin login forces a password change. If the
hostname doesn't resolve, use the server IP or add a hosts entry.

---

*See also: [architecture.md](architecture.md) · [changelog.md](changelog.md) ·
`docs/` for deep-dives (installation, administration, user guide, API,
security, database, deployment, testing, migration).*
