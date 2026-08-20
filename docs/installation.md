# Installation Guide

## Prerequisites

- Linux (Ubuntu 22.04+/RHEL 9/Oracle Linux 8 tested), **Python 3.11 – 3.13**
  (OL8's AppStream `python311` works out of the box; the OL8 setup script
  auto-detects any 3.11+ and only builds 3.13 from source if none exists),
  Docker 24+ with Compose v2, or a bare-metal target with systemd.
- Ports: 80/443 (nginx), 8000 (API), 5432 (Postgres), 6379 (Redis).
- Outbound access to `acme-v02.api.letsencrypt.org:443` and DNS/HTTP reachability
  for domains you manage.

## Option A — Docker Compose (recommended)

```bash
git clone <repo> certmgr && cd certmgr
cp backend/.env.example .env

# 1) Set strong secrets (REQUIRED):
#    CERTMGR_SECRET_KEY      — JWT signing (>=32 chars)
#    CERTMGR_SECRETS_MASTER_KEY — master key encrypting private keys (>=32 chars)
#    POSTGRES_PASSWORD
# 2) Set CERTMGR_DEFAULT_LETSENCRYPT_EMAIL, SMTP, CORS origins.

docker compose up -d --build
docker compose ps          # postgres/redis healthy, api/worker/beat running
```

Migrations run automatically on API start (`alembic upgrade head`).

### First login

- User: `admin` — Password: randomly generated on first API start and logged
  once (`docker compose logs api` or `journalctl -u certmgr-api`, search for
  "Bootstrap admin"). It is never derived from `CERTMGR_SECRETS_MASTER_KEY`.
- The UI forces a password change on first login. **Change it immediately.**

### Rotating the master key

The master key encrypts every private key and stored secret. To rotate:

1. Take a maintenance window (Settings → Maintenance).
2. Export all certificates you must keep (download bundles) — or restore from backup.
3. Replace `CERTMGR_SECRETS_MASTER_KEY`, restart api/worker.
4. Re-import any certificates whose material you need preserved.
5. Verify a sample deployment, then end maintenance.

> There is no multi-key keyring in v1 — rotation is offline by design. This is
> documented in [security.md](security.md#master-key-management).

> **Not the same as migrating to a new server.** Rotation intentionally
> replaces the key and abandons anything not re-imported. Moving to new
> hardware should instead *carry the existing key over unchanged* — see
> [migration.md](migration.md).

## Option B — Bare metal (systemd)

### Oracle Linux 8 / RHEL 8 — one command (recommended)

```bash
# Upload certmgr-deploy.tar.gz, then as root:
tar -xzf certmgr-deploy.tar.gz && cd certmgr
sudo bash deploy/server-setup-ol8.sh          # PostgreSQL 16 (default)
sudo DB_ENGINE=mariadb bash deploy/server-setup-ol8.sh   # installs MariaDB
# Reuse an EXISTING MariaDB (no extra DBMS on disk — prompts for admin password):
sudo DB_ENGINE=external-mariadb bash deploy/server-setup-ol8.sh
# Fully automated external DB (no prompts — for CI / remote runs):
sudo DB_ENGINE=external-mariadb MYSQL_HOST=10.0.0.5 MYSQL_PORT=3306 \
     MYSQL_ADMIN_USER=root MYSQL_ADMIN_PASSWORD='<admin-pw>' \
     CERTMGR_DB_PASSWORD='<app-db-pw>' bash deploy/server-setup-ol8.sh
# Already prepared a database yourself? Just point at it (skips DB setup):
sudo CERTMGR_DATABASE_URL='mysql+pymysql://certmgr:pw@10.0.0.5:3306/certmgr' \
     bash deploy/server-setup-ol8.sh
```

The script installs Redis, ensures Python 3.11+ (uses an existing
`python3`/`python3.11` if present — e.g. OL8's AppStream `python311` — and only
builds 3.13 from source when no 3.11+ exists), nginx + self-signed TLS, sets up
the DB (installs PostgreSQL 16 /
MariaDB, or connects to an existing MariaDB and creates the `certmgr` DB+user),
writes `/etc/certmgr/certmgr.env` with generated secrets (or reuses
`CERTMGR_SECRETS_MASTER_KEY`/`CERTMGR_SECRET_KEY` if pre-exported — see
[migration.md](migration.md) if this is a server move, not a fresh install),
runs migrations, and installs the systemd units + backup/verify/retention
timers. See the header of the script for a step-by-step explanation.

**External-MariaDB mode** never installs a DBMS and uses `MYSQL_PWD` for
authentication (the admin password is not exposed on the command line). It
creates the `certmgr` database/user idempotently on the existing instance —
zero extra disk for disk-constrained servers.

### Manual (any EL/RHEL/Debian)

```bash
sudo useradd --system --create-home certmgr
sudo mkdir -p /etc/certmgr /opt/certmgr /var/lib/certmgr/{certificates,backups,tmp} /var/log/certmgr /etc/letsencrypt
sudo chown -R certmgr:certmgr /var/lib/certmgr /var/log/certmgr

cd /opt/certmgr && git clone <repo> .
cd backend
python3 -m venv .venv && source .venv/bin/activate   # any Python 3.11–3.13
pip install -r requirements.txt
pip install -e .               # installs the `certmgr` CLI entry point (pyproject.toml)
cp .env.example /etc/certmgr/certmgr.env   # fill values; env file format
sudo cp ../deploy/systemd/certmgr-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certmgr-api certmgr-worker certmgr-beat
```

Front the API with nginx using `infra/nginx/` configs (adjust `server_name`,
certificate paths). Install PostgreSQL 16 and Redis 7 and create the database:

```sql
CREATE USER certmgr WITH PASSWORD 'certmgr';
CREATE DATABASE certmgr OWNER certmgr;
```

## Using an existing MariaDB instance (disk-constrained servers)

If you already run MariaDB and want to avoid running a second DBMS (zero extra
disk), point the app at it directly — MariaDB is a fully supported fallback
(dialect-safe SQL, `MEDIUMTEXT` log columns, `mysqldump` backups):

```sql
-- 1. On your existing MariaDB (as root/admin):
CREATE DATABASE certmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'certmgr'@'127.0.0.1' IDENTIFIED BY '<strong-password>';
GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'127.0.0.1';
FLUSH PRIVILEGES;
```

```bash
# 2. In /etc/certmgr/certmgr.env (or your env file):
CERTMGR_DATABASE_URL=mysql+pymysql://certmgr:<strong-password>@127.0.0.1:3306/certmgr
CERTMGR_MYSQLDUMP_BINARY=/usr/bin/mysqldump      # for DB backups
# Data-retention keeps the DB small (see Administration guide):
CERTMGR_EXECUTION_RETENTION_DAYS=365
CERTMGR_AUDIT_RETENTION_DAYS=730
CERTMGR_NOTIFICATION_RETENTION_DAYS=365

# 3. Migrate schema + start services:
cd /opt/certmgr/backend && ./.venv/bin/alembic upgrade head
sudo systemctl restart certmgr-api certmgr-worker certmgr-beat
certmgr status          # database should report "mysql"
```

The `PyMySQL` driver ships in `requirements.txt`; the `MEDIUMTEXT` migration
runs automatically (no-op on PostgreSQL). See
[migration-mariadb-to-postgres.md](migration-mariadb-to-postgres.md) for the
later move to PostgreSQL.

## Database support matrix

| Engine | Status | URL | Notes |
|---|---|---|---|
| **PostgreSQL 12+** | **Primary (tested in CI)** | `postgresql+psycopg://user:pass@host:5432/db` | JSONB, `NULLS LAST`, `pg_dump` backups |
| **MariaDB 10.3+ / MySQL 8** | **Supported fallback** | `mysql+pymysql://user:pass@host:3306/db` | `pymysql` driver, dialect-safe SQL, `MEDIUMTEXT` log columns, `mysqldump` backups. 10.3 works (verified); **10.5+ recommended** — 10.3 is EOL since May 2023, plan an upgrade |
| **SQLite** | Dev/tests only | `sqlite:///./certmgr-dev.db` | single-writer — not for production |

MariaDB support: the engine factory adds `charset=utf8mb4`; the inventory
ordering is dialect-aware (no `NULLS LAST` on MySQL/MariaDB); backups use
`mysqldump`. Covered by compile-time dialect tests and a full migration-DDL
verification for the MySQL dialect.

## Configuration reference

All configuration is via environment variables prefixed `CERTMGR_`
(see `backend/.env.example`). Key groups:

| Group | Variables |
|---|---|
| App | `CERTMGR_ENVIRONMENT`, `CERTMGR_DEBUG`, `CERTMGR_CORS_ORIGINS` |
| Security | `CERTMGR_SECRET_KEY`, `CERTMGR_SECRETS_MASTER_KEY`, `CERTMGR_SECRETS_ENCRYPTION_FILE`, `CERTMGR_ACCESS_TOKEN_EXPIRE_MINUTES`, `CERTMGR_MFA_REQUIRED`, `CERTMGR_CSRF_ENABLED`, `CERTMGR_COOKIE_SECURE` |
| Data | `CERTMGR_DATABASE_URL`, `CERTMGR_REDIS_URL`, `CERTMGR_DB_POOL_SIZE` |
| Celery | `CERTMGR_CELERY_BROKER_URL`, `CERTMGR_CELERY_RESULT_BACKEND`, `CERTMGR_CELERY_TASK_ALWAYS_EAGER` |
| Storage | `CERTMGR_STORAGE_ROOT`, `CERTMGR_BACKUP_ROOT`, `CERTMGR_LOG_ROOT`, `CERTMGR_TEMP_WORKDIR`, `CERTMGR_STORAGE_BACKEND` |
| Certbot | `CERTMGR_CERTBOT_BINARY`, `CERTMGR_CERTBOT_WORKDIR`, `CERTMGR_DEFAULT_LETSENCRYPT_EMAIL`, `CERTMGR_DEFAULT_STAGING` |
| Scheduler | `CERTMGR_RENEWAL_THRESHOLD_DAYS`, `CERTMGR_RENEWAL_CRON`, `CERTMGR_DISCOVERY_CRON`, `CERTMGR_HEALTH_CRON`, `CERTMGR_BACKUP_CRON` |
| Notifications | `CERTMGR_SMTP_*` |
| Deployment | `CERTMGR_SSH_CONNECT_TIMEOUT`, `CERTMGR_SSH_COMMAND_TIMEOUT`, `CERTMGR_DEPLOYMENT_VERIFY_ENABLED`, `CERTMGR_DEPLOYMENT_ROLLBACK_ENABLED` |
| Observability | `CERTMGR_PROMETHEUS_ENABLED`, `CERTMGR_METRICS_AUTH_TOKEN`, `CERTMGR_JSON_LOGGING`, `CERTMGR_LOG_LEVEL` |
| AI (optional) | `CERTMGR_AI_ENABLED`, `CERTMGR_AI_API_KEY`, `CERTMGR_AI_BASE_URL`, `CERTMGR_AI_MODEL` |
| Vault (optional) | `CERTMGR_VAULT_ENABLED`, `CERTMGR_VAULT_URL`, `CERTMGR_VAULT_TOKEN`, `CERTMGR_VAULT_KV_PATH` |

## Upgrades

1. `git pull`
2. `docker compose build api worker beat && docker compose up -d`
3. `alembic upgrade head` runs automatically; for bare metal run it manually first.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| API refuses to boot in production | `CERTMGR_SECRETS_MASTER_KEY` missing/too short |
| Issuance fails `DNS problem: NXDOMAIN` | DNS record missing; use AI assistant on the failed job for the fix |
| Deployment fails `Connection refused` | Server unreachable or wrong SSH credentials in Server inventory |
| Certbot rate limited | Use staging for testing; consolidate SANs |
| Workers not running tasks | Redis unreachable; check `CERTMGR_REDIS_URL` |
