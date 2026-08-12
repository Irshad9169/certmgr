# CertMgr — Enterprise SSL Certificate Lifecycle Management Platform

**CertMgr** is a production-grade, self-hosted platform for issuing, renewing, revoking,
importing, deploying, monitoring and auditing SSL/TLS certificates at enterprise scale —
thousands of certificates across hundreds of Linux servers.

It is **not** a simple Certbot frontend. It is a full certificate lifecycle management
platform with a plugin-based provider architecture (Let's Encrypt today; DigiCert,
GoDaddy, Sectigo, GlobalSign, Entrust, MS ADCS and internal PKI plug in without core
changes), a remote deployment engine, automatic discovery, compliance, reporting,
RBAC, audit, notifications, webhooks, background job processing and an AI-assisted
troubleshooter.

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
| **Background jobs** | Celery workers + beat; issuance/renewal/deployment/notifications/discovery/health/compliance/backup |
| **Observability** | Prometheus metrics, Grafana dashboard, `/health/live`, `/health/ready`, structured JSON logs |
| **REST API** | Full OpenAPI + Swagger UI (`/docs`), rate limiting, CSRF protection |
| **CLI** | `certmgr issue|renew|revoke|deploy|import|verify|inventory|discover|status` |

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
                    │  FastAPI (stateless)     │───────▶│  PostgreSQL (metadata)   │
                    │  JWT / RBAC / audit      │        └──────────────────────────┘
                    └──────┬───────────────┬───┘
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
`api/` (HTTP) → `services/` (business logic, providers, engines) → `repositories` (SQLAlchemy models in `models/`) — schemas (`schemas/`) sit at the boundary; `tasks/` (Celery) and `cli/` are secondary entry-points into the same services. No business logic in routes.

```
backend/
├── app/
│   ├── api/            # FastAPI routers + deps (auth, RBAC, audit)
│   ├── core/           # config, logging, database, security, middleware, scheduler
│   ├── models/         # SQLAlchemy 2.0 models (30 tables)
│   ├── schemas/        # Pydantic v2 contracts
│   ├── services/       # certificate lifecycle, certbot, deployment, discovery,
│   │   │               # health, compliance, notifications, webhooks, ai, reports…
│   │   └── providers/  # plugin registry: letsencrypt, openssl-ca (+ future CAs)
│   └── tasks/          # Celery workers + beat schedule
├── alembic/            # migrations
├── cli/                # certmgr CLI (typer)
├── tests/              # 110 unit + integration tests
├── Dockerfile*         # api / worker / beat images
└── requirements.txt
frontend/               # React + TypeScript SPA (Phase 2)
infra/                  # nginx, prometheus, grafana
deploy/systemd/         # systemd units
.github/workflows/      # CI + deploy
docs/                   # full documentation set
```

See [docs/architecture.md](docs/architecture.md) for the detailed architecture and
[docs/database.md](docs/database.md) for the ER model.

---

## Quick start (Docker Compose)

```bash
cp backend/.env.example .env
# edit .env — MUST set CERTMGR_SECRET_KEY and CERTMGR_SECRETS_MASTER_KEY
docker compose up -d --build
```

- UI: `https://localhost` (or `http://localhost`)
- API docs: `http://localhost/api/docs`
- Health: `http://localhost/health/ready`
- Metrics: `http://localhost/metrics`

Bootstrap admin is created on first boot: username `admin`, password =
`CERTMGR_SECRETS_MASTER_KEY` (change immediately — the UI forces it).

### Local development (no Docker)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # Python 3.11 – 3.13
pip install -r requirements-dev.txt
cp .env.example .env           # point DATABASE_URL at sqlite or postgres
alembic upgrade head
uvicorn app.main:app --reload --port 8000
# separate terminal (if using Redis for tasks):
celery -A app.tasks.celery_app:celery_app worker --loglevel=INFO
```

> In development with `CERTMGR_CELERY_TASK_ALWAYS_EAGER=true`, operations run
> synchronously inside the API process — no Redis/worker required.

### CLI

```bash
certmgr status                       # platform state
certmgr issue -d example.com,www.example.com -m ops@corp.com -v dns-01 -k rsa4096
certmgr inventory --status expiring --json
certmgr renew -c 42 --force
certmgr revoke -c 42 --reason keycompromise
certmgr deploy -c 42 -s 3 --service nginx
certmgr import-cert --cert-path /tmp/cert.pem --key-path /tmp/key.pem
certmgr verify -c 42
certmgr discover --paths /etc/nginx,/custom/path
```

---

## Security model

- **No `shell=True` anywhere** — every command is `subprocess.run(argv_list)` with
  per-argument metacharacter validation (lint + tests enforce).
- **Private keys encrypted at rest** (Fernet, master key from env/file/Vault) and
  **never** written to PostgreSQL; DB credentials/secrets also encrypted.
- **JWT** (access + refresh, rotation, revocation), **API tokens** (hashed at rest),
  **TOTP MFA**, account lockout, password policy.
- **RBAC** with granular permission codes (`certificate:issue`, `certificate:download_key`, …).
- **CSRF** double-submit cookie for cookie-authenticated flows; **rate limiting**
  (Redis-backed); secure cookies (SameSite, Secure).
- **Remote command center** executes only an allowlist of maintenance commands.
- **Log redaction** — private keys, passwords and tokens are stripped from every log.
- **Input validation** at the schema layer (domains, emails, paths, uploads, sizes).

See [docs/security.md](docs/security.md).

---

## Demo data (evaluation only)

To verify the UI with realistic mock data before wiring real infrastructure:

```bash
certmgr seed-demo --reset        # populates 10 certs, 6 servers, hooks,
                                 # deployments, notifications, audit, users…
```

- **Never runs automatically** — it is invoked explicitly and is intended for
  evaluation only. The platform starts empty in production.
- Seeds certificates (active/expiring/expired/revoked/failed, wildcard, internal
  CA, weak-signature for compliance demo), servers, hooks (real executable demo
  scripts under `backend/demo-hooks/`), deployment templates + history,
  notifications (4 channels + history), webhook endpoints, audit entries,
  discovery runs, scheduled jobs, backups, and 3 extra RBAC users.
- Demo users: `ops1` (operator), `cm1` (certificate_manager),
  `viewer1` (read_only) — password `Demo!Passw0rd2024`.
- All rows are plain rows in the normal tables. To remove them for a real
  deployment: `certmgr seed-demo --no-reset` keeps data; delete rows manually
  or re-run the reset on a clean database. Demo rows use the `example.com`
  namespace and carry "Demo data" notes for easy identification.

## Testing

```bash
cd backend && source .venv/bin/activate
pytest -q                 # 110 tests: unit, integration, API, RBAC, security
ruff check app/           # lint
bandit -r app/            # security scanner
```

CI (`.github/workflows/ci.yml`): lint → tests against real PostgreSQL+Redis →
docker build + Trivy vulnerability scan. End-to-end flows are documented in
[docs/testing.md](docs/testing.md).

---

## Documentation

| Document | Purpose |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System architecture, components, HA design, plugin framework |
| [docs/installation.md](docs/installation.md) | Installation (Docker & bare-metal), configuration reference |
| [docs/administration.md](docs/administration.md) | Admin guide: settings, roles, providers, maintenance, backups |
| [docs/user-guide.md](docs/user-guide.md) | Operator guide: wizard, inventory, import, deploy, discovery |
| [docs/api.md](docs/api.md) | REST API overview + auth flows (full spec at `/docs`) |
| [docs/database.md](docs/database.md) | ER diagram and table reference |
| [docs/security.md](docs/security.md) | Security architecture and hardening checklist |
| [docs/deployment.md](docs/deployment.md) | HA deployment, systemd, observability, upgrade paths |
| [docs/roadmap.md](docs/roadmap.md) | Delivery phases & future CA/SSO integrations |

---

## Project status (phased delivery)

- **Phase 1 — Backend (complete):** full API, lifecycle engine, providers, deployment,
  discovery, notifications, RBAC, audit, Celery, reports, CLI, tests, Docker/CI/docs.
- **Phase 2 — Frontend (next):** React + TypeScript SPA (wizard, dashboard, inventory,
  details, servers, admin) with dark/light enterprise UI.
- **Phase 3 — Enterprise extensions:** LDAP/OIDC/SAML SSO, Vault secrets, S3 storage,
  CyberArk, additional CA plugins, e2e test suite.

## License

Proprietary — internal enterprise use.
