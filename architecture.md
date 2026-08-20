# CertMgr — Architecture

> Version 1.0.0 · Companion to [document.md](document.md) and
> [changelog.md](changelog.md). This document describes the system
> architecture, component responsibilities, data model, key flows, security
> architecture, deployment topologies, observability and extensibility.

---

## 1. System context

```
                    ┌──────────────────────────────┐
                    │          Operators           │
                    │   (browser / REST / CLI)     │
                    └──────────────┬───────────────┘
                                   │ HTTPS (JWT, RBAC, CSRF)
                    ┌──────────────▼───────────────┐
                    │      Nginx (edge proxy)      │
                    │  TLS termination, CSP/HSTS   │
                    └──────────────┬───────────────┘
                                   │ /api/v1
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
┌───────▼────────┐        ┌────────▼────────┐        ┌────────▼────────┐
│  FastAPI API   │        │  Celery worker  │        │ Celery beat     │
│  (stateless,   │        │  (N instances)  │        │ (exactly one)   │
│  N replicas)   │        └────────┬────────┘        └────────┬────────┘
└───────┬────────┘                 │                          │
        │        ┌─────────────────┼───────────────┐          │
        │        │                 │               │          │
┌───────▼────┐ ┌─▼─────────┐ ┌─────▼──────┐ ┌──────▼───────┐ │
│ PostgreSQL │ │  Redis    │ │ Encrypted  │ │ Certbot /    │ │
│  / MariaDB │ │ broker+   │ │ file store │ │ OpenSSL CA / │ │
│ (metadata) │ │ cache+RL  │ │ (Fernet)   │ │ SSH targets  │ │
└────────────┘ └───────────┘ └────────────┘ └──────────────┘ │
                                                              │
            All workers + API read the same schedule/config ──┘
```

## 2. Technology stack

| Layer | Technology |
|---|---|
| API | Python 3.11–3.13 · FastAPI · Uvicorn (Gunicorn optional) |
| ORM / migrations | SQLAlchemy 2.0 · Alembic |
| Validation | Pydantic v2 · pydantic-settings |
| Background jobs | Celery + Redis (broker/backend) · APScheduler (in-process option) |
| Databases | PostgreSQL 12+ (primary) · MariaDB 10.3+/MySQL 8 (fallback) · SQLite (dev) |
| Crypto | cryptography (x509), Fernet (at-rest encryption), bcrypt, PyJWT, pyotp |
| Remote ops | paramiko (SSH/SFTP/SCP), rsync |
| Frontend | React 18 · TypeScript · Vite · Material UI · Tailwind · React Query · Recharts |
| Infra | Docker Compose · nginx · systemd · Prometheus/Grafana |
| CI | GitHub Actions (Postgres + MariaDB × Python 3.11/3.13, Trivy) |

## 3. Clean-architecture layering

| Layer | Location | Responsibility | Depends on |
|---|---|---|---|
| **Interface** | `app/api/`, `cli/`, `app/tasks/` | HTTP routes, CLI commands, Celery tasks | Services only |
| **Application services** | `app/services/` | Lifecycle, deployment, discovery, notifications, health, compliance, reports, backups, retention, AI | Models, providers |
| **Domain** | `app/services/providers/` | `CertificateProvider` abstraction + registry | models/enums |
| **Persistence** | `app/models/` | SQLAlchemy 2.0 ORM (30 tables) | — |
| **Contracts** | `app/schemas/` | Pydantic v2 request/response models | — |
| **Infrastructure** | `app/core/` | config, logging, security, middleware, scheduler, DB engine, metrics | — |

**Dependency rule:** routes/tasks/CLI never touch models directly for business
operations; they call services. Services never import routers. Schemas validate
at the boundary. This keeps the domain testable and lets Celery workers and the
API share identical business logic (`certificate_service` is used by both).

## 4. Components

### 4.1 FastAPI application (`app/main.py`)
- Lifespan: DB connectivity check → seed roles/settings/bootstrap admin
  (concurrency-safe across workers) → optional APScheduler.
- Middleware stack: request context (request-id) → security headers → CSRF →
  metrics → CORS.
- Health: `/health/live` (liveness), `/health/ready` (DB check),
  `/health` (summary + maintenance + providers).
- Metrics: `/metrics` (Prometheus, optionally bearer-protected).

### 4.2 Celery workers + beat (`app/tasks/`)
Beat schedule (UTC): renewal 03:00 · discovery 02:30 · health every 4h ·
backup 01:00 · compliance 04:30 · expiry warnings 06:00 · daily summary 07:00 ·
weekly verify Sun 02:30 · retention 04:00 · backup cleanup Sat 05:30.
Workers run through `db_task` (fresh session + maintenance-mode guard) and
respect `renewal_retry_max` with backoff.

### 4.3 Certificate provider plugin framework
```python
class CertificateProvider(ABC):
    provider_key: str                 # e.g. "letsencrypt"
    def capabilities(self) -> ProviderCapabilities   # drives the UI wizard
    def validate_config(self, config) -> list[str]
    def issue(self, IssueRequest) -> IssueResult
    def renew(self, cert_name, ...) -> RenewResult
    def revoke(self, cert_path, reason) -> RevokeResult
    def verify(self, cert_path, domains) -> tuple[bool, str]
```
- Built-ins: `letsencrypt` (Certbot/ACME v2), `openssl-ca` (internal PKI).
- Third-party CAs ship as packages exposing the `certmgr.providers` entry
  point; the registry discovers them at startup. **The core never changes when
  a new CA is added.**
- Provider configs are stored in the `providers` table, encrypted at rest, and
  hydrated at runtime.
- **GoDaddy is intentionally *not* a `CertificateProvider`** — it's a
  separate, narrower service (`app/services/godaddy_service.py` +
  `godaddy_client.py`) that only pulls an already-issued certificate by
  domain or certificate ID and imports it via the standard import pipeline.
  GoDaddy's API doesn't support ACME-style issue/renew automation, so forcing
  it into the `issue()`/`renew()` interface would misrepresent what it
  actually does. Credentials are two Settings entries
  (`godaddy.api_key`/`godaddy.api_secret`), not a `providers` row — this
  project has no generic UI/API to manage `providers` rows for *any*
  provider yet (letsencrypt/openssl-ca configs are seeded, not
  user-editable through the app today).

### 4.4 Encrypted file store (`app/services/storage.py`)
- Layout: `{storage_root}/{sha256-fingerprint}/` containing `cert.pem`,
  `chain.pem`, `fullchain.pem`, `privkey.enc.pem` (Fernet-encrypted), `bundle.pfx`.
- Public material plaintext; **private keys always encrypted at rest** even on
  plain filesystems/NFS (defense in depth).
- Backends: `filesystem`, `encrypted-filesystem`, `nfs` (S3 planned).

### 4.5 Secret management (`app/services/secrets.py`)
- Priority: Vault (optional) → env → encrypted app-settings rows.
- Fernet master key from `CERTMGR_SECRETS_MASTER_KEY` / key file; production
  refuses to boot without one.

### 4.6 Command execution (`app/services/command.py`)
- The **only** execution primitive: `subprocess.run(argv, shell=False)`.
- Per-argument metacharacter validation; optional setuid to another user;
  full stdout/stderr/exit-code/duration capture.

## 5. Data model (30 tables)

```
users 1───* api_tokens        roles 1───* users
users 1───* refresh_tokens    users 1───* favorites *───1 certificates
users 1───* audit_logs

certificates 1───* certificate_domains
certificates *───* tags (certificate_tags)
certificates 1───* job_executions
certificates 1───* deployments *───1 servers
certificates 1───* backups
certificates 1───* certificate_health_checks
certificates 1───* certificate_relationships
servers *───* tags (server_tags)
deployment_templates 1───* deployments
webhook_endpoints 1───* webhook_deliveries
providers · hooks · discovery_runs · discovery_ignores · scheduled_jobs ·
app_settings · maintenance_windows · compliance_reports · notifications ·
notification_settings
```

Key design decisions:
- Integer PKs, indexed lookups, JSON columns (SANs/tags/checks/config) —
  PostgreSQL `JSONB`-compatible, cross-DB with SQLite/MariaDB.
- Enums stored as strings with application-level validation (portable).
- **No private-key material in the DB — encrypted file paths only.**
- `job_executions.stdout/stderr` and `notifications.body` are `MEDIUMTEXT` on
  MySQL/MariaDB (TEXT caps at 64 KB; logs up to 100 KB) — dialect-variant
  `LONGTEXT` in models, guarded migration.

Full ER detail: `docs/database.md`.

## 6. Key flows

### 6.1 Issuance (Let's Encrypt)
1. `POST /certificates/issue` → validated by `IssueRequestSchema`
2. `certificate_service.issue_certificate()` creates row + domains + tags
3. `_execute_issuance()` opens a `JobExecution`, calls
   `provider.issue(IssueRequest)`
4. `LetsEncryptProvider` builds a **validated argv list** and runs it via
   `subprocess.run(..., shell=False)`, capturing stdout/stderr/exit/duration
5. On success, issued files are copied into the encrypted store; x.509
   metadata parsed and written back; audit + notifications queued
6. Celery (or eager mode) executes the same path; UI polls executions for live
   logs

### 6.2 Renewal
- Daily sweep finds auto-renew certificates expiring within the threshold;
  calls `renew_certificate` per cert (status guard prevents concurrent runs).
- Failure → `renewal_status=failed` + notification; retries with backoff.

### 6.3 Import
- PEM/CRT/CER (+key/chain) or PFX upload → parse → extract metadata (issuer,
  SAN, fingerprint, key algo/size, validity) → verify key matches cert →
  store encrypted → dedupe by fingerprint → audit + notify.
- **GoDaddy variant**: resolve a certificate ID (given directly, or via a
  best-effort domain search — GoDaddy's own domain filter doesn't reliably
  narrow results, so every candidate's actual commonName/SANs is re-checked
  client-side) → download the cert+chain bundle (no private key; GoDaddy
  never holds it) → same import pipeline as above.

### 6.4 Deployment (with automatic rollback)
```
pre-deploy hook → stage files (SFTP/SCP/rsync) → backup existing remote files
→ install + chmod/chown → post-deploy hook → reload service → TLS verification
→ on ANY failure: restore remote backup (rollback)
```
Templates are Jinja2-rendered per deployment; every run stores a log + the
verification JSON.

### 6.5 Discovery
Scheduled scan of configured paths → parse cert/key/PFX → fingerprint dedupe →
import via the standard import pipeline → run summary + audit.

### 6.6 Backup / restore / verify
- Daily: archive each certificate's material (encrypted keys) + DB dump
  (`pg_dump`/`mysqldump`/sqlite copy) + retention cleanup.
- Weekly: verify archives (integrity, members, SHA-256 vs DB) and dump
  readability.
- Restore: match by fingerprint → restore into existing row or import new;
  keys stay encrypted; `--dry-run` previews.

### 6.7 Notifications & webhooks
- Event → queue `Notification` rows for enabled channels → worker delivers
  (SMTP/Slack/Teams/webhook). Outbound webhooks signed with HMAC-SHA256,
  delivery history with response codes.

## 7. Security architecture

- **Command execution:** argv-only, validated; no shell interpolation.
- **At-rest encryption:** keys + secrets Fernet-encrypted; master key from
  env/file/Vault; production fails closed without it.
- **Authentication:** JWT access+refresh (rotation, revocation on password
  change), API tokens (SHA-256 hashed), TOTP MFA, lockout, password policy.
- **CSRF:** double-submit cookie; `GET /auth/csrf` establishes it; auth
  endpoints exempt (public, SameSite=Lax already mitigates); Bearer requests
  exempt (header auth not CSRF-able); middleware remains for non-auth
  state-changing requests.
- **RBAC matrix:** administrator / certificate_manager / operator / read_only
  with granular permission codes (`certificate:issue`,
  `certificate:download_key`, `server:command`, `admin:settings`, …).
- **Remote access:** allowlist-only maintenance commands; service-name
  allowlist.
- **Log redaction:** private keys/passwords/tokens stripped at the logging
  boundary.
- **Rate limiting:** Redis-backed; login 10/min, API 300/min.

Full threat model: `docs/security.md`.

## 8. Deployment topologies

### 8.1 Single node (bare metal)
nginx + API + worker + beat + PostgreSQL/MariaDB + Redis on one host; systemd
units + timers. Sufficient up to a few thousand certificates.

### 8.2 High availability
- **N stateless API replicas** behind a load balancer (JWT in headers, shared
  Postgres/Redis).
- **M Celery workers** (idempotent tasks, `acks_late`,
  `prefetch_multiplier=1`); **exactly one beat** scheduler.
- **Shared PostgreSQL** (or MariaDB) and **shared Redis**.
- Certificate material on shared storage (NFS or object storage) since keys
  are encrypted at rest regardless of backend.
- Liveness/readiness probes gate LB traffic; `/metrics` per replica.

### 8.3 Docker Compose
postgres:16 · redis:7 · api (uvicorn ×4) · worker · beat · nginx; volumes for
cert-data/logs/letsencrypt; migrations on API start.

## 9. Observability

- `/health/live`, `/health/ready` (DB), `/health` (summary + maintenance).
- `/metrics` — HTTP counters/latency, certbot executions, certificate gauges,
  nearest-expiry, job outcomes. Grafana dashboard:
  `infra/grafana/dashboards/certmgr.json`.
- **Prometheus multiprocess mode** (`PROMETHEUS_MULTIPROC_DIR`, set on both
  the API and worker systemd units) is required for certbot-execution and
  job-outcome metrics to be accurate: the API (N uvicorn workers) and the
  worker are separate OS processes, each with its own in-memory
  Counter/Gauge state, and virtually all real certbot/job activity happens
  in the worker — a plain single-process `/metrics` scrape would never see
  it. The two certificate gauges use `multiprocess_mode="mostrecent"` since
  they're already recomputed fresh from the DB on every scrape rather than
  incremented in-line.
- Structured JSON logs with request-id context; redaction filter; log
  rotation via systemd/journal or logrotate.

## 10. Extensibility

| Extension point | Mechanism |
|---|---|
| New CAs as full issue/renew automation (DigiCert, Sectigo, GlobalSign, Entrust, ADCS…) | `CertificateProvider` + `certmgr.providers` entry point |
| GoDaddy specifically | Narrower, already-built fetch-existing-certificate integration — not a `CertificateProvider` (see §4.3) |
| Deployment targets | Jinja2 deployment templates + SSH/rsync methods |
| Notification channels | `notification_service` channel registry |
| Authentication | `SecretManager` abstraction; OIDC/LDAP scaffolding in settings |
| Storage | `FileStore` interface (S3 planned) |
| AI | heuristic engine by default; optional LLM provider |
| Scheduler | Celery beat + APScheduler in-process mode; user-defined scheduled jobs |

## 11. Sizing & scaling

| Workload | Sizing |
|---|---|
| 1k certs / 50 servers | 1 node, 2–4 GB RAM; DB ~150–400 MB with retention defaults |
| 5k certs / 300 servers | 2 API replicas + 2 workers + beat; DB ~1–3 GB |
| 10k certs / HA | 3+ API replicas, shared PG + Redis, dedicated certbot worker node |

Renewal sweep at 03:00 handles ~100 renewals/min comfortably. DB growth is
bounded by data retention (defaults: executions 365d, audit 730d,
notifications 365d).
