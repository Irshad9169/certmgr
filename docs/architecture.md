# Architecture

## 1. System context

```
                    ┌──────────────────────────────┐
                    │          Operators           │
                    │   (browser / REST / CLI)     │
                    └──────────────┬───────────────┘
                                   │ HTTPS (JWT, RBAC)
                    ┌──────────────▼───────────────┐
                    │      Nginx (edge proxy)      │
                    │  TLS termination, CSP/HSTS   │
                    └──────────────┬───────────────┘
                                   │ /api/v1
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
┌───────▼────────┐        ┌────────▼────────┐        ┌────────▼────────┐
│  FastAPI API   │        │  Celery worker  │        │ Celery beat     │
│  (stateless,   │        │  (n instances)  │        │ (single)        │
│  N instances)  │        └────────┬────────┘        └────────┬────────┘
└───────┬────────┘                 │                          │
        │                          │ schedule                 │
        │        ┌─────────────────┼───────────────┐          │
        │        │                 │               │          │
┌───────▼────┐ ┌─▼─────────┐ ┌─────▼──────┐ ┌──────▼───────┐ │
│ PostgreSQL │ │  Redis    │ │ Encrypted  │ │ Certbot /    │ │
│ metadata   │ │ broker+   │ │ file store │ │ OpenSSL CA / │ │
│ (30 tables)│ │ cache+RL  │ │ (Fernet)   │ │ SSH targets  │ │
└────────────┘ └───────────┘ └────────────┘ └──────────────┘ │
                                                              │
                     All workers + API read the same schedule ─┘
```

## 2. Clean architecture layering

| Layer | Location | Responsibility | Depends on |
|---|---|---|---|
| **Interface** | `app/api/`, `cli/`, `app/tasks/` | HTTP routes, CLI commands, Celery tasks | Services only |
| **Application services** | `app/services/` | Lifecycle, deployment, discovery, notifications, health, compliance, reports, AI | Models, providers |
| **Domain** | `app/services/providers/` | `CertificateProvider` abstraction + registry | models/enums |
| **Persistence** | `app/models/` | SQLAlchemy 2.0 ORM (30 tables) | — |
| **Contracts** | `app/schemas/` | Pydantic v2 request/response models | — |
| **Infrastructure** | `app/core/` | config, logging, security, middleware, scheduler, DB engine | — |

**Dependency rule:** routes/tasks/CLI never touch models directly for business
operations; they call services. Services never import routers. Schemas validate at
the boundary. This keeps the domain testable and lets Celery workers and the API
share identical business logic (`certificate_service` is used by both).

## 3. Certificate provider plugin framework

```python
class CertificateProvider(ABC):
    provider_key: str            # registry id, e.g. "letsencrypt"
    def capabilities(self) -> ProviderCapabilities   # drives the UI wizard
    def validate_config(self, config) -> list[str]
    def issue(self, IssueRequest) -> IssueResult
    def renew(self, cert_name, ...) -> RenewResult
    def revoke(self, cert_path, reason) -> RevokeResult
    def verify(self, cert_path, domains) -> tuple[bool, str]
```

- Built-in plugins: `letsencrypt` (Certbot/ACME v2), `openssl-ca` (internal PKI).
- Third-party CAs ship as Python packages exposing an entry point:

```toml
[project.entry-points."certmgr.providers"]
digicert = "myco.providers.digicert:DigiCertProvider"
```

- The registry (`providers/registry.py`) discovers entry points at startup; the core
  never changes when a new CA is added.
- Each provider returns normalized results (`IssueResult`, `RenewResult`, …); the
  service layer handles persistence, file storage and audit uniformly.

## 4. Certificate issuance flow (Let's Encrypt)

1. `POST /api/v1/certificates/issue` → validated by `IssueRequestSchema`
2. `certificate_service.issue_certificate()` creates the `Certificate` row + domains + tags
3. `_execute_issuance()` opens a `JobExecution` (status=running) and calls
   `provider.issue(IssueRequest)`
4. `LetsEncryptProvider` builds a **validated argv list** (`build_issue_command`) and
   runs it via `subprocess.run(..., shell=False)` capturing stdout/stderr/exit/duration
5. On success, issued files are copied into the encrypted store; x.509 metadata is
   parsed and written back; audit + notification rows are queued
6. Workers (Celery) or the API process (eager mode) executes the same path

In Celery mode the API returns `{status: "queued"}` immediately; the UI polls
`GET /certificates/{id}/executions` for live logs (bounded stdout in DB + full log
file on disk).

## 5. Deployment engine

`deployment_service.deploy_certificate()` implements the workflow:

```
pre-deploy hook → stage files via SFTP → backup existing → install + chmod/chown
→ post-deploy hook → reload service → TLS verification (handshake/chain/hostname/expiry)
→ on ANY failure: automatic rollback from the remote backup dir
```

- Methods: SFTP (paramiko), SCP, rsync (subprocess).
- Templates (`deployment_templates`) are Jinja2-rendered per deployment with vars like
  `{{remote_cert_path}}`, `{{service}}`, `{{backup_dir}}`.
- Verification failures or service reload failures trigger rollback automatically;
  every deployment stores a full log + verification JSON.

## 6. Background processing (Celery)

- **Broker/backend:** Redis. Tasks: `app.tasks.*`.
- **Beat schedule** (UTC): renewal 03:00, discovery 02:30, health every 4h, backup
  01:00, compliance 04:30, expiry warnings 06:00, daily summary 07:00, weekly verify
  Sun 05:00, backup cleanup Sat 05:30.
- All tasks run through `db_task` which opens a fresh session and checks maintenance
  mode; failures respect `renewal_retry_max` with exponential backoff.
- **HA:** the API is stateless (JWT in headers, shared Postgres/Redis); run N API
  replicas and M workers; exactly one beat scheduler.

## 7. Observability

- `/health/live` (liveness), `/health/ready` (DB check), `/health` (summary +
  maintenance state).
- `/metrics` (Prometheus): HTTP counters/latency, certbot executions, certificate
  gauges, job outcomes. Grafana dashboard: `infra/grafana/dashboards/certmgr.json`.
- Structured JSON logs with request-id context; redaction filter strips secrets and
  private-key material from all log sinks.

## 8. Security architecture

See [security.md](security.md) — summarized: JWT + refresh rotation, API tokens,
TOTP MFA, lockout, RBAC permission matrix, CSRF double-submit, Redis rate limits,
Fernet-encrypted secrets & keys at rest, argv-only command execution, allowlisted
remote commands, upload limits, path traversal guards, CSP/HSTS headers.

## 9. Data flow for discovery

`scheduled discovery → DiscoveryRun → walk scan paths → parse cert/key/pfx files →
fingerprint dedupe → import_certificate() → audit + notifications → run summary`

## 10. AI assistance (optional)

`ai_service` first runs a **local heuristic engine** (14+ known Certbot failure
signatures → root cause + fix, recurring-failure detection, renewal-failure
prediction). When `CERTMGR_AI_ENABLED=1` with an API key, the same context is
enhanced by an LLM call; LLM failures degrade gracefully to the local engine.
