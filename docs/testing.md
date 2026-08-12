# Testing Strategy

## Test layers

| Layer | Location | Scope |
|---|---|---|
| Unit | `backend/tests/test_security.py`, `test_domains.py`, `test_certbot.py`, `test_deployment_allowlist.py` | Hashing/JWT/Fernet/redaction, domain & injection validation, certbot argv construction, remote-command allowlist |
| Integration | `backend/tests/test_certificate_service.py`, `test_reports.py` | Real X.509 material (generated with `cryptography`): import (PEM/PFX), metadata extraction, key-match validation, encrypted-at-rest keys, exports, issue/renew/revoke with mocked providers |
| API | `backend/tests/test_api.py` | FastAPI TestClient against in-memory SQLite: auth flows, RBAC enforcement, pagination, uploads, downloads, audit |
| E2E (planned Phase 3) | `e2e/` | Playwright against the docker-compose stack |

## Running

```bash
cd backend && source .venv/bin/activate
pytest -q                    # full suite (currently 110 tests)
pytest -q --cov=app --cov-report=term-missing
ruff check app/ cli/         # lint
bandit -r app/ -x tests      # security scan
```

## Test isolation

- Tests run against an in-memory SQLite engine (StaticPool) so the schema is
  shared but data is reset between tests (`clean_db` fixture).
- `CERTMGR_CELERY_TASK_ALWAYS_EAGER=true` executes Celery tasks synchronously —
  no Redis required in CI.
- The bootstrap admin's password is derived from the test master key; new users
  are created through the real service layer so RBAC paths are exercised.
- Providers are mocked at the `LetsEncryptProvider.issue/revoke` boundary with
  real certificate files written to temp dirs — the full ingest pipeline
  (parse → store → audit) is exercised for real.

## CI

`.github/workflows/ci.yml` runs:

- **lint** (ruff + bandit)
- **`backend-tests`** — the full pytest suite against real **PostgreSQL 16**
  and Redis 7 services
- **`backend-tests-mariadb`** — the full pytest suite against real **MariaDB 11**
  (the supported fallback engine; exercises the dialect-safe ordering, JSON
  columns, and schema creation on MySQL-family servers)
- **`frontend-build`** — TypeScript build + ESLint
- **`build-images`** (main only) — Docker images + Trivy vulnerability scan

Dialect compatibility is additionally covered by compile-time tests in
`tests/test_dialects.py` (MySQL/MariaDB/PostgreSQL/SQLite) and by generating
the full Alembic migration as MySQL-family DDL.

## E2E (roadmap)

A Playwright suite will drive the browser through login → issue wizard →
inventory → details → import, asserting against the dockerized stack with a
stubbed certbot binary.
