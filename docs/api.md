# REST API

Interactive documentation is served at `/docs` (Swagger UI), `/redoc`, and the
OpenAPI spec at `/api/v1/openapi.json`. All endpoints are prefixed `/api/v1`.

## Authentication

1. `POST /auth/login` `{username, password, mfa_code?}` → `{access_token, refresh_token, ...}`
2. Send `Authorization: Bearer <access_token>` (or `X-API-Key: <token>` for API tokens).
3. `POST /auth/refresh` with the refresh token rotates the access token.
4. `POST /auth/logout` revokes the refresh token.

### Creating API tokens
`POST /auth/tokens` (authenticated) → returns the token **once**; only its SHA-256
hash is stored. Use for CI/CD.

## Error envelope

All errors return `{"error": {"code": "...", "message": "...", "details": {...}}}`.
Common codes: `UNAUTHORIZED`, `FORBIDDEN`, `VALIDATION_ERROR`, `NOT_FOUND`,
`CONFLICT`, `RATE_LIMITED`, `PROVIDER_ERROR`, `DEPLOYMENT_ERROR`, `MAINTENANCE_MODE`.

## Core resources

### Certificates
| Method | Path | Purpose |
|---|---|---|
| GET | `/certificates` | Inventory (search, filters, sort, pagination) |
| GET | `/certificates/{id}` | Details |
| POST | `/certificates/issue` | Issue (wizard payload) — returns queued or completed |
| POST | `/certificates/{id}/renew` | Renew (`{force}`) |
| POST | `/certificates/{id}/revoke` | Revoke (`{reason, delete_after}`) |
| POST | `/certificates/{id}/clone` | Clone to new domains |
| POST | `/certificates/import/upload` | Multipart import (cert/key/chain/pfx) |
| POST | `/certificates/import/paths` | Server-side import from paths |
| POST | `/certificates/bulk` | `{action: renew\|revoke\|deploy, ids: [...]}` |
| GET | `/certificates/{id}/download/{fmt}` | `zip\|pem\|key\|chain\|fullchain\|pfx` (audited; key gated) |
| GET | `/certificates/{id}/executions` | Execution history with logs |
| POST | `/certificates/{id}/favorite` · `/tags` | Favorites / tags |
| POST | `/certificates/wizard/validate/*` | Step-level wizard validation |

### Servers & deployment
| Method | Path | Purpose |
|---|---|---|
| GET/POST/PATCH | `/servers` | Inventory CRUD |
| POST | `/servers/{id}/test` | SSH connectivity test |
| POST | `/servers/{id}/command` | Allowlisted remote command |
| POST | `/servers/{id}/service/{svc}/{action}` | status/restart/reload/stop/start |
| POST | `/deployments` | Deploy certificate to server |
| GET | `/deployments` | Deployment history |
| POST | `/deployments/{id}/rollback` | Manual rollback |
| GET/POST | `/deployments/templates` | Deployment templates |

### Operations
| Resource | Paths |
|---|---|
| Hooks | `/hooks` (CRUD) |
| Discovery | `/discovery/run`, `/discovery/runs` |
| Health | `/health/certificate/{id}/scan`, `/health/certificate/{id}/checks` |
| Compliance | `/compliance/dashboard`, `/compliance/report` |
| Reports | `/reports/{type}.{csv\|xlsx\|pdf\|json}` |
| Webhooks | `/webhooks/endpoints`, `/webhooks/deliveries` |
| Notifications | `/notifications/settings`, `/notifications` |
| Jobs | `/jobs`, `/jobs/{id}/retry` |
| Audit | `/audit` |
| Dashboard | `/dashboard/*` |
| Search | `/search?q=` |
| AI | `/ai/explain/{exec_id}`, `/ai/troubleshoot/{exec_id}`, `/ai/recurring-failures`, `/ai/predict-renewal-failures`, `/ai/summarize/{cert_id}` |
| Backups | `/backups`, `/backups/run` |
| Users/Roles | `/users`, `/users/roles` |
| Settings | `/settings`, `/settings/{key}`, `/settings/maintenance` |
| Providers | `/providers` |
| Scheduled jobs | `/scheduled-jobs` |

## Pagination & filtering

- Lists accept `page`, `page_size` (≤500), `sort_by`, `sort_dir`, `search`, and
  field filters (`status`, `environment`, `issuer`, `provider`, `key_type`,
  `renewal_status`, `cert_type`, `owner_id`, `tags`, `auto_renew`).
- Responses include `{items, total, page, page_size, pages, summary}`.

## Webhooks (outbound)

Signed with `X-CertMgr-Signature: sha256=<hmac>` (HMAC-SHA256 over the raw JSON
body with the endpoint secret). Retries: the delivery record keeps response codes
and errors; a worker redelivers failed events.

## Rate limiting

- Login: `10/minute` per IP.
- General API: `300/minute` per IP (Redis-backed in production; headers
  `X-RateLimit-*` enabled).
