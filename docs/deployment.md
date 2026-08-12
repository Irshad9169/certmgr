# Deployment Guide (HA)

## High-availability topology

```
                 ┌───────────────────────────┐
LB (nginx/ALB) ─▶│ api-1 │ api-2 │ api-3      │   stateless FastAPI replicas
                 └───────────────────────────┘
                        │                ┌─────────────────────┐
                  shared PostgreSQL ◀──▶│ shared Redis (HA)    │
                        │                └─────────────────────┘
                 ┌───────────────────────────┐
                 │ worker-1 │ worker-2 │ …    │   Celery pool
                 └───────────────────────────┘
                 ┌───────────────────────────┐
                 │ beat (exactly ONE)         │   scheduler
                 └───────────────────────────┘
                 shared NFS / object mount: /var/lib/certmgr (certificates + backups)
```

- API replicas are stateless: JWT in headers, sessions in the token, shared
  Postgres/Redis. Horizontal scale by adding replicas behind the LB.
- **Exactly one beat** instance runs the schedule; workers are idempotent and
  `worker_prefetch_multiplier=1` + `acks_late` avoid duplicate certificate actions.
- Certbot must run on **one host at a time per certificate** — the lock is implicit:
  issuance is queued per certificate and `renewal_status` guards concurrent runs.
  For multi-worker setups, consider a single dedicated "certbot worker" node where
  `/etc/letsencrypt` lives; the file store mount is shared.

## Storage

| Mount | Contents | Recommendation |
|---|---|---|
| `/var/lib/certmgr/certificates` | encrypted keys + certs | NFS or object-storage-backed volume; `encrypted-filesystem` backend |
| `/var/lib/certmgr/backups` | backups | same volume, retention 30d |
| `/var/log/certmgr` | structured logs | local or log-shipper |

`CERTMGR_STORAGE_BACKEND=filesystem|encrypted-filesystem|nfs` — keys are always
Fernet-encrypted regardless of backend (defense in depth), so even plain NFS is safe.

## Health checks

- `GET /health/live` — process alive (no deps).
- `GET /health/ready` — DB reachable (LB drain on non-200).
- `GET /health` — version, environment, maintenance flag, provider list.
- Prometheus `/metrics` per replica.

## Observability stack

`infra/prometheus/prometheus.yml` + Grafana dashboard (`infra/grafana/`):
HTTP rate/latency, certbot executions, certificate gauges, nearest expirations, job
failures. Logs: JSON lines → ship with your collector (Fluentd/Vector/Loki).

## Scaling estimates (reference)

- 5k certificates, 300 servers: 2 API replicas (4 workers each), 2 Celery workers,
  1 beat; Postgres 16 with 4 GB RAM; Redis 1 GB. Renewal sweep at 03:00 handles
  ~100 renewals/min comfortably.

## Upgrade & rollback

1. Tag the release; CI builds images.
2. `docker compose up -d api worker beat` (migrations run on API start).
3. Rollback = `docker compose up -d --force-recreate` with the previous image tag
   (DB migrations are forward-only; restore from backup for schema rollback).

## Disaster recovery

- Daily full DB dump (`backups/database/`) + certificate material backups.
- Restore procedure: restore DB → restore certificate archives → re-run discovery
  to reconcile inventory → verify a sample deployment.
