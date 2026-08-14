# Administrator Guide

## Roles & permissions

| Role | Permissions (summary) |
|---|---|
| `administrator` | Everything: users, settings, providers, webhooks, maintenance, reports, commands |
| `certificate_manager` | Full certificate lifecycle + deploy; view-only for admin surfaces |
| `operator` | Issue/renew/import/export/deploy; no revoke, no key downloads, no user mgmt |
| `read_only` | View certificates, servers, hooks, audit, health |

Permission codes are granular (`certificate:issue`, `certificate:download_key`,
`server:command`, `admin:settings`, …) and are enforced in the API dependency layer
and honored by the UI. The matrix lives in `app/api/permissions.py` and is seeded
into the `roles` table at startup.

## Global settings (Settings page)

| Key | Purpose |
|---|---|
| `letsencrypt.email` | ACME account contact |
| `default.key_type` / `default.validation_method` | Wizard defaults |
| `renewal.threshold_days` | Auto-renew certificates expiring within N days |
| `storage.*` | Certificate/backup/temp locations |
| `discovery.scan_paths` | Comma-separated discovery directories |
| `smtp.*` / `slack.webhook_url` / `teams.webhook_url` / `webhook.url` | Notification channels (secrets masked in UI) |
| `maintenance.message` | Optional banner during maintenance |

Secrets are Fernet-encrypted before storage; the UI shows only `[SET]`.

## Providers

- `letsencrypt` — ACME v2 via Certbot. Supports all validation modes and key types.
- `openssl-ca` — internal PKI (OpenSSL). Configure `ca_key_path`, `ca_cert_path`,
  `org`, `validity_days` in the provider row.
- Adding a CA: implement `CertificateProvider`, register the entry point
  `certmgr.providers`, restart. No core changes.

## Running the worker as root for root-only hook scripts

`certmgr-worker` normally runs as the unprivileged `certmgr` (or `$APP_USER`)
service account, matching `certmgr-api` and `certmgr-beat`. Some sites have
pre-existing certbot auth/cleanup hook scripts that require root — e.g. a
script that `ssh`es out as root to place an HTTP-01 challenge file on a
separate front-end host, where no lesser-privileged account is authorized for
that hop, and organizational policy doesn't permit adding one (e.g. sudoers
is centrally managed and closed to new rules, or the service account has a
`nologin` shell that's itself denied `sudo` by PAM). In that situation the
practical options are: get the target host to authorize a scoped account/key
for the hop, or run just the worker as root.

If you must run the worker as root: edit the deployed
`/etc/systemd/system/certmgr-worker.service` (not just the repo template —
`systemctl` reads the installed copy) and change:

```
User=root
Group=root
ProtectHome=read-only   # ProtectHome=true hides /root/.ssh, breaking the hook's own SSH
```

then `systemctl daemon-reload && systemctl restart certmgr-worker`. Only
`certmgr-worker` ever executes certbot/hooks — leave `certmgr-api` and
`certmgr-beat` on the unprivileged account, since elevating them buys no
benefit and only widens what a bug in the RBAC-facing API process could
reach. This is a real reduction in process isolation for the worker
specifically — a bug in certificate issuance/renewal code, or in a
third-party CA provider plugin, now runs as root instead of a scoped service
account. Weigh it against your actual constraint before applying it, and
prefer getting the remote host to authorize a scoped, non-root account for
the SSH hop if that ever becomes possible.

## SSH credentials for hook scripts (Jenkins-credential-style)

Some auth/cleanup hook scripts `ssh` to a remote host with no `-i` flag to
place/remove an ACME challenge file — e.g. `ssh -l root front-end01 "echo
$VALIDATION > .well-known/acme-challenge/$TOKEN"`. That only works when the
calling process already trusts a key (an interactively-forwarded agent, or a
key at one of ssh's default identity paths), which a headless
`certmgr-worker` doesn't have. Rather than editing the hook script, a Hook
row can carry an encrypted SSH private key (Hooks page → New/Edit hook →
"SSH credential") and a target host; CertMgr stages it as a scoped,
temporary `ssh_config` `Host` entry for the duration of a single hook-driven
issuance, then removes it — the key is Fernet-encrypted at rest and never
returned by the API (masked as "configured" in the UI, replace/clear only).

**One-time setup required** before this works, on whatever host runs
`certmgr-worker`:

1. Add an `Include` line near the **top** of the worker's `~/.ssh/config`
   (create the file if it doesn't exist), pointing at the directory CertMgr
   stages per-job fragments into:

   ```
   Include ~/.ssh/certmgr.d/*.conf
   ```

   (Matches the default `CERTMGR_SSH_CONFIG_INCLUDE_DIR=~/.ssh/certmgr.d` —
   override that env var if you want a different directory, and update the
   `Include` line to match.)

2. If the worker's systemd unit hardens the filesystem (`ProtectHome=`,
   `ProtectSystem=strict`), make sure the worker's `~/.ssh` directory and
   `CERTMGR_SSH_KEY_STAGING_DIR` (default `/var/lib/certmgr/tmp/ssh`, already
   under the default `ReadWritePaths=`) are writable. If the worker runs as
   `root` under `ProtectHome=read-only` (see the section above), add the
   `~/.ssh/certmgr.d` directory specifically to `ReadWritePaths=` — read-only
   mode allows reads but not the writes CertMgr needs there.

3. Restart `certmgr-worker` after changing either file.

Without step 1, CertMgr refuses to run the issuance rather than silently
proceed without the credential — you'll see a clear "SSH credential
injection requires a one-time setup step" error on the certificate's job
execution log instead.

## Maintenance mode

Settings → Maintenance: pause renewals / deployments / notifications / imports /
background jobs, optionally until a scheduled end time. Celery tasks check the flag
before executing; API lifecycle endpoints reject operations while active.

## Scheduled jobs

Beat schedule is fixed (see `app/tasks/celery_app.py`) and additionally manageable
via `GET/POST/PATCH /api/v1/scheduled-jobs` for user-defined jobs (interval or cron)
when the API runs with `CERTMGR_RUN_SCHEDULER=1` (single-node in-process mode).

## Backups & restore

- `POST /api/v1/backups/run`, the daily Celery beat task, or the CLI
  `certmgr backup` snapshot every certificate's material (encrypted keys
  included) into `CERTMGR_BACKUP_ROOT`, then dump the database. Certificates
  with no material on disk (failed/revoked) are skipped, never archived empty.
- Database dump engine is auto-selected from `CERTMGR_DATABASE_URL`:
  `pg_dump` for PostgreSQL (`CERTMGR_PG_DUMP_BINARY`), `mysqldump` for
  MariaDB/MySQL (`CERTMGR_MYSQLDUMP_BINARY`), or a plain file copy for SQLite.
- Retention: backups older than `CERTMGR_BACKUP_KEEP_DAYS` (default 30) are
  removed on each run.
- **Bare-metal (systemd):** the OL8 setup script installs a daily timer
  (`certmgr-backup.timer`, 01:00) that runs `certmgr-backup.service` →
  `certmgr backup`, plus a **weekly verification timer**
  (`certmgr-backup-verify.timer`, Sun 02:30) that runs
  `certmgr-backup-verify.service` → `certmgr verify-backups`. Logs go to
  `/var/log/certmgr/backup.log` and `backup-verify.log`. Manual runs:
  `sudo systemctl start certmgr-backup.service` /
  `sudo systemctl start certmgr-backup-verify.service`.

### Restore

- CLI: `certmgr restore --backup <archive.tar.gz> [--cert <id>] [--dry-run]`
  - with `--cert` → restores into that row (fingerprint must match the archive)
  - without → matches by fingerprint; if no row exists a new certificate is
    imported
  - keys are restored still encrypted at rest (archives hold the Fernet blob)
  - `--dry-run` validates the archive and reports the plan without writing
- API: `POST /api/v1/backups/{backup_id}/restore` (admin, audited)
- Database restore: restore the dump from `backups/database/`.

### Backup verification

`certmgr verify-backups [--sample] [--no-checksums]` (also
`POST /api/v1/backups/verify`, admin) checks every archive: gzip/tar integrity,
required `cert_path.bin` member present, SHA-256 checksum matches the DB
record, and database dumps are readable (sqlite `integrity_check`, PostgreSQL
`pg_restore --list`, SQL-text scan). Exit code non-zero if anything fails —
surfaced by the weekly timer logs.

## Data retention (bounded DB growth)

Certificate metadata is tiny (≈700 B/row); the database grows through history
tables — **job_executions** (certbot/deploy logs, the biggest), **audit_logs**
and **notifications**. Retention bounds that growth:

| Setting | Default | What it purges |
|---|---|---|
| `CERTMGR_EXECUTION_RETENTION_DAYS` | 365 | `job_executions` older than N days |
| `CERTMGR_AUDIT_RETENTION_DAYS` | 730 | `audit_logs` older than N days |
| `CERTMGR_NOTIFICATION_RETENTION_DAYS` | 365 | `notifications` older than N days |

`0` (or negative) = keep forever. Rough guidance: with defaults, 1,000 certs
≈ 150–400 MB, 5,000 certs ≈ 1–3 GB, stable year over year.

- **Scheduling:** daily at 04:00 via the `certmgr-retention` systemd timer
  (bare metal) and the `daily-retention` Celery beat task (Docker).
- **CLI:** `certmgr retention [--execution-days N] [--audit-days N]
  [--notifications-days N] [--dry-run]` — `--dry-run` previews what would be
  purged. Logs to `/var/log/certmgr/retention.log`.
- **API (admin):** `GET /api/v1/settings/retention` (config + row counts),
  `POST /api/v1/settings/retention/run` (`{"dry_run": true}` to preview).
  Runs are audited (`maintenance.retention`).
- Purging is a single bulk `DELETE` (no row-by-row loads), so it stays fast
  even on large tables.

## Webhooks

Admin → Webhooks: register endpoints with an HMAC-SHA256 signing secret. Events:
`certificate.issued`, `certificate.renewed`, `certificate.expired`,
`certificate.revoked`, `certificate.imported`, `deployment.completed`,
`deployment.failed`, `renewal.failed`. Deliveries (with response codes) are
inspectable under `GET /api/v1/webhooks/deliveries`.

## Compliance

The compliance engine evaluates every certificate against:
- RSA key length ≥ 2048, ECC ≥ 256
- signature algorithms (SHA-1/MD5 flagged)
- certificate lifetime ≤ 398 days (CA/B Forum)
- expired/revoked status, missing SANs, duplicate fingerprints, unused certificates

`GET /api/v1/compliance/dashboard` returns a scored summary; a scheduled task
persists weekly reports.

## Observability

- `/health/ready` gates load balancer traffic.
- `/metrics` exports Prometheus metrics (protect with `CERTMGR_METRICS_AUTH_TOKEN`).
- Grafana dashboard: `infra/grafana/dashboards/certmgr.json`.
- Logs are JSON lines under `CERTMGR_LOG_ROOT` (`app/`, `certbot/`, `deployments/`)
  and mirrored to stdout for container deployments.
