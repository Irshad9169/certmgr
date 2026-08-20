# Changelog

All notable changes to CertMgr are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

---

## [1.0.0] — 2026-08-12 — Initial production release

The complete enterprise SSL certificate lifecycle management platform.

### Added — Core platform
- **Certificate lifecycle**: issue (single / multi-SAN / wildcard), renew
  (manual + automatic), revoke, import (PEM/CRT/CER/PFX with automatic
  metadata extraction), clone, bulk actions, favorites, tags, ownership.
- **Providers (plugin registry)**: Let's Encrypt via Certbot (ACME v2) and
  internal PKI (OpenSSL CA). Extensible via `certmgr.providers` entry points
  (DigiCert, GoDaddy, Sectigo, GlobalSign, Entrust, MS ADCS planned).
- **Validation methods**: HTTP-01, DNS-01, manual HTTP/DNS, standalone,
  webroot, custom auth/cleanup hooks (env vars, execution user, working dir,
  timeout).
- **Key types**: RSA 2048/4096, ECDSA P-256/P-384.
- **Deployment engine**: SSH/SCP/SFTP/rsync; Nginx/Apache/HAProxy/OpenVPN/
  Tomcat/Jetty/NodeJS/IIS/PKCS12/custom templates; pre/post-deploy hooks;
  backup → replace → reload → TLS verify → **automatic rollback**.
- **Servers**: inventory, connectivity testing, restricted remote command
  center (allowlist), service control.
- **Discovery**: scheduled scans of /etc/letsencrypt, /etc/pki, /etc/nginx,
  custom paths; auto-import.
- **Health & compliance**: health scores, compliance engine (key length,
  curves, signature algorithms, lifetime, duplicates, unused).
- **Notifications**: SMTP, Slack, Microsoft Teams, signed webhooks; expiry
  thresholds 60/30/15/7/3/1 + lifecycle events; daily summary.
- **RBAC**: administrator / certificate_manager / operator / read_only with
  granular permissions.
- **Auth**: JWT access+refresh (rotation, revocation), API tokens, TOTP MFA,
  account lockout, password policy, CSRF protection.
- **Audit**: every action logged (user, IP, browser, device, duration, result).
- **Background jobs**: Celery workers + beat (renewal, discovery, health,
  compliance, backup, retention, notifications, summary); APScheduler mode.
- **REST API**: full OpenAPI/Swagger; certificates, servers, deployments,
  hooks, discovery, health, compliance, reports, notifications, webhooks,
  jobs, audit, dashboard, search, AI, backups, users, settings.
- **Reports**: CSV / XLSX / PDF / JSON (inventory, expiry, history, failures,
  audit).
- **AI assistant**: explain failures, troubleshooting, recurring-failure
  detection, renewal-failure prediction.
- **Observability**: Prometheus metrics, Grafana dashboard, health endpoints,
  structured JSON logs with redaction.
- **Frontend**: React + TypeScript + MUI + Tailwind; dark/light themes;
  dashboard with charts; 7-step issue wizard with live console; certificate
  details; servers + command center; deployments; discovery; hooks;
  notifications; audit; users; settings + maintenance; compliance; reports;
  AI.
- **CLI**: issue, renew, revoke, deploy, import-cert, verify, inventory,
  discover, server-test, status.
- **Infra**: Docker images (api/worker/beat), docker-compose, nginx config,
  systemd units, GitHub Actions CI/CD.
- **Database support**: PostgreSQL (primary), MariaDB/MySQL (fallback),
  SQLite (dev) — dialect-safe SQL, Alembic migrations.

### Added — Operations (later in 1.0.0)
- **Backups**: daily full backup (certificate material incl. encrypted keys +
  database dump via `pg_dump`/`mysqldump`), retention cleanup, `certmgr backup`
  CLI, admin API.
- **Backup verification**: weekly integrity checks (archives open, required
  members, SHA-256 vs DB record, dump readability), `certmgr verify-backups`,
  Celery task + systemd timer.
- **Restore**: per-certificate restore from archives (fingerprint match or new
  row import), keys stay encrypted at rest, `--dry-run` preview, admin API,
  audited.
- **Data retention**: configurable purge of execution/audit/notification
  history (`CERTMGR_EXECUTION_RETENTION_DAYS` 365, `AUDIT` 730,
  `NOTIFICATION` 365) — bounds DB growth; daily timer + beat task + CLI +
  admin API.
- **First-login password change**: UI now forces and presents a change-password
  screen when `must_change_password` is set.

### Fixed
- **CSRF login deadlock**: auth endpoints are CSRF-exempt by design (public +
  SameSite=Lax mitigation); non-auth state-changing requests remain protected.
  Login self-heals on stale cookies (force token refresh + retry).
- **Token-refresh deadlock** ("Loading platform…" forever): refresh/login
  endpoints exempt from the refresh-retry loop; logout is non-blocking and
  clears the local session immediately.
- **`cors_origins` parsing**: accepts JSON, quote-stripped (`[https://a]`) and
  plain comma-separated forms — fixes env-file `source` failures.
- **MariaDB/MySQL `MEDIUMTEXT`**: stdout/stderr/notification body columns
  widened (TEXT caps at 64 KB; logs up to 100 KB) via dialect-guarded
  migration (no-op on PostgreSQL/SQLite).
- **`CERTMGR_BACKUP_CRON` quoting** in the env file (bash `source` no longer
  errors).
- **Bootstrap-admin seeding race** across uvicorn workers (IntegrityError
  handled, retried).
- **Health check accuracy** in the installer (checks the API on :8000 for
  `"ready"`, not the nginx port-80 redirect).
- **`useradd` on NFS-mounted /home**: fallback to `-M -d <storage>`.
- **Empty backup archives** for material-less certificates are no longer
  created (skipped).
- **RBAC gap**: `/users` and `/users/roles` now admin-only.
- **Log redaction + CLI JSON output**: CLI logs routed to stderr so JSON
  stays clean.
- **Python 3.11 support** verified end-to-end (CI matrix 3.11 + 3.13);
  `requires-python >= 3.11`; installer auto-detects an existing interpreter.

### Security
- Hardened `.gitignore` (inline comments break patterns) so demo CA keys and
  demo storage can never be committed.
- Secret scan in CI; Trivy vulnerability scan on images.

---

## [1.1.0] — 2026-08-20 — Reliability fixes, GoDaddy import, observability

The 1.0.0 release above was a freshly-scaffolded, single-commit codebase with
several critical paths never actually exercised end-to-end. This release is
the result of taking it live on a real internal server and fixing what that
surfaced — security hardening, several silent-failure bugs in the async job
pipeline, and a handful of new operator-facing features.

### Fixed — critical reliability
- **`session_scope()` was missing `@contextmanager`**, breaking every single
  Celery task since the initial commit (`'generator' object does not support
  the context manager protocol`) — the root cause behind bulk actions,
  discovery runs, and queued issuance all silently doing nothing.
- **Async/queued issuance dropped hook/webroot/standalone-port/email
  configuration** — `_execute_issuance()`'s reconstruction path only carried
  6 basic fields from the certificate row. Now persisted on `Certificate` and
  restored on the async path (migration `3f7a9c2e5b1d`).
- **Bulk actions and job retry crashed in real (non-eager) deployments**:
  `.delay()` was called on plain dispatch helper functions, not the actual
  Celery tasks, raising `'function' object has no attribute 'delay'` — masked
  in tests because they always run in eager mode.
- **`discovery.scan_paths` was a dead setting** — `settings_scan_paths()`
  called `get_setting()` with the wrong signature, always raised, and
  silently fell back to hardcoded defaults regardless of what was configured.
  Discovery's imported/skipped counts also always reported 0 (dead stub
  functions overwrote the real, correctly-incremented values).
- **Notification expiry thresholds were a dead env var**
  (`CERTMGR_EXPIRY_WARNING_DAYS` was defined and documented but never read;
  the real logic used a hardcoded `(60, 30, 15, 7, 3, 1)` tuple). Now a live,
  Settings-page-editable value (`notification.expiry_warning_days`), with the
  Notifications page's event-subscription list generated from it instead of
  a matching hardcoded array.
- **PDF reports had no column widths and non-wrapping cells** — a full issuer
  DN, or the 17-column inventory report in general, ran off the edge of the
  page instead of wrapping.
- **Prometheus: 4 of 6 metrics were defined but never incremented anywhere**
  (certbot executions, job outcomes, certificate/expiry gauges) — wired up,
  plus multiprocess-mode support so worker-process activity (where virtually
  all real certbot/job work happens) is actually visible to `/metrics`
  scraped from the API process.
- Certificate delete blocked imported certificates regardless of status
  (only failed/revoked/archived were deletable) — relaxed for imported
  (non-platform-managed) certs specifically, since CertMgr was never their
  issuing/renewal authority.

### Added
- **Certificate delete** and **server delete** — permission codes existed
  with no function/route behind either.
- **SSH credentials on Hooks** (Jenkins-credential-style): an encrypted SSH
  private key + target host, staged as a temporary, host-scoped `ssh_config`
  entry for the duration of a single issuance — for auth/cleanup scripts that
  SSH to a remote host with no identity file of their own.
- **GoDaddy certificate import** — fetch an already-issued certificate by
  domain or certificate ID directly from a GoDaddy account (Import page) and
  bring it into inventory. Deliberately scoped to pulling existing
  certificates only; GoDaddy's API doesn't support ACME-style automated
  issuance/renewal, so this isn't a full `CertificateProvider`.
- **Discovery ignore-list** — deleting a discovery-imported certificate now
  records its fingerprint so the next scan doesn't just re-import the same
  file (`discovery_ignores` table).
- Sortable columns on the Certificates page for ID, Issuer, Env, Status, Key,
  Days and Renewal (previously only Domain/Expires); a visible certificate ID
  column; `qa` added as a selectable environment.
- Audit report export gained date-range filtering, matching what the Audit
  Log page's own list view already had.

---

## [Unreleased] — Planned

- SSO: LDAP/AD, OpenID Connect, OAuth2, SAML (settings scaffolding exists).
- HashiCorp Vault first-class secret backend; CyberArk.
- S3-compatible object storage backend.
- Additional CA plugins as full `CertificateProvider`s: DigiCert, Sectigo,
  GlobalSign, Entrust, Microsoft ADCS. (GoDaddy has a narrower, working
  fetch-existing-certificate integration as of 1.1.0 — see above — but not
  full issue/renew automation, since GoDaddy's API doesn't support that.)
- WebSocket remote terminal (allowlist-constrained).
- Playwright end-to-end test suite.
- Multi-tenancy / folders, approval workflows.

---

*Changelog format: [Keep a Changelog](https://keepachangelog.com/) ·
Versioning: [SemVer](https://semver.org/).*
