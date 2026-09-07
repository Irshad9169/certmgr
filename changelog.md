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

## [1.2.0] — 2026-08-27 — Security fix, migration runbook, certificate type

### Fixed — security
- **Shell injection via the Server `proxy_jump` field (RCE)** — the field
  (`user@host[:port]`) had no format validation and was interpolated into a
  command line handed to paramiko's `ProxyCommand`, which runs it via a local
  shell. Anyone able to create/edit a Server row could set
  `proxy_jump="root@host; rm -rf /"` and get arbitrary command execution as
  the CertMgr service account on the CertMgr host itself — independent of the
  target server's own SSH auth. Found via this project's first-ever `bandit`
  run (no Python interpreter was available in the session that did the
  original 2026-08-12 security review). Fixed with strict validation enforced
  at both the API schema layer and again at point of use.
- Ran the full test suite + `ruff` + `bandit` against the 2026-08-13 security
  remediation for the first time (234 tests, later 255 after this release's
  additions) — confirms those fixes are real, not just manually reviewed.

### Fixed
- **Imported certificates always got `cert_type="imported"` regardless of
  their actual structure** — `import_certificate()` already parsed
  `is_wildcard`/`sans` correctly but hardcoded the type field anyway, so a
  wildcard or SAN certificate brought in via import looked identical to a
  single-domain one everywhere `cert_type` is used (the new Type column,
  the dashboard's certificates-by-type breakdown). Now derived from
  structure like issued certificates already were; the separate `imported`
  boolean still tracks provenance. Migration `b2e6f1a4c7d9` backfills
  existing rows.

### Added
- **`docs/migration.md`** — a full server-to-server migration runbook (master
  key, storage roots, certbot state, hook scripts, worker-as-root override,
  SSH credential config, CertMgr's own web-UI TLS cert, SELinux relabeling).
  Cross-linked from every other doc an operator planning a move would
  plausibly land on first.
- `deploy/server-setup-ol8.sh` / `deploy/server-setup.sh` now reuse an
  exported `CERTMGR_SECRETS_MASTER_KEY`/`CERTMGR_SECRET_KEY` instead of always
  generating fresh ones — previously, migrating to a new server via the
  normal setup script silently made every existing private key and secret
  permanently undecryptable.
- **Type column on the Certificates page** (Single / SAN / Wildcard /
  Internal / Imported), sortable — replaces the old ad-hoc "wildcard" chip
  under the domain, which couldn't distinguish SAN from single-domain certs.

---

## [1.3.0] — 2026-09-03 — Network TLS scanner

### Added
- **Network TLS certificate discovery** — scan IP ranges/hostnames/CIDRs
  across a port list (default 443, 8443, 636, 465, admin-configurable) and
  record whatever certificate each live endpoint presents over a real TLS
  handshake, regardless of trust (self-signed, expired, internal-CA
  certificates are found too — that's the point: surfacing certificates
  CertMgr didn't already know about, the actual "shadow cert" problem this
  complements the existing filesystem-path discovery for). A
  network-found certificate has no private key (impossible to extract from
  a live handshake), so it's read-only inventory
  (`status=discovered`) — visible, not renewable/deployable, unless
  separately imported.
- Certificate-rotation history: `network_certificate_sightings` records
  every host:port a certificate was seen at, append-only — an endpoint's
  certificate changing over time (self-signed → CA-issued, or a renewal)
  is preserved as history rather than silently overwritten, visible on
  each certificate's new "Seen on network" tab.
- Admin-only permission (`discovery:network_scan`) — stricter than
  filesystem discovery's `discovery:run` (granted to admin + certificate
  manager), since scanning arbitrary IP ranges touches infrastructure
  outside CertMgr's control and could be mistaken for unauthorized network
  reconnaissance by security monitoring.
- New Discovery page section (targets + ports input, pre-filled from the
  admin-configured default ports setting) alongside the existing
  filesystem-discovery UI; the runs table now shows a Filesystem/Network
  type badge.

---

## [1.4.0] — 2026-09-07 — Network scanner hardening + scheduling

Real production testing of the 1.3.0 network scanner on test05 surfaced
several bugs, all now fixed, plus the scheduling capability it launched
without.

### Fixed
- Scan log said "No certificates found." even when certificates were found
  but unchanged since the last scan (the common rescan case, deliberately
  silent to avoid log noise) — now distinguishes "found nothing" from
  "found N, all already known."
- `revoke_certificate()` had no guard for certificates with no registered
  provider (e.g. `provider_name="imported"` or `"network-scan"`) — an
  unhandled `KeyError` from the provider registry crashed with a 500 instead
  of a clean error. Not unique to network-scan certs; any manually-imported
  certificate had the same latent risk.
- `delete_certificate()`'s deletability gate and its `DiscoveryIgnore`-write
  both checked `cert.imported`, which network-scan certificates never set —
  they could not be deleted at all despite the function's own docstring
  saying discovered certificates should be. Now keys off
  `managed_by_platform`. `run_network_scan()` also now consults
  `DiscoveryIgnore` before creating a certificate, so a deleted
  network-found certificate stays deleted instead of reappearing on the
  next scan.
- Network-found certificates got a fixed `status="discovered"` that
  nothing ever revisited — unlike platform-managed certificates, whose
  status refreshes on every renewal attempt, these never go through
  issue/renew (no private key, `auto_renew` always `False`), so a
  certificate discovered today and expired next month showed "discovered"
  forever. Status is now computed from the actual validity window
  (active/expiring/expired) both at creation and on every rescan.
- Audit log's Resource column only ever showed `certificate:77` — the
  identifying detail (domain, hostname, etc.) was already recorded in the
  `details` JSON blob but required expanding it to see; now shown inline,
  picking whichever human-readable field is present since different
  action types populate different keys. Also fixed the column stretching
  to fill the page (an HTML table sizes a column to its widest cell across
  every row, so one long `details` value elsewhere in the list widened it
  for all rows) with a truncate + tooltip, matching the Certificates page's
  existing pattern for long text cells.

### Added
- Automatic weekly network scans via Celery beat
  (`CERTMGR_NETWORK_SCAN_CRON`, default Sunday 03:00 UTC) — opt-in via the
  new `tls_scan.scheduled_targets` setting (empty by default; the scheduled
  run is a no-op until targets are configured, deliberately not scanning
  anything until an admin has explicitly reviewed and enabled it). Also
  wired into the single-node `scheduled_jobs` mechanism
  (`job_type: "network_scan"`) for non-beat deployments.

---

## [1.5.0] — 2026-09-07 — Certificate Transparency monitoring

### Added
- **Certificate Transparency (CT) monitoring** — queries crt.sh (free, public,
  no API key) for admin-configured domains and surfaces certificates issued
  for them, including ones never deployed anywhere (a mis-issued/rogue
  certificate from an unexpected CA). Complements the network scanner: that
  one finds what's actually *reachable*; this finds what's been *issued*.
  Detections: new certificate, unknown CA (against a configurable expected-
  issuer list), sensitive hostname, staging/test hostname — each with a
  deterministic, explained risk score (0–100, informational/low/medium/high/
  critical). Lookalike/typosquat detection is deliberately not included: a
  crt.sh substring search on your own domain can never surface a lookalike
  like `examp1e.com` in the first place, so it doesn't fit this ingestion
  method — would need a separate technique entirely.
- **Findings** — the first lifecycle-bearing security record in CertMgr
  (compliance reports and health checks are both point-in-time logs with no
  acknowledge/resolve capability). A CT finding starts `open` and moves
  through `acknowledged`/`investigating` to `false_positive`/`resolved`; a
  rescan of an already-open finding refreshes its evidence without
  reopening work an analyst is already engaged with. New Findings page,
  plus a "CT Findings" tab on the certificate detail page.
- Automatic daily CT scans via Celery beat (`CERTMGR_CT_MONITOR_CRON`,
  default 04:00 UTC — daily, not weekly like the network scanner, since
  this only calls a public read-only aggregator, none of the "looks like
  reconnaissance" concern that justified the network scanner's more
  conservative cadence). Opt-in via `ct_monitoring.domains`, empty by
  default. Also wired into the single-node `scheduled_jobs` mechanism.
- Admin-only permission (`discovery:ct_monitor`) for triggering scans;
  `finding:view`/`finding:manage` for the findings lifecycle (view granted
  broadly, manage to admin + certificate manager).

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
