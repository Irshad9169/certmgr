# Database Schema (ER)

35 tables. ER diagram:

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
certificates 1───* notifications (related_certificate_id)
certificates 1───* network_certificate_sightings
certificates 1───* ct_observations, 1───* ct_findings
certificates 1───* certificate_usage_scans 1───* certificate_usage_results
certificate_usage_results *───1 certificates (presented_certificate_id, nullable)
servers *───* tags (server_tags)
servers 1───* deployments
deployment_templates 1───* deployments
webhook_endpoints 1───* webhook_deliveries
providers (CA registry config, encrypted)
hooks (auth/cleanup/pre-post-deploy scripts)
job_executions (every certbot/deploy/import run)
discovery_runs (filesystem/network/ct_log scan_type), discovery_ignores, scheduled_jobs
app_settings (key/value, secrets encrypted), maintenance_windows
compliance_reports
```

## Key tables

| Table | Purpose | Notable columns |
|---|---|---|
| `users` | Accounts | username, email, hashed_password, role_id, mfa_secret_encrypted, failed_login_attempts, locked_until |
| `roles` | RBAC | name, permissions (JSON code list) |
| `api_tokens` | PATs | token_hash (SHA-256), prefix, scopes, expires_at, revoked_at |
| `refresh_tokens` | Rotation/revocation | jti, token_hash, expires_at, revoked_at, ip, user_agent |
| `certificates` | **Inventory core** | domain, sans (JSON), cert_type, provider_name, validation_method, key_type, key_size, signature_algorithm, fingerprint_sha256, serial_number, issuer, subject, valid_from/until, status, environment, auto_renew, renewal_status, cert_path/key_path/chain_path/fullchain_path/pfx_path (**paths only — never key material**), health_score, compliance_status, owner_id |
| `certificate_domains` | Per-domain rows | domain, is_primary, is_wildcard, validation_status |
| `providers` | CA plugins | name, provider_type (registry key), config_encrypted, is_default |
| `hooks` | Scripts | script_path, env_vars (JSON), execution_user, working_directory, timeout_seconds |
| `servers` | Remote inventory | hostname, ip, environment, ssh_port, auth_method, ssh_password_encrypted, ssh_key_path, proxy_jump, web_server_type, connection_status |
| `deployment_templates` | Reusable scripts | target_type, pre_deploy/deploy/backup/post_deploy scripts, reload_command, variables (JSON) |
| `deployments` | Deployment runs | certificate_id, server_id, method, status, backup_path, verification (JSON), error |
| `job_executions` | Every operation | job_type, certificate_id, status, exit_code, stdout/stderr (bounded), execution_time_ms, trigger, retry_count |
| `notifications` | Queue | event_type, channel, recipients (JSON), status, retries |
| `notification_settings` | Channels | channel, config_encrypted, events (JSON), enabled |
| `webhook_endpoints` / `webhook_deliveries` | Outbound events | secret_encrypted, events, response_code, error |
| `audit_logs` | Immutable trail | action, username, resource, result, ip, browser, device, duration_ms, details (JSON) |
| `app_settings` | Admin config | key, value, is_secret (encrypted) |
| `maintenance_windows` | Maintenance mode | pause_renewals/deployments/notifications/imports/background_jobs, scheduled_end |
| `backups` | Restore points | kind, storage_path, size_bytes, checksum_sha256 |
| `compliance_reports` | Compliance runs | report_type, summary (JSON), file_path |
| `scheduled_jobs` | User schedules | schedule_type, cron_expression, interval_seconds, config |
| `certificate_health_checks` | Health history | status, score, checks (JSON) |
| `discovery_ignores` | "Stay deleted" list | fingerprint_sha256 (unique), domain, source_path — every discovery mechanism (filesystem, network scan, CT monitor) skips a fingerprint recorded here |
| `network_certificate_sightings` | Network-scan history | fingerprint_sha256, certificate_id, host, port, sni_hostname (unused — never populated), first/last_seen_at — append-only, a certificate rotation at the same host:port inserts a new row rather than overwriting |
| `ct_observations` | CT log entries seen | certificate_id, crt_sh_id (unique — an immutable crt.sh record), matched_domain, first/last_seen_at |
| `ct_findings` | CT security findings | certificate_id, domain, match_type, detections (JSON), risk_score, severity, status (open→acknowledged/investigating→false_positive/resolved) — the first lifecycle-bearing finding model, unlike the point-in-time compliance_reports/certificate_health_checks logs |
| `certificate_usage_scans` | Usage-discovery runs | certificate_id, status, sources (JSON), candidate/scanned/confirmed/different_certificate/unreachable/error counts |
| `certificate_usage_results` | Usage-discovery results | certificate_id, hostname, ip_address, port (unique together), status, expected/presented_fingerprint, presented_certificate_id (nullable — links a `different_certificate` result to another tracked certificate), first_seen_at (preserved across rescans), last_seen_at/last_checked_at |

## Design decisions

- **Integer PKs** (fast, simple with thousands of rows; indexed lookups everywhere).
- **JSON columns** for SANs/tags/checks/config — PostgreSQL `jsonb` compatible
  (SQLAlchemy `JSON`); cross-DB with SQLite for local dev/tests.
- **Enums** stored as strings with application-level validation (portable,
  avoids Postgres enum migration pain).
- **No private-key material ever in the DB** — encrypted file paths only; the
  `FileStore` keeps keys Fernet-encrypted at rest.
- Migrations via Alembic (`alembic upgrade head`); the initial migration covers
  the original 30 tables, with each feature added since (network scanning, CT
  monitoring, usage discovery) as its own incremental revision, written by
  hand rather than via `alembic revision --autogenerate`. Always test
  upgrade → downgrade → upgrade against a scratch SQLite DB before committing
  a new one.
