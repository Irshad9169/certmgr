# Security Architecture & Hardening

## Threat model

| Threat | Mitigation |
|---|---|
| Command injection via domains/hooks | argv-list execution (`shell=False` everywhere), per-argument metacharacter validation, domain/email/path schema validation, hook paths must be absolute + executable |
| Private key exfiltration | Keys encrypted at rest (Fernet, master key from env/file/Vault); never in PostgreSQL; downloads gated by `certificate:download_key` permission + audited; log redaction |
| Credential theft | Encrypted secrets at rest, API tokens hashed (SHA-256), refresh-token rotation + revocation, lockout after failed logins |
| Unauthorized access | JWT (HS256, issuer, expiry, type), RBAC permission matrix, TOTP MFA, secure cookies, rate limiting |
| CSRF | Double-submit cookie pattern for cookie-authenticated state-changing requests; bearer-token APIs exempt (not CSRF-able) |
| XSS | CSP `frame-ancestors 'none'`, no inline scripts in production builds, React default escaping, `X-Content-Type-Options: nosniff` |
| Path traversal / unsafe uploads | Upload size limits, extension + content sniffing, storage path jail (`resolve_within_root`), safe filenames |
| Remote server compromise via command center | Allowlist-only commands, service name allowlist, no free-form shell |
| Supply chain | Pinned dependencies, CI dependency scan (Trivy on images), non-root container user, read-only root FS |
| Secrets in logs | Redaction filter applied at the logging boundary (private keys, passwords, tokens, JWT regex) |

## Master key management

- `CERTMGR_SECRETS_MASTER_KEY` (env) **or** `CERTMGR_SECRETS_ENCRYPTION_FILE` (key
  file, preferred for container secrets) — production refuses to boot without one.
- Optional HashiCorp Vault (`CERTMGR_VAULT_ENABLED=1`) provides a KV backend for
  runtime secret retrieval; env remains the fallback.
- Rotation is an offline procedure (see installation guide) — plan for it.
- Moving to a **new server** is not rotation — the existing key must be carried
  over unchanged or all existing encrypted data becomes permanently
  undecryptable. See [migration.md](migration.md).

## RBAC permission matrix (seed)

```
administrator        → all
certificate_manager  → certificate:view,issue,renew,revoke,import,export,download_key,
                       deploy,edit,bulk · server:view,deploy · hook:view ·
                       notification:view · discovery:run,view · health:view
operator             → certificate:view,issue,renew,import,export,deploy ·
                       server:view,deploy · hook:view · notification:view ·
                       discovery:view · health:view
read_only            → certificate:view · server:view · hook:view ·
                       notification:view · audit:view · discovery:view · health:view
```

## Command execution policy

- `subprocess.run(argv, shell=False, capture_output=True)` is the ONLY execution
  primitive (`app/services/command.py`).
- Every argv element passes `assert_safe_argument` (rejects `; & | ` $ < > ( ) { }
  [ ] * ? ~ ! " ' \` newline/tab/space`).
- Script paths must be absolute, exist, and (for hooks) be executable.
- Remote commands (SSH) are restricted to an allowlist (`server_service`).

## HTTPS / headers

- Nginx terminates TLS (TLSv1.2+), HSTS, CSP, frame/sniffing/referrer headers.
- API enforces the same via middleware so direct exposure is also hardened.
- `Secure`/`SameSite` cookie flags; CSRF cookie is not HttpOnly by design
  (double-submit requires JS access) — pair with the CSP.

## Audit

Every sensitive action (login, issue, renew, revoke, deploy, download, import,
config change, user management, remote command) writes an `audit_logs` row with
user, IP, user-agent/browser/device, result, duration and sanitized details.
Downloading a private key is always audited with the format used.

## Security checklist before production

- [ ] `CERTMGR_SECRET_KEY` and `CERTMGR_SECRETS_MASTER_KEY` are unique, strong, rotated
- [ ] `CERTMGR_COOKIE_SECURE=true`, HSTS enabled in nginx
- [ ] TLS 1.2+ only; platform certificate issued via CertMgr itself
- [ ] Bootstrap admin password changed; MFA enabled for administrators
- [ ] SMTP/Teams/Slack webhook secrets configured via settings (masked)
- [ ] Rate limiting enabled; `CERTMGR_METRICS_AUTH_TOKEN` set if /metrics is public
- [ ] Backups enabled + restore drill performed
- [ ] Bandit/Trivy clean in CI; dependency pins reviewed
- [ ] File permissions: storage dirs `0700`, keys `0600`
