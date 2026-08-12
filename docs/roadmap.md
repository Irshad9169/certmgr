# Roadmap & Delivery Phases

## Phase 1 — Backend platform ✅ (this repository, current state)

- Full REST API, RBAC, JWT + refresh + API tokens + TOTP MFA
- Certificate lifecycle: issue/renew/revoke/import/clone/bulk with real Certbot
  execution and OpenSSL internal CA provider
- Encrypted key storage, x.509 metadata engine, PFX support
- Deployment engine (SFTP/SCP/rsync, templates, backup/verify/rollback)
- Server inventory, restricted command center, service control
- Discovery, health monitoring, compliance engine
- Notifications (SMTP/Slack/Teams/webhook) + signed outbound webhooks
- Audit log, Celery workers + beat, APScheduler in-process mode
- Reports (CSV/XLSX/PDF/JSON), CLI, Prometheus/Grafana
- Docker images, Compose, nginx, systemd units, GitHub Actions CI/CD
- 110 unit/integration/API tests; full documentation set

## Phase 2 — Frontend SPA (next)

- React 18 + TypeScript + Vite + Tailwind + Material UI
- Dark/light enterprise theme, responsive layout, toast + confirm + progress
- Pages: Login/MFA, Dashboard (charts), Certificate inventory, 7-step Issue wizard
  with live Certbot console, Import, Details (tabs + downloads), Servers +
  Command Center, Deployments + templates, Discovery, Hooks, Notifications,
  Audit, Users, Settings, Maintenance, Compliance, Reports, AI assistant
- Role-aware UI from `/auth/me` permissions

## Phase 3 — Enterprise extensions

- **SSO**: LDAP/AD, OpenID Connect, OAuth2, SAML (python3-saml), enforced MFA
- **Secrets**: full HashiCorp Vault integration, CyberArk AIM
- **Storage**: S3-compatible object store backend for certificate material
- **Additional CA plugins**: DigiCert, GoDaddy, Sectigo, GlobalSign, Entrust,
  Microsoft ADCS (via provider entry points)
- **Web terminal**: live SSH WebSocket session (allowlist-constrained)
- **E2E tests** (Playwright) against the docker-compose stack
- **Multi-tenancy / folders** for large enterprises, approval workflows,
  certificate usage analytics

## Contributing conventions

- Services contain business logic; routers stay thin; schemas validate at the edge.
- Every command executed via `app/services/command.py` (argv, no shell).
- Never log secrets; never store key material in the DB.
- New features ship with tests + audit coverage.
