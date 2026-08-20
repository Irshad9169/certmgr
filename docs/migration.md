# Migrating an existing installation to a new server

This is for moving a **live, data-bearing** CertMgr install to new hardware —
different from a fresh install (`docs/installation.md`) and different from
swapping database engines on the same server (`docs/migration-mariadb-to-postgres.md`,
which this doc complements rather than replaces if you're doing both at once).

Schema/bootstrap isn't the hard part — `alembic upgrade head` recreates the
whole schema on an empty database, and role/settings/admin-account seeding
happens automatically on first API boot. The hard part is the state that
lives **outside** the database and isn't carried by any existing tooling.
Miss any of the items below and the symptom ranges from "have to log back in"
(harmless) to "every existing private key is now permanently unreadable"
(not recoverable) — read the whole checklist before starting, not just the
steps.

## Pre-migration checklist — gather all of this from the OLD server first

| # | Item | Where it lives | Why it matters |
|---|---|---|---|
| 1 | **`CERTMGR_SECRETS_MASTER_KEY`** | `/etc/certmgr/certmgr.env` (bare metal) or `.env` (Docker) | Encrypts every private key and every encrypted setting/secret already in the database and certificate storage. **If the new server generates a different one, all of that becomes permanently undecryptable — not just hard to recover, cryptographically gone.** This is the one item on this list that has no recovery path if missed. |
| 2 | `CERTMGR_SECRET_KEY` | same env file | JWT signing key. Losing this just logs everyone out — annoying, not destructive — but worth carrying over for a clean cutover. |
| 3 | **Certificate/key storage** (`CERTMGR_STORAGE_ROOT`, default `/var/lib/certmgr/certificates`) | on-disk directory tree, one folder per SHA-256 fingerprint | Every issued/imported certificate's encrypted private key and cert material. Copy byte-for-byte (`rsync -a` or tar) — decrypting it later depends on item 1 being correct. |
| 4 | Backup archive history (`CERTMGR_BACKUP_ROOT`, default `/var/lib/certmgr/backups`) | on-disk | Optional — only needed if you want prior backup archives to remain restorable on the new host. |
| 5 | **Certbot's own state** (`CERTMGR_CERTBOT_WORKDIR`, default `/etc/letsencrypt`) | on-disk | Let's Encrypt account registration + renewal config. Without this, existing certs still work, but their next renewal effectively starts fresh instead of continuing cleanly. |
| 6 | **Hook scripts** (auth/cleanup, referenced by `Hook` rows) | wherever an admin originally placed them — not tracked by the app or this repo | If these live outside the directories you're already copying, find and copy them separately. Losing them breaks any `manual-http`/`manual-dns`/`custom` validation issuance until replaced. |
| 7 | **"Worker as root" override**, if applied (`docs/administration.md#running-the-worker-as-root-for-root-only-hook-scripts`) | hand-edited into the *deployed* `/etc/systemd/system/certmgr-worker.service` — never written back to the repo template | Check `systemctl cat certmgr-worker \| grep -E 'User=\|Group=\|ProtectHome='` on the old server. If it shows `User=root`, the new server needs the same override reapplied manually — nothing detects or warns if you forget this, issuance for root-only hooks just starts failing. |
| 8 | **Hooks SSH-credential `~/.ssh/config` `Include` line**, if used (`docs/administration.md#ssh-credentials-for-hook-scripts-jenkins-credential-style`) | hand-edited into the worker account's `~/.ssh/config` on the old server | Same category as #7 — a manual one-time step with no tooling tracking whether it was done. The encrypted key itself is already covered by #1/#3 (it's in the DB), but this config line is not. |
| 9 | The full env file itself, for DB connection details you're keeping, cron schedules, retention settings, etc. | `/etc/certmgr/certmgr.env` or `.env` | Faster to carry the whole file forward and adjust host-specific bits (see step 3) than to reconstruct it from `.env.example` defaults. **Note:** SMTP/Slack/Teams/webhook/GoDaddy credentials configured via the Settings UI are stored encrypted in the *database*, not this file — they migrate automatically with item 1 + the DB dump and don't need separate handling here. |
| 10 | **Env-only secrets with no database counterpart**: `CERTMGR_AI_API_KEY`, `CERTMGR_VAULT_TOKEN`/`VAULT_ROLE_ID`/`VAULT_SECRET_ID`, `CERTMGR_LDAP_BIND_PASSWORD`, `CERTMGR_OIDC_CLIENT_SECRET`, and the `CERTMGR_SMTP_*` fallback values (used only when a notification channel hasn't overridden them in Settings) | `/etc/certmgr/certmgr.env` or `.env` | Unlike item 9's DB-backed settings, these genuinely only exist in the env file — carrying the file forward (item 9) covers them, but call them out explicitly since they're easy to assume are "in the database like everything else." |
| 11 | **CertMgr's own web UI TLS certificate** (nginx `server_name`/`ssl_certificate`, under `/etc/letsencrypt/live/<old-domain>/`) | on-disk, hostname-bound | This is the cert nginx presents for the CertMgr UI itself — unrelated to certificates CertMgr *manages*. It's issued for the old server's domain; copying `/etc/letsencrypt` verbatim (item 5) carries over a cert that won't match the new server's `server_name`. Regenerate (self-signed, same as a fresh install) or reissue for the new hostname — don't rely on the copied one. |

If you don't already know whether items 7/8 apply to your install, check now,
on the **old** server, before it's decommissioned:
```
systemctl cat certmgr-worker | grep -E 'User=|Group=|ProtectHome='
cat ~root/.ssh/config 2>/dev/null   # or the worker account's home, if not root
```

## Procedure

### 1. Snapshot the old server
```
certmgr backup                              # certificate material + DB dump, see docs/administration.md
tar czf certmgr-storage.tar.gz -C / var/lib/certmgr/certificates
tar czf certmgr-letsencrypt.tar.gz -C / etc/letsencrypt
cp /var/lib/certmgr/celerybeat-schedule ./celerybeat-schedule.old 2>/dev/null || true
cp /etc/certmgr/certmgr.env ./certmgr.env.old   # bare metal; or ./.env for Docker
```
Also locate and copy any hook scripts (item 6) if they're not already under a
path you're archiving above.

### 2. Provision the new server, but don't let it generate secrets yet
Run the normal setup script (`deploy/server-setup-ol8.sh` or
`deploy/server-setup.sh`), but first export the master key (and ideally the
JWT secret key) you captured in step 1 — both scripts now check for these and
reuse them instead of generating fresh ones:
```
export CERTMGR_SECRETS_MASTER_KEY="<value from the old certmgr.env>"
export CERTMGR_SECRET_KEY="<value from the old certmgr.env>"
sudo -E bash deploy/server-setup-ol8.sh    # -E preserves the exported vars under sudo
```
Confirm the script logged that it reused the provided master key rather than
generating one — the exact message differs by path:
- `server-setup-ol8.sh`: `reusing provided CERTMGR_SECRETS_MASTER_KEY (migration mode)`
- `server-setup.sh` (Docker): `written with your provided master key (migration mode)`

If instead you see `secrets generated` / `Secrets written to ... (keep this
file safe!)` (no "migration mode" mention), **stop** — it means a new key was
generated and the migration would result in permanently undecryptable data
once you copy the old database/storage over. Re-check that
`CERTMGR_SECRETS_MASTER_KEY` was actually exported in the shell the script ran
in (`sudo -E`, not plain `sudo`) before re-running.

### 3. Reconcile the rest of the env file
Diff the new host's generated env file against the one you saved in step 1.
Carry over the genuinely env-only secrets (checklist item 10 — AI/Vault/LDAP/
OIDC/SMTP-fallback) and any custom retention/cron settings — SMTP/Slack/Teams/
webhook/GoDaddy credentials set via the Settings UI do **not** need this step,
they migrate with the database dump (item 9's note). Update anything
genuinely host-specific: `CERTMGR_DATABASE_URL`/`CERTMGR_REDIS_URL` if the
DB/Redis host changed, `CERTMGR_CORS_ORIGINS`/nginx `server_name` if the
domain changed, and any firewall/MariaDB grant that was scoped to the old
server's IP. Leave the freshly-generated nginx self-signed cert in place
(item 11) — don't overwrite it with the old server's copied one.

### 4. Restore data
```
# Database: restore the dump from step 1's `certmgr backup` (or via your DB's
# own restore tooling if moving between major versions — see
# docs/migration-mariadb-to-postgres.md for a DB-engine swap specifically)

# Certificate storage — must land at the same CERTMGR_STORAGE_ROOT path
# configured in the new env file
tar xzf certmgr-storage.tar.gz -C /
chown -R <app_user>:<app_user> /var/lib/certmgr/certificates

# Certbot state — do NOT let this overwrite the new host's own nginx TLS cert
# under /etc/letsencrypt/live/<new-domain>/ (item 11); restore into a scratch
# path and copy back only the account/renewal-config directories you need.
tar xzf certmgr-letsencrypt.tar.gz -C /

# Celery beat bookkeeping (optional — safe to skip, tasks just re-fire fresh)
cp ./celerybeat-schedule.old /var/lib/certmgr/celerybeat-schedule 2>/dev/null || true

# OL8 with SELinux enforcing: re-label everything restored above, since tar/
# rsync don't preserve SELinux contexts by default
sudo restorecon -R /var/lib/certmgr /etc/letsencrypt
```

### 5. Reapply the manual, untracked pieces (checklist items 6–8)
- Copy hook scripts to the same paths the `Hook` rows in the migrated
  database reference (or update the rows if paths changed).
- If the old server had the worker-as-root override applied, hand-edit the
  **deployed** `/etc/systemd/system/certmgr-worker.service` on the new host
  the same way — see `docs/administration.md`. `daemon-reload` + restart
  after.
- If the old server had the Hooks SSH-credential `Include` line, add the
  matching line to the new worker account's `~/.ssh/config`.

### 6. Run migrations and start services
```
cd /opt/certmgr/backend && source .venv/bin/activate
alembic upgrade head
sudo systemctl restart certmgr-api certmgr-worker certmgr-beat
```

## Verification

- `curl -fsS http://127.0.0.1:8000/health/ready` → `{"status":"ready"}`.
- Log in as an existing user with their **old** password — if this fails
  with an internal error (not just "wrong password"), the master key almost
  certainly doesn't match; stop and investigate before doing anything else.
- Open an existing certificate's detail page and confirm its private key can
  still be downloaded/exported — this is the definitive test that the master
  key carried over correctly.
- If the worker-as-root override applies, trigger one real issuance that
  exercises the SSH-based hook path end to end.
- Run `certmgr inventory` (or the Certificates page) and spot-check counts
  against the old server.

## Rollback

Keep the old server intact and powered on (not decommissioned) until the new
one is fully verified — the fastest rollback is just pointing DNS/traffic
back at the old host. Don't delete `certmgr-storage.tar.gz` or the DB dump
until you've confirmed certificates can be decrypted and downloaded on the
new server.
