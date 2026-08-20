# Migrating from MariaDB to PostgreSQL

CertMgr supports both, so this is a data move — no code changes. The database
holds **metadata only**; private keys stay as encrypted files under
`CERTMGR_STORAGE_ROOT`, so they are untouched by the migration.

> Swapping the database engine **on the same server** (the pgloader path
> below): no extra steps needed. Also moving to **new hardware** at the same
> time (the "restore from backup archives" path, or relocating
> `CERTMGR_STORAGE_ROOT`): `CERTMGR_SECRETS_MASTER_KEY` must be carried over
> to the new host unchanged, or every existing private key/secret becomes
> permanently undecryptable — see [migration.md](migration.md).

## Recommended: pgloader (automated, preserves everything)

[pgloader](https://pgloader.io/) converts MariaDB → PostgreSQL directly,
including JSON columns and quoting the reserved `key` column.

```bash
# 1. Install pgloader (on a host with network access to both DBs)
sudo dnf install -y epel-release && sudo dnf install -y pgloader

# 2. Create the Postgres target
sudo -u postgres psql -c "CREATE USER certmgr WITH PASSWORD '<new-password>';"
sudo -u postgres createdb -O certmgr certmgr

# 3. Migrate (MariaDB → Postgres)
pgloader \
  mysql://certmgr:<mariadb-password>@127.0.0.1:3306/certmgr \
  postgresql://certmgr:<new-password>@127.0.0.1:5432/certmgr

# 4. Point the app at Postgres and restart
#    edit /etc/certmgr/certmgr.env:
#      CERTMGR_DATABASE_URL=postgresql+psycopg://certmgr:<new-password>@127.0.0.1:5432/certmgr
sudo systemctl restart certmgr-api certmgr-worker certmgr-beat

# 5. Verify
curl -fsS http://127.0.0.1/health/ready && echo OK
```

Notes:
- `pgloader` maps `MEDIUMTEXT → TEXT`, `JSON → JSONB` automatically. The
  `certificates`/`users`/`roles` rows and all history carry over.
- Run `alembic upgrade head` after the move — the MEDIUMTEXT migration is a
  no-op on PostgreSQL, and any future migrations apply normally.
- The file store (`CERTMGR_STORAGE_ROOT`) must be readable by the app on the
  new host — copy the directory or mount it; DB paths point at it.

## Alternative: restore from backup archives

If pgloader isn't an option, the material is safe either way:

1. **Before migrating**, on MariaDB run: `certmgr backup` (archives every
   certificate's material + a DB dump) — store the archives off-server.
2. Install the fresh Postgres deployment, start it empty.
3. Restore each certificate from its archive:
   `certmgr restore --backup <archive>` (matches by fingerprint; creates new
   rows). Certificate material, keys (still encrypted) and validity are fully
   restored.
4. Re-enter operational metadata you care about (tags, owners, environment
   labels) — pgloader preserves these, this fallback path re-imports the
   certificate material fresh.

## Rollback

Keep the MariaDB instance running until the Postgres setup is verified; the app
can switch back by editing `CERTMGR_DATABASE_URL` and restarting services.
