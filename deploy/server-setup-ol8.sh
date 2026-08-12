#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  CertMgr — Oracle Linux 8 bare-metal setup (no Docker)
# ═══════════════════════════════════════════════════════════════════════════
#
#  Run as root on a fresh Oracle Linux 8 server:
#      sudo bash deploy/server-setup-ol8.sh
#
#  What it does (each step prints what's happening):
#    1. Installs system prerequisites (EPEL, build tools, certbot, rsync)
#    2. Sets up the database:
#         DB_ENGINE=postgres        → installs PostgreSQL 16 (PGDG repo), creates DB/user
#         DB_ENGINE=mariadb         → installs MariaDB (AppStream), creates DB/user
#         DB_ENGINE=external-mariadb→ uses an EXISTING MariaDB (no install).
#                                     Prompts for the admin password, then creates
#                                     the certmgr DB + user. Zero extra disk.
#         CERTMGR_DATABASE_URL set  → skips DB setup entirely, uses your URL
#                                     (e.g. an already-prepared database)
#    3. Installs Redis 7 (remi) — falls back to AppStream Redis 6.2 if needed
#    4. Installs Python 3.13 (builds from source if the distro lacks it)
#    5. Sets up the app: venv, pip deps, /etc/certmgr/certmgr.env secrets,
#       storage dirs, database migrations (alembic)
#    6. Installs nginx, generates a self-signed cert for your domain, and
#       writes the reverse-proxy config (UI + /api)
#    7. Installs + starts systemd units: certmgr-api, certmgr-worker,
#       certmgr-beat (+ backup / backup-verify / retention timers)
#    8. Applies SELinux/firewall policy so nginx can proxy and ports 80/443
#       are open
#    9. Prints the bootstrap admin password and next steps
#
#  Idempotent: safe to re-run; existing secrets / DB / services are preserved.
#
#  External-MariaDB mode env overrides (for non-interactive automation):
#     MYSQL_HOST=127.0.0.1  MYSQL_PORT=3306  MYSQL_ADMIN_USER=root
#     MYSQL_ADMIN_PASSWORD=<password>        CERTMGR_DB_PASSWORD=<app pw>
#  (without MYSQL_ADMIN_PASSWORD the script prompts interactively)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration (override via env) ───────────────────────────────────────
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # where the bundle is
DOMAIN="${CERTMGR_DOMAIN:-certmgr.example.com}"
ADMIN_EMAIL="${CERTMGR_EMAIL:-ssl-admin@example.com}"
DB_ENGINE="${DB_ENGINE:-postgres}"   # postgres | mariadb | external-mariadb
PY_VERSION="${PY_VERSION:-3.13.0}"
APP_USER="${APP_USER:-certmgr}"     # OS user the services run as (e.g. APP_USER=secauto)
ENV_FILE="/etc/certmgr/certmgr.env"
STORAGE_ROOT="${CERTMGR_STORAGE_ROOT:-/var/lib/certmgr}"

# External-MariaDB options
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_ADMIN_USER="${MYSQL_ADMIN_USER:-root}"
MYSQL_ADMIN_PASSWORD="${MYSQL_ADMIN_PASSWORD:-}"
DB_LABEL=""

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root: sudo bash $0"; exit 1
fi
if ! grep -qE 'EL8|ol8|release 8\.' /etc/oracle-release /etc/os-release 2>/dev/null; then
  echo "WARNING: this script targets Oracle Linux 8; continuing anyway (EL8/RHEL8 compatible)."
fi
if [[ -z "${CERTMGR_DATABASE_URL:-}" ]] \
   && [[ "$DB_ENGINE" != "postgres" && "$DB_ENGINE" != "mariadb" && "$DB_ENGINE" != "external-mariadb" ]]; then
  echo "ERROR: DB_ENGINE must be postgres, mariadb or external-mariadb (or set CERTMGR_DATABASE_URL)"; exit 1
fi

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '    \033[32m✓\033[0m %s\n' "$*"; }

# ── 1. Prerequisites ────────────────────────────────────────────────────────
say "1/9  Installing prerequisites (EPEL, build tools, certbot, rsync, nginx)"
dnf install -y -q epel-release
dnf install -y -q dnf-utils gcc make openssl-devel bzip2-devel libffi-devel \
               zlib-devel readline-devel certbot rsync nginx openssl \
               || { echo "WARNING: some packages failed (offline repo?) — continuing"; }
ok "prerequisites installed"

# ── 2. Database ─────────────────────────────────────────────────────────────
setup_database() {
  # Mode A: operator provided a complete URL — use it as-is (no DB install)
  if [[ -n "${CERTMGR_DATABASE_URL:-}" ]]; then
    say "2/9  Using provided CERTMGR_DATABASE_URL (skipping database install)"
    DATABASE_URL="$CERTMGR_DATABASE_URL"
    case "$DATABASE_URL" in
      postgresql*) PGDUMP_BIN="${CERTMGR_PG_DUMP_BINARY:-$(command -v pg_dump || echo /usr/bin/pg_dump)}" ;;
      mysql*|mariadb*) MYSQLDUMP_BIN="${CERTMGR_MYSQLDUMP_BINARY:-$(command -v mysqldump || echo /usr/bin/mysqldump)}" ;;
    esac
    DB_LABEL="Provided URL (${DATABASE_URL%%:*})"
    ok "using external database URL: ${DATABASE_URL%%://*}://…"
    return
  fi

  case "$DB_ENGINE" in
    postgres)
      say "2/9  Installing PostgreSQL 16 (PGDG repo)"
      dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
      dnf -qy module disable postgresql || true
      dnf install -y -q postgresql16-server postgresql16
      PGBIN=/usr/pgsql-16/bin
      if [[ ! -d /var/lib/pgsql/16/data/base ]]; then
        $PGBIN/postgresql-16-setup initdb
      fi
      systemctl enable --now postgresql-16
      ok "PostgreSQL 16 running"

      # Create app user + database (idempotent)
      DB_PASSWORD="${CERTMGR_DB_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)}"
      su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='certmgr'\"" | grep -q 1 \
        || su - postgres -c "psql -c \"CREATE USER certmgr WITH PASSWORD '$DB_PASSWORD';\""
      su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='certmgr'\"" | grep -q 1 \
        || su - postgres -c "createdb -O certmgr certmgr"
      DATABASE_URL="postgresql+psycopg://certmgr:${DB_PASSWORD}@127.0.0.1:5432/certmgr"
      PGDUMP_BIN="$PGBIN/pg_dump"
      DB_LABEL="PostgreSQL 16 (installed)"
      ok "database 'certmgr' ready (postgresql)"
      ;;

    mariadb)
      say "2/9  Installing MariaDB 10.5+ (AppStream)"
      dnf install -y -q mariadb-server mariadb
      systemctl enable --now mariadb
      DB_PASSWORD="${CERTMGR_DB_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)}"
      mariadb -e "CREATE DATABASE IF NOT EXISTS certmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
      mariadb -e "CREATE USER IF NOT EXISTS 'certmgr'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';"
      mariadb -e "GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'127.0.0.1'; FLUSH PRIVILEGES;"
      DATABASE_URL="mysql+pymysql://certmgr:${DB_PASSWORD}@127.0.0.1:3306/certmgr"
      MYSQLDUMP_BIN="$(command -v mysqldump || echo /usr/bin/mysqldump)"
      DB_LABEL="MariaDB (installed)"
      ok "database 'certmgr' ready (mariadb)"
      ;;

    external-mariadb)
      say "2/9  Using EXISTING MariaDB at $MYSQL_HOST:$MYSQL_PORT (no DBMS install)"
      # MySQL client only (no server)
      if ! command -v mysql >/dev/null 2>&1; then
        dnf install -y -q mariadb
      fi
      # Admin credentials: env override or interactive prompt
      if [[ -z "$MYSQL_ADMIN_PASSWORD" ]]; then
        read -r -s -p "  MariaDB admin ($MYSQL_ADMIN_USER@$MYSQL_HOST) password: " MYSQL_ADMIN_PASSWORD || true
        echo
        if [[ -z "$MYSQL_ADMIN_PASSWORD" ]]; then
          echo "ERROR: no admin password provided (set MYSQL_ADMIN_PASSWORD for automation)"
          exit 1
        fi
      fi
      # Test connectivity (MYSQL_PWD avoids exposing the password on the CLI)
      if ! MYSQL_PWD="$MYSQL_ADMIN_PASSWORD" mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
            -u "$MYSQL_ADMIN_USER" -N -e "SELECT VERSION();" >/dev/null 2>&1; then
        echo "ERROR: cannot connect to MariaDB at $MYSQL_HOST:$MYSQL_PORT as $MYSQL_ADMIN_USER"
        exit 1
      fi
      ok "connected: MariaDB $(MYSQL_PWD="$MYSQL_ADMIN_PASSWORD" mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_ADMIN_USER" -N -e "SELECT VERSION();" 2>/dev/null)"

      # Create certmgr DB + user (idempotent)
      DB_PASSWORD="${CERTMGR_DB_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)}"
      MYSQL_PWD="$MYSQL_ADMIN_PASSWORD" mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_ADMIN_USER" <<SQL
CREATE DATABASE IF NOT EXISTS certmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'certmgr'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS 'certmgr'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS 'certmgr'@'$MYSQL_HOST' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'127.0.0.1';
GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'localhost';
GRANT ALL PRIVILEGES ON certmgr.* TO 'certmgr'@'$MYSQL_HOST';
FLUSH PRIVILEGES;
SQL
      DATABASE_URL="mysql+pymysql://certmgr:${DB_PASSWORD}@${MYSQL_HOST}:${MYSQL_PORT}/certmgr"
      MYSQLDUMP_BIN="${CERTMGR_MYSQLDUMP_BINARY:-$(command -v mysqldump || echo /usr/bin/mysqldump)}"
      DB_LABEL="Existing MariaDB ($MYSQL_HOST:$MYSQL_PORT)"
      ok "database 'certmgr' ready on existing MariaDB"
      ;;
  esac
}
setup_database

# ── 3. Redis ────────────────────────────────────────────────────────────────
say "3/9  Installing Redis (7 preferred, 6.2 fallback)"
if dnf -q module list redis 2>/dev/null | grep -q ':7'; then
  dnf -qy module reset redis && dnf -qy module enable redis:7 && dnf install -y -q redis
else
  # try remi repo for Redis 7
  dnf install -y -q https://rpms.remirepo.net/enterprise/remi-release-8.rpm 2>/dev/null || true
  if dnf -q module list redis 2>/dev/null | grep -q ':7'; then
    dnf -qy module reset redis && dnf -qy module enable redis:7 && dnf install -y -q redis
  else
    dnf install -y -q redis   # AppStream 6.2 — fully compatible with the app
    ok "note: Redis 6.2 (AppStream) installed; Redis 7 requires the remi repo"
  fi
fi
systemctl enable --now redis
ok "redis running on 127.0.0.1:6379"

# ── 4. Python (3.11+ — OL8 ships 3.11 in AppStream; 3.13 built only if needed) ─
say "4/9  Ensuring Python 3.11+"
# Preferred order: explicit override → python3.13 → python3.11 → python3
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for cand in python3.13 python3.11 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
      major_minor="$("$cand" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      if [[ "$major_minor" =~ ^(3\.(1[1-9]|[2-9][0-9]))$ ]]; then
        PYTHON_BIN="$(command -v "$cand")"
        ok "using $("$PYTHON_BIN" --version)"
        break
      fi
    fi
  done
fi
if [[ -z "$PYTHON_BIN" ]]; then
  say "     No Python 3.11+ found — building Python $PY_VERSION from source (takes a few minutes)"
  cd /tmp
  curl -fsSLO "https://www.python.org/ftp/python/${PY_VERSION}/Python-${PY_VERSION}.tgz"
  rm -rf "Python-${PY_VERSION}" && tar -xzf "Python-${PY_VERSION}.tgz" && cd "Python-${PY_VERSION}"
  ./configure --with-ensurepip=install --prefix=/usr/local
  make -j"$(nproc)"
  make altinstall
  PYTHON_BIN="$(command -v python3.13)"
fi
"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"' && ok "python $("$PYTHON_BIN" --version | awk '{print $2}') ready"

# ── 5. Application (venv, deps, env, storage, migrations) ───────────────────
say "5/9  Setting up the application"
# Create the service user tolerantly: some servers mount /home on NFS where
# useradd --create-home fails. Fall back to no home dir (home = storage root).
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  if ! useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER" 2>/dev/null; then
    echo "     (cannot create /home/$APP_USER — using $STORAGE_ROOT as home)"
    useradd --system -M -d "$STORAGE_ROOT" -s /usr/sbin/nologin "$APP_USER" \
      || { echo "ERROR: cannot create user $APP_USER"; exit 1; }
  fi
fi
mkdir -p "$STORAGE_ROOT"/{certificates,backups,tmp} /var/log/certmgr /etc/certmgr /etc/letsencrypt
chown -R "$APP_USER":"$APP_USER" "$STORAGE_ROOT" /var/log/certmgr /etc/letsencrypt

# App files must be readable by the service user
chown -R "$APP_USER":"$APP_USER" "$APP_DIR" 2>/dev/null || true

cd "$APP_DIR/backend"
if [[ ! -d .venv ]]; then
  "$PYTHON_BIN" -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi
ok "python venv (from $PYTHON_BIN) + dependencies ready"

# Environment file (idempotent — keeps existing secrets)
if [[ ! -f "$ENV_FILE" ]]; then
  say "     Writing secrets to $ENV_FILE"
  SECRET_KEY="$(openssl rand -hex 32)"
  MASTER_KEY="$(openssl rand -base64 40 | tr -d '/+=' | head -c 48)"
  cat > "$ENV_FILE" <<EOF
CERTMGR_ENVIRONMENT=production
CERTMGR_DATABASE_URL=$DATABASE_URL
CERTMGR_REDIS_URL=redis://127.0.0.1:6379/0
CERTMGR_SECRET_KEY=$SECRET_KEY
CERTMGR_SECRETS_MASTER_KEY=$MASTER_KEY
CERTMGR_STORAGE_ROOT=$STORAGE_ROOT/certificates
CERTMGR_BACKUP_ROOT=$STORAGE_ROOT/backups
CERTMGR_LOG_ROOT=/var/log/certmgr
CERTMGR_TEMP_WORKDIR=$STORAGE_ROOT/tmp
CERTMGR_CERTBOT_WORKDIR=/etc/letsencrypt
CERTMGR_DEFAULT_LETSENCRYPT_EMAIL=$ADMIN_EMAIL
CERTMGR_JSON_LOGGING=true
CERTMGR_LOG_LEVEL=INFO
CERTMGR_PROMETHEUS_ENABLED=true
CERTMGR_COOKIE_SECURE=true
CERTMGR_RATE_LIMIT_ENABLED=true
CERTMGR_CORS_ORIGINS=["https://$DOMAIN"]
CERTMGR_PG_DUMP_BINARY=${PGDUMP_BIN:-/usr/pgsql-16/bin/pg_dump}
CERTMGR_MYSQLDUMP_BINARY=${MYSQLDUMP_BIN:-/usr/bin/mysqldump}
CERTMGR_BACKUP_KEEP_DAYS=30
CERTMGR_BACKUP_CRON="0 1 * * *"
CERTMGR_EXECUTION_RETENTION_DAYS=365
CERTMGR_AUDIT_RETENTION_DAYS=730
CERTMGR_NOTIFICATION_RETENTION_DAYS=365
EOF
  chmod 600 "$ENV_FILE"
  ok "secrets generated — keep $ENV_FILE safe!"
else
  ok "existing $ENV_FILE preserved"
fi

# Database migrations
say "     Running database migrations (alembic upgrade head)"
set +u
if ! source "$ENV_FILE"; then
  echo "ERROR: cannot source $ENV_FILE (check quoting of values with spaces)"
  exit 1
fi
set -u
./.venv/bin/alembic upgrade head
ok "schema migrated"

# ── 6. nginx (reverse proxy + UI) ───────────────────────────────────────────
say "6/9  Configuring nginx for $DOMAIN"
# Self-signed cert so nginx can start; replace with a real cert (or issue one
# via CertMgr itself) later.
if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
  mkdir -p "/etc/letsencrypt/live/$DOMAIN"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
    -out "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" \
    -subj "/CN=$DOMAIN" 2>/dev/null
fi
chown -R "$APP_USER":"$APP_USER" /etc/letsencrypt

cat > /etc/nginx/conf.d/certmgr.conf <<EOF
upstream certmgr_api { server 127.0.0.1:8000; keepalive 32; }

server {
    listen 80;
    server_name $DOMAIN _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN _;
    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy same-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    root $APP_DIR/frontend/dist;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
    location /api/ {
        proxy_pass http://certmgr_api;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        client_max_body_size 15m;
    }
    location /docs { proxy_pass http://certmgr_api; }
    location /health { proxy_pass http://certmgr_api; }
    location /metrics { proxy_pass http://certmgr_api; }
}
EOF
rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/ssl.conf
nginx -t && systemctl enable --now nginx
ok "nginx configured (self-signed TLS until you add a real certificate)"

# ── 7. systemd units ────────────────────────────────────────────────────────
say "7/9  Installing systemd services (api / worker / beat / backup+verify / retention timers)"
for unit in certmgr-api certmgr-worker certmgr-beat certmgr-backup certmgr-backup-verify certmgr-retention; do
  sed -e "s|/opt/certmgr|$APP_DIR|g" \
      -e "s/^User=certmgr/User=$APP_USER/" \
      -e "s/^Group=certmgr/Group=$APP_USER/" \
      "$APP_DIR/deploy/systemd/$unit.service" > "/etc/systemd/system/$unit.service"
done
cp "$APP_DIR/deploy/systemd/certmgr-backup.timer" \
   "$APP_DIR/deploy/systemd/certmgr-backup-verify.timer" \
   "$APP_DIR/deploy/systemd/certmgr-retention.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now certmgr-api certmgr-worker certmgr-beat
systemctl enable --now certmgr-backup.timer certmgr-backup-verify.timer certmgr-retention.timer
# Run one backup + verification + retention now to validate the pipeline end-to-end
systemctl start certmgr-backup.service || echo "WARNING: initial backup failed — check: journalctl -u certmgr-backup -n 30"
systemctl start certmgr-backup-verify.service || echo "WARNING: initial backup verification failed — check: journalctl -u certmgr-backup-verify -n 30"
systemctl start certmgr-retention.service || echo "WARNING: initial retention failed — check: journalctl -u certmgr-retention -n 30"
sleep 2
systemctl is-active certmgr-api certmgr-worker certmgr-beat || true
systemctl list-timers certmgr-backup.timer certmgr-backup-verify.timer certmgr-retention.timer --no-pager | tail -3
ok "services started (check: systemctl status certmgr-api)"

# ── 8. SELinux + firewall ───────────────────────────────────────────────────
say "8/9  Applying SELinux / firewall policy"
if command -v setsebool >/dev/null 2>&1; then
  # nginx must be allowed to proxy to the backend on localhost
  setsebool -P httpd_can_network_connect 1 || true
  # If certificate storage is on NFS, also run: setsebool -P nfs_export_all_rw 1
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-service=http --add-service=https >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
ok "policy applied"

# ── 9. Summary ──────────────────────────────────────────────────────────────
say "9/9  Verifying health"
# Check the API directly (port 8000) and require the JSON "ready" body — a
# redirect or HTML page from nginx must NOT count as healthy.
API_OK=""
for _ in $(seq 1 12); do
  if curl -fsS "http://127.0.0.1:8000/health/ready" 2>/dev/null | grep -q '"ready"'; then
    API_OK="direct"
    break
  fi
  sleep 3
done
if [[ -z "$API_OK" ]] && curl -kfsS "https://127.0.0.1/health/ready" 2>/dev/null | grep -q '"ready"'; then
  API_OK="via-nginx-https"
fi
if [[ -n "$API_OK" ]]; then
  ok "API is healthy (checked $API_OK)"
else
  echo "WARNING: API did not report ready — run:"
  echo "    systemctl status certmgr-api"
  echo "    journalctl -u certmgr-api -n 50"
fi

MASTER_KEY="$(grep CERTMGR_SECRETS_MASTER_KEY "$ENV_FILE" | cut -d= -f2)"
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  CertMgr deployed on Oracle Linux 8 (DB: ${DB_LABEL:-$DB_ENGINE})"
echo "  UI:        https://$DOMAIN   (self-signed until you add a real cert)"
echo "  API docs:  https://$DOMAIN/api/docs"
echo "  Health:    https://$DOMAIN/health/ready"
echo ""
echo "  Bootstrap admin:  admin"
echo "  Password:         $MASTER_KEY   (shown once — change on first login)"
echo ""
echo "  NEXT STEPS:"
echo "   1. Point DNS  $DOMAIN → this server."
echo "   2. Replace the self-signed cert — issue a real one via CertMgr"
echo "      (Certificate wizard) or your CA, then: systemctl reload nginx."
echo "   3. Configure SMTP/Slack/Teams + Let's Encrypt email in Settings."
echo "   4. Add hook scripts under Hooks (DNS-01 etc.) as needed."
echo "   5. Backups run daily (pg/mysqldump + encrypted key material)."
echo "   6. Optional UI verification: cd $APP_DIR/backend && ./.venv/bin/certmgr seed-demo"
echo "   7. Later move to PostgreSQL: see docs/migration-mariadb-to-postgres.md"
echo "════════════════════════════════════════════════════════════════════"
