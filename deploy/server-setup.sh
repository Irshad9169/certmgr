#!/usr/bin/env bash
# ── CertMgr one-shot server setup (Docker path) ─────────────────────────────
# Run on a fresh Ubuntu 22.04+/RHEL 9+ server as root or with sudo:
#
#   sudo bash server-setup.sh
#
# What it does:
#   1. Installs Docker + Compose if missing
#   2. Extracts certmgr-deploy.tar.gz into /opt/certmgr (if run from the bundle)
#   3. Generates strong secrets and writes /opt/certmgr/.env
#   4. Builds & starts the full stack (postgres, redis, api, worker, beat, nginx)
#   5. Prints the bootstrap admin password and next steps
#
# Idempotent: safe to re-run. Re-running only regenerates secrets if .env is absent.
set -euo pipefail

APP_DIR="/opt/certmgr"
DOMAIN="${CERTMGR_DOMAIN:-certmgr.example.com}"     # ← change to your real domain
ADMIN_EMAIL="${CERTMGR_EMAIL:-ssl-admin@example.com}" # ← change to your real email

echo "==> CertMgr deployment to $APP_DIR (domain: $DOMAIN)"

# 1) Docker ----------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "==> Installing Docker…"
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "==> Installing Docker Compose plugin…"
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin || \
  yum install -y -q docker-compose-plugin || true
fi
echo "==> Docker: $(docker --version) / $(docker compose version)"

# 2) Extract bundle ---------------------------------------------------------
if [ -f certmgr-deploy.tar.gz ]; then
  mkdir -p "$APP_DIR"
  tar -xzf certmgr-deploy.tar.gz -C "$APP_DIR"
  echo "==> Extracted bundle into $APP_DIR"
elif [ -f "$APP_DIR/docker-compose.yml" ]; then
  echo "==> Bundle already extracted at $APP_DIR"
else
  echo "ERROR: certmgr-deploy.tar.gz not found. Place it next to this script (or in $APP_DIR)."
  exit 1
fi
cd "$APP_DIR"

# 3) Secrets / env ----------------------------------------------------------
if [ ! -f .env ]; then
  echo "==> Generating secrets…"
  SECRET_KEY="$(openssl rand -hex 32)"
  MASTER_KEY="$(openssl rand -base64 40 | tr -d '/+=' | head -c 48)"
  POSTGRES_PW="$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"
  cp backend/.env.example .env
  # Compose uses ${...} substitution for these:
  {
    echo "CERTMGR_SECRET_KEY=$SECRET_KEY"
    echo "CERTMGR_SECRETS_MASTER_KEY=$MASTER_KEY"
    echo "POSTGRES_PASSWORD=$POSTGRES_PW"
    echo "CERTMGR_DEFAULT_LETSENCRYPT_EMAIL=$ADMIN_EMAIL"
    echo "CERTMGR_DOMAIN=$DOMAIN"
  } >> .env
  echo "==> Secrets written to $APP_DIR/.env (keep this file safe!)"
else
  echo "==> .env already exists — keeping existing secrets"
fi

# 4) Start stack ------------------------------------------------------------
echo "==> Building & starting containers (first build can take a few minutes)…"
docker compose up -d --build

echo "==> Waiting for API health…"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1/health/ready" >/dev/null 2>&1; then
    echo "==> API is ready."
    break
  fi
  [ "$i" -eq 30 ] && { echo "ERROR: API did not become ready. Check: docker compose logs api"; exit 1; }
  sleep 4
done

# 5) Summary ----------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  CertMgr deployed!"
echo "  UI:        https://$DOMAIN   (or http://<server-ip>/ until DNS/TLS)"
echo "  API docs:  https://$DOMAIN/api/docs"
echo "  Health:    https://$DOMAIN/health/ready"
echo ""
echo "  Bootstrap admin:  admin"
echo "  Password:         randomly generated on first API start — retrieve it via:"
echo "                       docker compose logs api | grep 'Bootstrap admin'"
echo "                     (change it immediately on first login)"
echo ""
echo "  NEXT STEPS:"
echo "   1. Point DNS  $DOMAIN → this server, then set REAL TLS in"
echo "      infra/nginx/certmgr.conf (or put this behind your company LB)."
echo "   2. Log in → Settings → change secrets, SMTP, notification channels."
echo "   3. Configure Let's Encrypt email + hooks in the UI."
echo "   4. Backups run daily automatically (CERTMGR_BACKUP_ROOT)."
echo "   5. The platform starts EMPTY (no demo data). To verify the UI first:"
echo "        docker compose exec api certmgr seed-demo"
echo "      then delete rows before going live (or re-run with --no-reset)."
echo "═══════════════════════════════════════════════════════════════"
