"""Application configuration.

All settings are read from environment variables / .env files (pydantic-settings).
Secrets may optionally be injected from HashiCorp Vault via the SecretManager
(see app/services/secrets.py) — the settings layer stays dependency-free so the
app can boot even when Vault is unreachable (fail-open to env vars only for
*non-critical* runtime settings; database/secrets always fail closed).
"""

from __future__ import annotations

import json
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ENV_PREFIX = "CERTMGR_"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "CertMgr — Enterprise Certificate Lifecycle Management"
    environment: Literal["development", "staging", "production", "testing"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    allowed_hosts: list[str] = ["*"]
    # NoDecode: pydantic-settings normally JSON-decodes list fields from env and
    # fails hard when the value isn't valid JSON. Some env-file loaders (bash
    # `source`) strip the inner quotes, turning ["https://a"] into [https://a].
    # We accept JSON, bracket/comma-separated, or plain comma-separated forms.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"]
    )
    trust_proxy_headers: bool = True

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, v):
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except json.JSONDecodeError:
                pass
            # Fallback: `[https://a, https://b]` (quotes stripped by shell) or
            # plain comma-separated.
            s = s.strip("[]").strip()
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    # ── Security ─────────────────────────────────────────────────────────────
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    jwt_issuer: str = "certmgr"
    cookie_secure: bool = True
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    csrf_enabled: bool = True
    password_min_length: int = 12
    max_login_attempts: int = 5
    lockout_minutes: int = 15
    mfa_required: bool = False
    # Master key used to encrypt secrets at rest (DB secrets, private keys on disk).
    # Supply CERTMGR_SECRETS_MASTER_KEY (32+ bytes) in production; a dev key is
    # derived deterministically ONLY when environment == development.
    secrets_master_key: str | None = None
    secrets_encryption_file: str | None = None  # path to a key file (preferred)

    # ── Database / Redis ─────────────────────────────────────────────────────
    database_url: str = "sqlite:///./certmgr-dev.db"
    redis_url: str = "redis://localhost:6379/0"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    sql_echo: bool = False

    # ── Celery ───────────────────────────────────────────────────────────────
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None
    celery_task_always_eager: bool = False  # True forces synchronous execution (tests/CI)

    # ── Storage ──────────────────────────────────────────────────────────────
    storage_root: str = "/var/lib/certmgr/certificates"
    backup_root: str = "/var/lib/certmgr/backups"
    log_root: str = "/var/log/certmgr"
    temp_workdir: str = "/var/lib/certmgr/tmp"
    storage_backend: Literal["filesystem", "encrypted-filesystem", "nfs"] = (
        "encrypted-filesystem"
    )

    # ── Certbot ──────────────────────────────────────────────────────────────
    certbot_binary: str = "certbot"
    certbot_workdir: str = "/etc/letsencrypt"
    certbot_timeout_seconds: int = 900
    default_letsencrypt_email: str = "ssl-admin@example.com"
    default_staging: bool = False
    default_environment: str = "production"

    # ── SSH credentials for hook scripts ────────────────────────────────────
    # A Hook may carry an encrypted SSH private key (see app/services/
    # ssh_credentials.py) for scripts that SSH to a remote host with no -i
    # flag. Requires a one-time `Include ~/certmgr.d/*.conf` line added to
    # the service account's ~/.ssh/config — see docs/administration.md.
    ssh_key_staging_dir: str = "/var/lib/certmgr/tmp/ssh"
    ssh_config_include_dir: str = "~/.ssh/certmgr.d"

    # ── Renewal / scheduler ──────────────────────────────────────────────────
    renewal_threshold_days: int = 30
    renewal_retry_max: int = 3
    renewal_cron: str = "0 3 * * *"  # 03:00 UTC daily
    discovery_cron: str = "30 2 * * *"
    health_cron: str = "0 */4 * * *"

    # ── Data retention (bounded DB growth) ──────────────────────────────────
    # Purge history older than N days. 0 (or negative) = keep forever.
    execution_retention_days: int = 365     # job_executions (certbot/deploy logs)
    audit_retention_days: int = 730         # audit_logs
    notification_retention_days: int = 365  # notifications

    # ── Notifications ────────────────────────────────────────────────────────
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_from: str = "certmgr@example.com"
    smtp_from_name: str = "CertMgr Platform"

    # ── Observability ────────────────────────────────────────────────────────
    prometheus_enabled: bool = True
    metrics_auth_token: str | None = None
    json_logging: bool = True
    log_level: str = "INFO"

    # ── AI assistant ─────────────────────────────────────────────────────────
    ai_enabled: bool = False
    ai_provider: Literal["openai", "anthropic", "local"] = "local"
    ai_base_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "gpt-4o-mini"

    # ── Deployment engine ────────────────────────────────────────────────────
    ssh_connect_timeout: int = 10
    ssh_command_timeout: int = 120
    rsync_binary: str = "rsync"
    deployment_verify_enabled: bool = True
    deployment_rollback_enabled: bool = True
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB uploads

    # ── Rate limiting ────────────────────────────────────────────────────────
    rate_limit_enabled: bool = True
    rate_limit_login: str = "10/minute"
    rate_limit_api: str = "300/minute"

    # ── SSO / external auth (Phase 3 extensions) ─────────────────────────────
    oidc_enabled: bool = False
    oidc_discovery_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    ldap_enabled: bool = False
    ldap_url: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_search_base: str | None = None
    ldap_user_filter: str = "(uid={username})"

    # ── Vault (optional secret backend) ──────────────────────────────────────
    vault_enabled: bool = False
    vault_url: str | None = None
    vault_token: str | None = None
    vault_kv_path: str = "secret/certmgr"
    vault_role_id: str | None = None
    vault_secret_id: str | None = None

    # ── Backup / restore ─────────────────────────────────────────────────────
    backup_enabled: bool = True
    backup_cron: str = "0 1 * * *"
    backup_keep_days: int = 30
    pg_dump_binary: str = "pg_dump"
    mysqldump_binary: str = "mysqldump"

    # ── Derived helpers ──────────────────────────────────────────────────────
    @field_validator("secrets_master_key")
    @classmethod
    def _warn_short_master_key(cls, v: str | None) -> str | None:
        if v is not None and len(v) < 32:
            raise ValueError("secrets_master_key must be at least 32 characters")
        return v

    @property
    def celery_broker(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def celery_backend(self) -> str:
        return self.celery_result_backend or self.redis_url

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_testing(self) -> bool:
        return self.environment == "testing" or self.database_url.startswith("sqlite")

    @property
    def storage_root_path(self) -> Path:
        return Path(self.storage_root)

    @property
    def backup_root_path(self) -> Path:
        return Path(self.backup_root)

    @property
    def log_root_path(self) -> Path:
        return Path(self.log_root)

    @property
    def temp_path(self) -> Path:
        return Path(self.temp_workdir)

    def secrets_payload(self) -> dict[str, Any]:
        """Non-sensitive metadata exposed to the API (never values of secrets)."""
        return {
            "vault_enabled": self.vault_enabled,
            "storage_backend": self.storage_backend,
            "mfa_required": self.mfa_required,
            "ai_enabled": self.ai_enabled,
            "environment": self.environment,
            "renewal_threshold_days": self.renewal_threshold_days,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
