"""Secret management abstraction.

Secret sources (in priority order):
  1. HashiCorp Vault (CERTMGR_VAULT_ENABLED=1) — KV v2
  2. Encrypted app_settings rows (secrets written by admins via the API)
  3. Environment variables

Every credential stored by the platform is encrypted at rest with the Fernet
master key before it touches the database or the filesystem.
"""

from __future__ import annotations

import os

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import decrypt_secret, encrypt_secret

logger = get_logger(__name__)


class SecretBackend:
    """Interface for secret retrieval."""

    def get(self, key: str, default: str | None = None) -> str | None:  # pragma: no cover
        raise NotImplementedError

    def set(self, key: str, value: str) -> None:  # pragma: no cover
        raise NotImplementedError


class EnvironmentBackend(SecretBackend):
    def get(self, key: str, default: str | None = None) -> str | None:
        return os.getenv(key, default)

    def set(self, key: str, value: str) -> None:
        raise RuntimeError("Environment secrets cannot be written at runtime")


class VaultBackend(SecretBackend):
    """KV v2 secrets engine via hvac. Falls back to env when vault is down."""

    def __init__(self) -> None:
        import hvac  # guarded import — optional dependency

        self._client = hvac.Client(url=settings.vault_url, token=settings.vault_token)
        if not self._client.is_authenticated():
            raise RuntimeError("Vault authentication failed")
        self._path = settings.vault_kv_path

    def get(self, key: str, default: str | None = None) -> str | None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(path=f"{self._path}/{key}")
            return str(resp["data"]["data"]["value"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Vault read failed for %s: %s", key, exc)
            return default

    def set(self, key: str, value: str) -> None:
        self._client.secrets.kv.v2.create_or_update_secret(
            path=f"{self._path}/{key}", secret={"value": value}
        )


class SecretManager:
    """Facade used across the platform."""

    def __init__(self) -> None:
        self._db_backend: DbSecretBackend | None = None
        self._backends: list[SecretBackend] = [EnvironmentBackend()]
        if settings.vault_enabled:
            try:
                self._backends.insert(0, VaultBackend())
            except Exception as exc:  # noqa: BLE001
                logger.error("Vault unavailable, falling back to env secrets: %s", exc)

    def bind_db(self, backend: DbSecretBackend) -> None:
        """Inject the app-settings-backed secret store once a session exists."""
        self._db_backend = backend

    def get(self, key: str, default: str | None = None) -> str | None:
        for backend in self._backends:
            value = backend.get(key)
            if value is not None:
                return value
        if self._db_backend is not None:
            return self._db_backend.get(key)
        return default

    def set_db(self, key: str, value: str) -> None:
        if self._db_backend is None:
            raise RuntimeError("DB secret backend not bound")
        self._db_backend.set(key, value)

    def encrypt(self, plaintext: str) -> str:
        return encrypt_secret(plaintext)

    def decrypt(self, token: str) -> str:
        return decrypt_secret(token)


class DbSecretBackend(SecretBackend):
    """Reads/writes secrets to app_settings rows (values Fernet-encrypted)."""

    def __init__(self, db) -> None:
        self._db = db

    def _row(self, key: str):
        from app.models.settings import AppSetting

        row = (
            self._db.query(AppSetting).filter(AppSetting.key == f"secret.{key}").first()
        )
        if row is None:
            return None
        return decrypt_secret(row.value) if row.value else None

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._row(key) or default

    def set(self, key: str, value: str) -> None:
        from app.models.settings import AppSetting

        row = (
            self._db.query(AppSetting).filter(AppSetting.key == f"secret.{key}").first()
        )
        if row is None:
            row = AppSetting(key=f"secret.{key}", value=encrypt_secret(value), is_secret=True)
            self._db.add(row)
        else:
            row.value = encrypt_secret(value)
            row.is_secret = True


_secret_manager: SecretManager | None = None


def get_secret_manager() -> SecretManager:
    global _secret_manager
    if _secret_manager is None:
        _secret_manager = SecretManager()
    return _secret_manager


def resolve_secret(key: str, default: str | None = None) -> str | None:
    return get_secret_manager().get(key, default)
