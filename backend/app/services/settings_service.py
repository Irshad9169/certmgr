"""Admin-configurable key/value settings (secrets encrypted at rest)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.security import decrypt_secret, encrypt_secret
from app.models.settings import AppSetting

logger = get_logger(__name__)

# Keys that must never be returned in plaintext via the API
_SECRET_KEYS = {
    "smtp.password", "slack.webhook_url", "teams.webhook_url",
    "webhook.url", "webhook.secret", "letsencrypt.account_key",
}

DEFAULT_SETTINGS: dict[str, tuple[str, bool, str]] = {
    "letsencrypt.email": ("", False, "Let's Encrypt account/contact email"),
    "default.key_type": ("rsa2048", False, "Default key type for new certificates"),
    "default.validation_method": ("http-01", False, "Default validation method"),
    "default.hook_id": ("", False, "Default auth hook id"),
    "renewal.threshold_days": ("30", False, "Auto-renew certificates expiring within N days"),
    "storage.certificate_location": ("", False, "Certificate storage root"),
    "storage.backup_location": ("", False, "Backup location"),
    "storage.temp_dir": ("", False, "Temporary working directory"),
    "discovery.scan_paths": ("/etc/letsencrypt/live,/etc/pki/tls/certs", False, "Discovery scan paths (comma-separated)"),
    "smtp.host": ("", False, "SMTP host"),
    "smtp.port": ("587", False, "SMTP port"),
    "smtp.username": ("", False, "SMTP username"),
    "smtp.password": ("", True, "SMTP password (secret)"),
    "smtp.from": ("", False, "SMTP from address"),
    "slack.webhook_url": ("", True, "Slack webhook URL (secret)"),
    "teams.webhook_url": ("", True, "Microsoft Teams webhook URL (secret)"),
    "webhook.url": ("", True, "Generic webhook URL (secret)"),
    "notification.default_recipients": ("", False, "Default notification recipients (comma-separated emails)"),
    "notification.expiry_warning_days": ("60,30,15,7,3,1", False,
                                         "Days before expiry to send warnings (comma-separated, e.g. 14,7,1)"),
    "maintenance.message": ("", False, "Optional maintenance banner message"),
    "godaddy.api_key": ("", True, "GoDaddy API key (secret) — developer.godaddy.com"),
    "godaddy.api_secret": ("", True, "GoDaddy API secret (secret)"),
}


def seed_defaults(db: Session) -> None:
    for key, (default, is_secret, description) in DEFAULT_SETTINGS.items():
        row = db.query(AppSetting).filter(AppSetting.key == key).first()
        if row is None:
            db.add(AppSetting(key=key, value=encrypt_secret(default) if is_secret and default else (default or None),
                              is_secret=is_secret, description=description))
    db.commit()


def get_setting(db: Session | None, key: str) -> str | None:
    """Read a setting (raw/decrypted). Accepts a session or resolves one."""
    from app.core.database import SessionLocal

    own = db is None
    session = db or SessionLocal()
    try:
        row = session.query(AppSetting).filter(AppSetting.key == key).first()
        if row is None:
            default = DEFAULT_SETTINGS.get(key)
            return default[0] if default else None
        if row.is_secret and row.value:
            return decrypt_secret(row.value)
        return row.value
    finally:
        if own:
            session.close()


def get_all_settings(db: Session) -> list[dict[str, Any]]:
    """Return settings with secrets masked (admin UI shows '•••set•••').

    A list, not a dict keyed by setting name — the frontend renders this
    directly as a table via .map(), which a dict shape doesn't support.
    """
    out: list[dict[str, Any]] = []
    rows = db.query(AppSetting).all()
    for key, (default, is_secret, description) in DEFAULT_SETTINGS.items():
        row = next((r for r in rows if r.key == key), None)
        value = row.value if row else (default or "")
        out.append({
            "key": key,
            "value": ("[SET]" if (row and row.value) else "") if is_secret else (value or ""),
            "is_secret": is_secret,
            "description": description,
            "configured": row is not None and bool(row.value),
        })
    return out


def set_setting(db: Session, key: str, value: str | None, *, updated_by: int | None = None,
                is_secret: bool | None = None) -> AppSetting:
    if key not in DEFAULT_SETTINGS:
        raise ValueError(f"Unknown setting key: {key}")
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row is None:
        row = AppSetting(key=key, description=DEFAULT_SETTINGS[key][2],
                         is_secret=is_secret if is_secret is not None else DEFAULT_SETTINGS[key][1])
        db.add(row)
    secret = is_secret if is_secret is not None else row.is_secret
    row.is_secret = secret
    row.value = encrypt_secret(value) if secret and value else (value if value else None)
    row.updated_by = updated_by
    db.commit()
    db.refresh(row)
    return row


def get_secret(db: Session, key: str) -> str | None:
    """Return a decrypted secret value (internal callers only)."""
    if key not in _SECRET_KEYS and key not in DEFAULT_SETTINGS:
        raise ValueError(f"Not a secret setting: {key}")
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row is None or not row.value:
        return None
    if row.is_secret:
        return decrypt_secret(row.value)
    return row.value
