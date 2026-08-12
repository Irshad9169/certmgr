"""Security primitives: password hashing, JWT, Fernet encryption, CSRF tokens.

Never log raw secrets. All private key material and stored credentials are
encrypted at rest with a Fernet master key derived from the configured
secrets_master_key (or a key file) — see app/services/secrets.py for the
SecretManager abstraction that sources this key from env / Vault / file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.core.exceptions import AuthError, SecurityError
from app.core.logging import get_logger

logger = get_logger(__name__)

JWT_ALGORITHM = settings.jwt_algorithm


# ── Password hashing ────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    if len(password) < settings.password_min_length:
        raise SecurityError(
            f"Password must be at least {settings.password_min_length} characters"
        )
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def validate_password_policy(password: str) -> list[str]:
    """Return a list of policy violations (empty == compliant)."""
    violations: list[str] = []
    if len(password) < settings.password_min_length:
        violations.append(f"Must be at least {settings.password_min_length} characters")
    if not any(c.islower() for c in password):
        violations.append("Must contain a lowercase letter")
    if not any(c.isupper() for c in password):
        violations.append("Must contain an uppercase letter")
    if not any(c.isdigit() for c in password):
        violations.append("Must contain a digit")
    if not any(c in "!@#$%^&*()_+-=[]{};:,.<>?/~`" for c in password):
        violations.append("Must contain a special character")
    return violations


# ── Master key / Fernet ─────────────────────────────────────────────────────
def _load_master_key() -> bytes:
    """Load the 32-byte master key from file, env, or (dev only) deterministic fallback."""
    key_file = settings.secrets_encryption_file
    if key_file:
        path = key_file
        try:
            with open(path, "rb") as fh:
                data = fh.read().strip()
            if len(data) == 44:
                return data  # already a Fernet key
            if len(data) >= 32:
                return base64.urlsafe_b64encode(hashlib.sha256(data).digest())
        except OSError as exc:  # pragma: no cover - depends on host env
            raise SecurityError(f"Cannot read secrets encryption file {path}: {exc}") from exc

    if settings.secrets_master_key:
        raw = settings.secrets_master_key.encode("utf-8")
        return base64.urlsafe_b64encode(hashlib.sha256(raw).digest())

    if settings.is_production:
        raise SecurityError(
            "CERTMGR_SECRETS_MASTER_KEY (or CERTMGR_SECRETS_ENCRYPTION_FILE) is required "
            "in production — refusing to boot with a predictable key."
        )
    # Development only: deterministic key so local state survives restarts.
    logger.warning("Using development-derived master key (NOT for production)")
    return base64.urlsafe_b64encode(hashlib.sha256(b"certmgr-dev-master-key").digest())


_fernet: Fernet | None = None


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_master_key())
    return _fernet


def encrypt_secret(plaintext: str | bytes) -> str:
    """Encrypt a secret; returns base64 Fernet token (safe to store in DB)."""
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    return get_fernet().encrypt(data).decode("utf-8")


def decrypt_secret(token: str) -> str:
    try:
        return get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise SecurityError("Unable to decrypt secret (invalid master key)") from exc


# ── JWT ─────────────────────────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(UTC)


def _create_token(
    subject: str,
    token_type: Literal["access", "refresh"],
    expires_delta: timedelta,
    extra: dict[str, Any] | None = None,
    jti: str | None = None,
) -> str:
    now = _now()
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "iss": settings.jwt_issuer,
        "jti": jti or secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    return _create_token(
        subject,
        "access",
        timedelta(minutes=settings.access_token_expire_minutes),
        extra,
    )


def create_refresh_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    return _create_token(
        subject,
        "refresh",
        timedelta(days=settings.refresh_token_expire_days),
        extra,
    )


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired", code="TOKEN_EXPIRED") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token", code="TOKEN_INVALID") from exc
    if payload.get("type") != expected_type:
        raise AuthError("Wrong token type", code="TOKEN_TYPE")
    return payload


# ── CSRF (double-submit cookie pattern) ─────────────────────────────────────
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf_token(token: str, expected: str) -> bool:
    if not token or not expected:
        return False
    return hmac.compare_digest(token, expected)


# ── Secure random helpers ───────────────────────────────────────────────────
def generate_api_token() -> str:
    """Return a random API token; only the SHA-256 hash should be persisted."""
    return secrets.token_urlsafe(48)


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_secret_key() -> str:
    return secrets.token_urlsafe(32)
