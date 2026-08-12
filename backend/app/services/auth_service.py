"""Authentication: login with lockout + optional TOTP MFA, token lifecycle."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthError, ConflictError, ValidationAppError
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    generate_api_token,
    hash_api_token,
    hash_password,
    verify_password,
)
from app.core.timeutils import ensure_aware
from app.models.user import ApiToken, RefreshToken, User

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def authenticate(db: Session, username: str, password: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        # Constant-ish timing: still hash a dummy password
        verify_password(password, hash_password("dummy-"+secrets.token_urlsafe(6)+"!Aa9"))
        raise AuthError("Invalid username or password", code="BAD_CREDENTIALS")

    if not user.is_active:
        raise AuthError("Account is disabled", code="ACCOUNT_DISABLED")
    if user.is_locked and user.locked_until and _now() < ensure_aware(user.locked_until):
        mins = int((ensure_aware(user.locked_until) - _now()).total_seconds() // 60)
        raise AuthError(f"Account temporarily locked; retry in {mins} minute(s)", code="ACCOUNT_LOCKED")

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.is_locked = True
            user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
            user.failed_login_attempts = 0
        db.commit()
        raise AuthError("Invalid username or password", code="BAD_CREDENTIALS")

    user.failed_login_attempts = 0
    user.is_locked = False
    user.locked_until = None
    user.last_login_at = _now()
    db.commit()
    return user


def verify_mfa(user: User, code: str) -> bool:
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        return True
    secret = decrypt_secret(user.mfa_secret_encrypted)
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def issue_tokens(db: Session, user: User, *, ip: str | None = None,
                 user_agent: str | None = None) -> dict[str, Any]:
    extra = {"role": user.role_name.value, "permissions": list(user.role.permissions or [])}
    access = create_access_token(str(user.id), extra)
    refresh = create_refresh_token(str(user.id), extra)
    refresh_jti = decode_token(refresh, expected_type="refresh")["jti"]
    db.add(RefreshToken(
        user_id=user.id,
        jti=refresh_jti,
        token_hash=hashlib.sha256(refresh.encode()).hexdigest(),
        expires_at=_now() + timedelta(days=settings.refresh_token_expire_days),
        user_agent=(user_agent or "")[:500],
        ip_address=ip,
    ))
    db.commit()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
    }


def refresh_access_token(db: Session, refresh_token: str) -> dict[str, Any]:
    payload = decode_token(refresh_token, expected_type="refresh")
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if row is None or row.revoked_at is not None:
        raise AuthError("Refresh token has been revoked", code="TOKEN_REVOKED")
    if ensure_aware(row.expires_at) < _now():
        raise AuthError("Refresh token expired", code="TOKEN_EXPIRED")

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if user is None or not user.is_active:
        raise AuthError("User no longer active", code="ACCOUNT_DISABLED")

    extra = {"role": user.role_name.value, "permissions": list(user.role.permissions or [])}
    return {
        "access_token": create_access_token(str(user.id), extra),
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60,
    }


def revoke_refresh_token(db: Session, refresh_token: str) -> None:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if row:
        row.revoked_at = _now()
        db.commit()


def create_api_token(db: Session, user: User, name: str, scopes: list[str],
                     expires_at: datetime | None = None) -> dict[str, Any]:
    token = generate_api_token()
    db.add(ApiToken(
        user_id=user.id,
        name=name,
        token_hash=hash_api_token(token),
        prefix="cm_" + token[:8],
        scopes=scopes or [],
        expires_at=expires_at,
    ))
    db.commit()
    return {"token": token, "name": name, "scopes": scopes, "expires_at": expires_at}


def authenticate_api_token(db: Session, token: str) -> User | None:
    row = db.query(ApiToken).filter(ApiToken.token_hash == hash_api_token(token)).first()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at and row.expires_at < _now():
        return None
    user = db.query(User).filter(User.id == row.user_id, User.is_active.is_(True)).first()
    if user is None:
        return None
    row.last_used_at = _now()
    db.commit()
    return user


def setup_mfa(db: Session, user: User) -> dict[str, str]:
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    db.commit()
    provisioning = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="CertMgr")
    return {"secret": secret, "provisioning_uri": provisioning}


def enable_mfa(db: Session, user: User, code: str) -> None:
    if not user.mfa_secret_encrypted:
        raise ConflictError("MFA not initialized; call setup first")
    secret = decrypt_secret(user.mfa_secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise ValidationAppError("Invalid verification code")
    user.mfa_enabled = True
    db.commit()


def disable_mfa(db: Session, user: User, password: str) -> None:
    if not verify_password(password, user.hashed_password):
        raise AuthError("Password verification failed", code="BAD_CREDENTIALS")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    db.commit()


def change_password(db: Session, user: User, old_password: str, new_password: str) -> None:
    if not verify_password(old_password, user.hashed_password):
        raise AuthError("Current password is incorrect", code="BAD_CREDENTIALS")
    from app.core.security import validate_password_policy

    violations = validate_password_policy(new_password)
    if violations:
        raise ValidationAppError("Password policy not met", details=violations)
    if old_password == new_password:
        raise ValidationAppError("New password must differ from the current password")
    user.hashed_password = hash_password(new_password)
    user.must_change_password = False
    # Invalidate all refresh tokens on password change
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update({"revoked_at": _now()})
    db.commit()


def create_user(db: Session, *, username: str, email: str | None, full_name: str,
                password: str, role_name: str, created_by: int | None = None) -> User:
    from app.api.permissions import ROLE_PERMISSIONS
    from app.models.user import Role

    if db.query(User).filter(User.username == username).first():
        raise ConflictError(f"Username '{username}' already exists")
    if email and db.query(User).filter(User.email == email).first():
        raise ConflictError(f"Email '{email}' already exists")
    role = db.query(Role).filter(Role.name == role_name).first()
    if role is None or role_name not in ROLE_PERMISSIONS:
        raise ValidationAppError(f"Invalid role: {role_name}")

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role_id=role.id,
        created_by=created_by,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_or_create_bootstrap_admin(db: Session) -> User:
    """Idempotent bootstrap admin for first-run (env-configured credentials).

    Concurrency-safe: if multiple workers race to create the admin on first
    boot, the loser rolls back and returns the winner's row.
    """
    from sqlalchemy.exc import IntegrityError

    from app.models.user import Role

    admin = db.query(User).filter(User.username == "admin").first()
    if admin:
        return admin
    role = db.query(Role).filter(Role.name == "administrator").first()
    password = settings.secrets_master_key or "ChangeMe!Admin2024"
    admin = User(
        username="admin",
        email=settings.default_letsencrypt_email,
        full_name="Platform Administrator",
        hashed_password=hash_password(password[:60]),
        role_id=role.id if role else None,
        must_change_password=True,
    )
    if admin.role_id is None:
        from sqlalchemy import text
        admin.role_id = db.execute(text("SELECT id FROM roles WHERE name='administrator'")).scalar()
    db.add(admin)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(User).filter(User.username == "admin").first()
        if existing is None:
            raise
        return existing
    db.commit()
    return admin
