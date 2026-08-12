"""Security primitives: hashing, JWT, encryption, CSRF, redaction."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.exceptions import AuthError, SecurityError
from app.core.logging import redact
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    generate_csrf_token,
    hash_api_token,
    hash_password,
    verify_csrf_token,
    verify_password,
)


def test_password_hash_roundtrip():
    hashed = hash_password("Str0ng!Passw0rd-2024")
    assert hashed != "Str0ng!Passw0rd-2024"
    assert verify_password("Str0ng!Passw0rd-2024", hashed)
    assert not verify_password("wrong", hashed)


def test_password_policy_rejects_weak():
    with pytest.raises(SecurityError):
        hash_password("short")


def test_jwt_access_roundtrip():
    token = create_access_token("42", {"role": "administrator"})
    payload = decode_token(token, expected_type="access")
    assert payload["sub"] == "42"
    assert payload["role"] == "administrator"
    assert payload["iss"] == settings.jwt_issuer


def test_jwt_type_mismatch_rejected():
    refresh = create_refresh_token("42")
    with pytest.raises(AuthError):
        decode_token(refresh, expected_type="access")


def test_jwt_tampered_rejected():
    token = create_access_token("42")
    with pytest.raises(AuthError):
        decode_token(token[:-2] + "xx")


def test_fernet_roundtrip():
    secret = "super-secret-value"
    token = encrypt_secret(secret)
    assert token != secret
    assert decrypt_secret(token) == secret


def test_csrf_token_verification():
    token = generate_csrf_token()
    assert verify_csrf_token(token, token)
    assert not verify_csrf_token("attacker", token)


def test_api_token_hashing():
    token = "cm_secret-token-value"
    h1 = hash_api_token(token)
    h2 = hash_api_token(token)
    assert h1 == h2
    assert token not in h1


def test_log_redaction_private_key():
    key = (
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
        "-----END PRIVATE KEY-----\n"
    )
    redacted = redact(f"log line {key} end")
    assert "BEGIN PRIVATE KEY" not in redacted
    assert "REDACTED" in redacted


def test_log_redaction_password():
    redacted = redact("connect with password=hunter2 and token=abc123")
    assert "hunter2" not in redacted
    assert "abc123" not in redacted
