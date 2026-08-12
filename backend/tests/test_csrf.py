"""CSRF protection tests — the login flow must work when CSRF is ENABLED
(production default), and be rejected without a valid token."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


@pytest.fixture()
def csrf_client():
    """A TestClient with CSRF protection force-enabled (like production)."""
    was_enabled = settings.csrf_enabled
    settings.csrf_enabled = True
    try:
        with TestClient(app) as c:
            yield c
    finally:
        settings.csrf_enabled = was_enabled


def _get_csrf(client: TestClient) -> tuple[str, dict]:
    resp = client.get("/api/v1/auth/csrf")
    assert resp.status_code == 200, resp.text
    token = resp.json()["csrf_token"]
    # capture the cookie set by the response
    return token, {"certmgr_csrf": token}


def test_csrf_endpoint_sets_cookie(csrf_client):
    resp = csrf_client.get("/api/v1/auth/csrf")
    assert resp.status_code == 200
    assert resp.json()["csrf_token"]
    assert "certmgr_csrf" in resp.cookies


def test_login_rejected_without_csrf(csrf_client):
    token, cookies = _get_csrf(csrf_client)
    resp = csrf_client.post(
        "/api/v1/auth/login",
        cookies=cookies,
        json={"username": "admin", "password": "wrong"},
    )
    # no X-CSRF-Token header → CSRF rejection (403) takes precedence
    assert resp.status_code == 403
    assert "CSRF" in resp.text


def test_login_rejected_with_wrong_csrf(csrf_client):
    token, cookies = _get_csrf(csrf_client)
    resp = csrf_client.post(
        "/api/v1/auth/login",
        cookies=cookies,
        headers={"X-CSRF-Token": "not-the-token"},
        json={"username": "admin", "password": "wrong"},
    )
    assert resp.status_code == 403


def test_login_succeeds_with_valid_csrf(csrf_client):
    token, cookies = _get_csrf(csrf_client)
    resp = csrf_client.post(
        "/api/v1/auth/login",
        cookies=cookies,
        headers={"X-CSRF-Token": token},
        json={"username": "admin", "password": settings.secrets_master_key},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"]


def test_bearer_requests_are_csrf_exempt(csrf_client):
    """Bearer-token-authenticated requests are not CSRF-able (header auth),
    so the middleware skips the double-submit check for them — by design."""
    token, cookies = _get_csrf(csrf_client)
    login = csrf_client.post(
        "/api/v1/auth/login",
        cookies=cookies,
        headers={"X-CSRF-Token": token},
        json={"username": "admin", "password": settings.secrets_master_key},
    )
    access = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    # No CSRF header, but Bearer present → reaches the handler (bad creds → 401)
    resp = csrf_client.post(
        "/api/v1/auth/change-password",
        cookies=cookies,
        headers=headers,
        json={"old_password": "wrong-old", "new_password": "New!Str0ng-2026"},
    )
    assert resp.status_code == 401  # CSRF skipped; auth logic rejected creds


def test_login_does_not_rotate_csrf_cookie(csrf_client):
    """The CSRF token must stay stable across login so the client never holds
    a stale token for its next state-changing request."""
    token, cookies = _get_csrf(csrf_client)
    login = csrf_client.post(
        "/api/v1/auth/login",
        cookies=cookies,
        headers={"X-CSRF-Token": token},
        json={"username": "admin", "password": settings.secrets_master_key},
    )
    assert login.status_code == 200
    body = login.json()
    assert body["csrf_token"] == token  # no rotation
    # cookie in the login response is the same token
    assert login.cookies.get("certmgr_csrf") == token
