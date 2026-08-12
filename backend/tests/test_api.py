"""API integration tests: auth, RBAC, inventory, import upload, downloads."""

from __future__ import annotations

import io
import zipfile

from conftest import TEST_ADMIN_PASSWORD, _generate_self_signed


# ── Auth ────────────────────────────────────────────────────────────────────
def test_login_and_me(client, admin_headers):
    resp = client.get("/api/v1/auth/me", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "admin"
    assert body["role"] == "administrator"
    assert "certificate:issue" in body["permissions"]


def test_login_bad_credentials(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpass"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "BAD_CREDENTIALS"


def test_protected_route_requires_auth(client):
    resp = client.get("/api/v1/certificates")
    assert resp.status_code == 401


def test_refresh_flow(client, admin_headers):
    resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": client.post("/api/v1/auth/login",
              json={"username": "admin", "password": TEST_ADMIN_PASSWORD}).json()["refresh_token"]},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_api_token_flow(client, admin_headers):
    create = client.post("/api/v1/auth/tokens", headers=admin_headers,
                         json={"name": "ci-token", "scopes": ["certificate:view"]})
    assert create.status_code == 200, create.text
    token = create.json()["token"]
    resp = client.get("/api/v1/certificates", headers={"X-API-Key": token})
    assert resp.status_code == 200


# ── RBAC ────────────────────────────────────────────────────────────────────
def test_read_only_cannot_issue(client, role_headers_factory):
    headers = role_headers_factory("ro_user", "read_only")
    resp = client.post("/api/v1/certificates/issue", headers=headers,
                       json={"domains": ["nope.example.com"], "validation_method": "http-01",
                             "key_type": "rsa2048", "email": "ops@corp.com"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


def test_operator_cannot_manage_users(client, role_headers_factory):
    headers = role_headers_factory("op_user", "operator")
    resp = client.post("/api/v1/users", headers=headers,
                       json={"username": "hacker", "password": "Str0ng!Passw0rd", "role": "admin"})
    assert resp.status_code == 403


def test_admin_can_create_user(client, admin_headers):
    resp = client.post("/api/v1/users", headers=admin_headers,
                       json={"username": "newbie", "password": "Str0ng!Passw0rd",
                             "full_name": "New User", "role": "operator"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "operator"


# ── Inventory ───────────────────────────────────────────────────────────────
def test_inventory_pagination_and_sort(client, admin_headers):
    resp = client.get("/api/v1/certificates", headers=admin_headers,
                      params={"page": 1, "page_size": 10, "sort_by": "domain", "sort_dir": "asc"})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body and "total" in body and "summary" in body


def test_inventory_invalid_page_size_rejected(client, admin_headers):
    resp = client.get("/api/v1/certificates", headers=admin_headers, params={"page_size": 100000})
    assert resp.status_code == 422


# ── Import via API ──────────────────────────────────────────────────────────
def test_import_upload(client, admin_headers, storage_root):
    cert, cert_pem, key_pem = _generate_self_signed(["upload.example.com"])
    files = {
        "certificate": ("cert.pem", cert_pem, "application/x-pem-file"),
        "private_key": ("key.pem", key_pem, "application/x-pem-file"),
    }
    resp = client.post("/api/v1/certificates/import/upload", headers=admin_headers,
                       files=files, params={"environment": "production"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["domain"] == "upload.example.com"
    assert body["fingerprint"]


def test_import_upload_rejects_oversize(client, admin_headers):
    cert, cert_pem, key_pem = _generate_self_signed(["big.example.com"])
    huge = b"x" * (11 * 1024 * 1024)
    resp = client.post(
        "/api/v1/certificates/import/upload", headers=admin_headers,
        files={"certificate": ("cert.pem", huge, "application/x-pem-file")},
    )
    assert resp.status_code == 422


def test_import_duplicate_via_api(client, admin_headers):
    cert, cert_pem, key_pem = _generate_self_signed(["dup.example.com"])
    files = {"certificate": ("c.pem", cert_pem, "text/plain")}
    first = client.post("/api/v1/certificates/import/upload", headers=admin_headers, files=files)
    assert first.status_code == 200
    second = client.post("/api/v1/certificates/import/upload", headers=admin_headers, files=files)
    assert second.status_code == 409


# ── Downloads (audited + permission gated) ─────────────────────────────────
def test_download_zip_requires_key_permission(client, role_headers_factory, admin_headers):
    cert, cert_pem, key_pem = _generate_self_signed(["dl.example.com"])
    files = {"certificate": ("c.pem", cert_pem, "text/plain")}
    create = client.post("/api/v1/certificates/import/upload", headers=admin_headers, files=files)
    cert_id = create.json()["certificate_id"]

    # operator may download cert but not the key
    op_headers = role_headers_factory("op_dl", "operator")
    resp = client.get(f"/api/v1/certificates/{cert_id}/download/zip",
                      headers=op_headers, params={"include_key": False})
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    assert "cert.pem" in zf.namelist()
    assert "privkey.pem" not in zf.namelist()

    resp = client.get(f"/api/v1/certificates/{cert_id}/download/key", headers=op_headers)
    assert resp.status_code == 403


# ── Audit trail ─────────────────────────────────────────────────────────────
def test_audit_records_actions(client, admin_headers):
    client.get("/api/v1/certificates", headers=admin_headers)
    resp = client.get("/api/v1/audit", headers=admin_headers,
                      params={"action": "certificate.download", "page_size": 5})
    assert resp.status_code == 200
    assert "items" in resp.json()
