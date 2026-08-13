"""RBAC enforcement: endpoints that previously had NO server-side permission
check must now reject roles that lack the corresponding permission code in
app/api/permissions.py, even though the permission check happens before any
downstream lookup (so a nonexistent resource id still yields 403, not 404 —
that ordering is intentional and asserted here)."""

from __future__ import annotations


def test_read_only_cannot_renew(client, role_headers_factory):
    headers = role_headers_factory("ro_renew", "read_only")
    resp = client.post("/api/v1/certificates/999999/renew", headers=headers, json={})
    assert resp.status_code == 403


def test_read_only_cannot_revoke(client, role_headers_factory):
    headers = role_headers_factory("ro_revoke", "read_only")
    resp = client.post("/api/v1/certificates/999999/revoke", headers=headers, json={})
    assert resp.status_code == 403


def test_read_only_cannot_clone(client, role_headers_factory):
    headers = role_headers_factory("ro_clone", "read_only")
    resp = client.post("/api/v1/certificates/999999/clone", headers=headers, json={})
    assert resp.status_code == 403


def test_operator_cannot_revoke(client, role_headers_factory):
    """OPERATOR has certificate:renew but not certificate:revoke."""
    headers = role_headers_factory("op_revoke", "operator")
    resp = client.post("/api/v1/certificates/999999/revoke", headers=headers, json={})
    assert resp.status_code == 403


def test_read_only_cannot_bulk_renew(client, role_headers_factory):
    headers = role_headers_factory("ro_bulk", "read_only")
    resp = client.post("/api/v1/certificates/bulk", headers=headers,
                       json={"action": "renew", "ids": [999999]})
    assert resp.status_code == 403


def test_operator_cannot_bulk_revoke(client, role_headers_factory):
    """OPERATOR lacks certificate:bulk entirely."""
    headers = role_headers_factory("op_bulk", "operator")
    resp = client.post("/api/v1/certificates/bulk", headers=headers,
                       json={"action": "renew", "ids": [999999]})
    assert resp.status_code == 403


def test_read_only_cannot_import_from_paths(client, role_headers_factory):
    headers = role_headers_factory("ro_import", "read_only")
    resp = client.post("/api/v1/certificates/import/paths", headers=headers,
                       json={"cert_path": "/etc/letsencrypt/live/example.com/cert.pem"})
    assert resp.status_code == 403


def test_read_only_cannot_deploy(client, role_headers_factory):
    headers = role_headers_factory("ro_deploy", "read_only")
    resp = client.post("/api/v1/deployments", headers=headers,
                       json={"certificate_id": 999999, "server_id": 999999})
    assert resp.status_code == 403


def test_read_only_cannot_rollback(client, role_headers_factory):
    headers = role_headers_factory("ro_rollback", "read_only")
    resp = client.post("/api/v1/deployments/999999/rollback", headers=headers)
    assert resp.status_code == 403


def test_read_only_cannot_trigger_discovery(client, role_headers_factory):
    headers = role_headers_factory("ro_discovery", "read_only")
    resp = client.post("/api/v1/discovery/run", headers=headers, json={})
    assert resp.status_code == 403


def test_operator_cannot_run_health_scan(client, role_headers_factory):
    """OPERATOR has health:view but not health:run."""
    headers = role_headers_factory("op_health", "operator")
    resp = client.get("/api/v1/health/certificate/999999/scan", headers=headers)
    assert resp.status_code == 403


def test_read_only_cannot_generate_compliance_report(client, role_headers_factory):
    headers = role_headers_factory("ro_compliance", "read_only")
    resp = client.post("/api/v1/compliance/report", headers=headers)
    assert resp.status_code == 403


def test_cert_manager_cannot_download_reports(client, role_headers_factory):
    """admin:reports is ADMIN-only in the permission matrix."""
    headers = role_headers_factory("cm_reports", "certificate_manager")
    resp = client.get("/api/v1/reports/inventory.csv", headers=headers)
    assert resp.status_code == 403


def test_read_only_cannot_use_ai_assistant(client, role_headers_factory):
    """ai:use is ADMIN-only in the permission matrix."""
    headers = role_headers_factory("ro_ai", "read_only")
    resp = client.get("/api/v1/ai/recurring-failures", headers=headers)
    assert resp.status_code == 403


def test_admin_can_use_ai_assistant(client, admin_headers):
    resp = client.get("/api/v1/ai/recurring-failures", headers=admin_headers)
    assert resp.status_code == 200
