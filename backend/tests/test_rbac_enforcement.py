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


def test_read_only_cannot_delete(client, role_headers_factory):
    headers = role_headers_factory("ro_delete", "read_only")
    resp = client.delete("/api/v1/certificates/999999", headers=headers)
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


def test_cert_manager_cannot_trigger_network_scan(client, role_headers_factory):
    """Network scanning is admin-only — stricter than discovery:run (which
    cert_manager does have), since it touches infrastructure outside
    CertMgr's control rather than just local filesystem paths."""
    headers = role_headers_factory("cm_netscan", "certificate_manager")
    resp = client.post("/api/v1/discovery/network-scan", headers=headers,
                       json={"targets": ["127.0.0.1"], "ports": [1]})
    assert resp.status_code == 403


def test_read_only_cannot_trigger_network_scan(client, role_headers_factory):
    headers = role_headers_factory("ro_netscan", "read_only")
    resp = client.post("/api/v1/discovery/network-scan", headers=headers,
                       json={"targets": ["127.0.0.1"], "ports": [1]})
    assert resp.status_code == 403


def test_admin_can_trigger_network_scan(client, admin_headers):
    resp = client.post("/api/v1/discovery/network-scan", headers=admin_headers,
                       json={"targets": ["127.0.0.1"], "ports": [1], "timeout_seconds": 1})
    assert resp.status_code == 200, resp.text


def test_cert_manager_cannot_trigger_ct_monitor(client, role_headers_factory):
    """CT monitoring is admin-only, same rationale as network_scan."""
    headers = role_headers_factory("cm_ctmon", "certificate_manager")
    resp = client.post("/api/v1/discovery/ct-monitor", headers=headers, json={"domains": ["example.com"]})
    assert resp.status_code == 403


def test_read_only_cannot_trigger_ct_monitor(client, role_headers_factory):
    headers = role_headers_factory("ro_ctmon", "read_only")
    resp = client.post("/api/v1/discovery/ct-monitor", headers=headers, json={"domains": ["example.com"]})
    assert resp.status_code == 403


def test_admin_can_trigger_ct_monitor(client, admin_headers, monkeypatch):
    from app.services import ct_monitor

    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries", lambda domain, *, limit, timeout=15.0: [])
    resp = client.post("/api/v1/discovery/ct-monitor", headers=admin_headers, json={"domains": ["example.com"]})
    assert resp.status_code == 200, resp.text


def test_read_only_can_view_findings_but_not_manage(client, role_headers_factory):
    headers = role_headers_factory("ro_findings", "read_only")
    resp = client.get("/api/v1/findings", headers=headers)
    assert resp.status_code == 200, resp.text
    resp = client.patch("/api/v1/findings/999999", headers=headers, json={"status": "resolved"})
    assert resp.status_code == 403


def test_operator_cannot_manage_findings(client, role_headers_factory):
    """OPERATOR has finding:view (via discovery:view-tier access) but not finding:manage."""
    headers = role_headers_factory("op_findings", "operator")
    resp = client.patch("/api/v1/findings/999999", headers=headers, json={"status": "resolved"})
    assert resp.status_code == 403


def test_read_only_cannot_trigger_usage_scan(client, role_headers_factory):
    headers = role_headers_factory("ro_usage", "read_only")
    resp = client.post("/api/v1/certificates/999999/usage/scan", headers=headers, json={})
    assert resp.status_code == 403


def test_operator_cannot_trigger_usage_scan(client, role_headers_factory):
    """OPERATOR has certificate:renew but not certificate:usage_scan (same
    renew/revoke-adjacent tier as revoke, not the broader operator set)."""
    headers = role_headers_factory("op_usage", "operator")
    resp = client.post("/api/v1/certificates/999999/usage/scan", headers=headers, json={})
    assert resp.status_code == 403


def test_cert_manager_can_trigger_usage_scan(client, role_headers_factory):
    from conftest import SessionLocal

    from app.models.certificate import Certificate
    from app.models.enums import CertificateType, ValidationMethod

    db = SessionLocal()
    try:
        cert = Certificate(domain="*.rbac-usage.example.com", cert_name="rbac-usage",
                           sans=["*.rbac-usage.example.com"], cert_type=CertificateType.WILDCARD.value,
                           validation_method=ValidationMethod.HTTP_01.value, is_wildcard=True)
        db.add(cert)
        db.commit()
        cert_id = cert.id
    finally:
        db.close()

    headers = role_headers_factory("cm_usage", "certificate_manager")
    resp = client.post(f"/api/v1/certificates/{cert_id}/usage/scan", headers=headers,
                       json={"sources": ["manual"], "hostnames": []})
    assert resp.status_code == 200, resp.text


def test_usage_scan_rejects_non_wildcard_certificate(client, admin_headers):
    from conftest import SessionLocal

    from app.models.certificate import Certificate
    from app.models.enums import CertificateType, ValidationMethod

    db = SessionLocal()
    try:
        cert = Certificate(domain="single.rbac-usage.example.com", cert_name="single-rbac-usage",
                           sans=["single.rbac-usage.example.com"], cert_type=CertificateType.SINGLE.value,
                           validation_method=ValidationMethod.HTTP_01.value, is_wildcard=False)
        db.add(cert)
        db.commit()
        cert_id = cert.id
    finally:
        db.close()

    resp = client.post(f"/api/v1/certificates/{cert_id}/usage/scan", headers=admin_headers, json={})
    assert resp.status_code == 422


def test_read_only_can_view_usage_results(client, role_headers_factory):
    headers = role_headers_factory("ro_usage_view", "read_only")
    resp = client.get("/api/v1/certificates/999999/usage", headers=headers)
    assert resp.status_code == 200, resp.text


def test_async_usage_scan_trigger_returns_a_pollable_scan_id(client, admin_headers, monkeypatch):
    """In real (non-eager) Celery deployments, the scan row must be created
    and its id returned BEFORE a worker picks up the task, so the frontend
    has something to poll immediately (rather than a bare {"status":
    "queued"}, which the other discovery scans return with no id)."""
    from conftest import SessionLocal

    from app.core.config import settings
    from app.models.certificate import Certificate
    from app.models.certificate_usage import CertificateUsageScan
    from app.models.enums import CertificateType, ValidationMethod

    monkeypatch.setattr(settings, "celery_task_always_eager", False)
    monkeypatch.setattr("app.tasks.discovery.run_certificate_usage_scan.delay", lambda *a, **k: None)

    db = SessionLocal()
    try:
        cert = Certificate(domain="*.async-usage.example.com", cert_name="async-usage",
                           sans=["*.async-usage.example.com"], cert_type=CertificateType.WILDCARD.value,
                           validation_method=ValidationMethod.HTTP_01.value, is_wildcard=True)
        db.add(cert)
        db.commit()
        cert_id = cert.id
    finally:
        db.close()

    resp = client.post(f"/api/v1/certificates/{cert_id}/usage/scan", headers=admin_headers,
                       json={"sources": ["manual"], "hostnames": ["api.async-usage.example.com"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    assert "scan_id" in body

    db = SessionLocal()
    try:
        scan = db.get(CertificateUsageScan, body["scan_id"])
        assert scan is not None
        assert scan.certificate_id == cert_id
    finally:
        db.close()


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
