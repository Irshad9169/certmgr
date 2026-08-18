"""Server inventory: create/delete via the API. No prior test coverage
existed for this resource at all."""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.models.server import Server
from app.services.server_service import create_server, delete_server


def test_delete_server_removes_it(db):
    server = create_server(db, {"hostname": "delete-me.example.com", "ssh_user": "root"})
    server_id = server.id

    delete_server(db, server_id)

    assert db.query(Server).filter(Server.id == server_id).first() is None


def test_delete_missing_server_raises(db):
    import pytest

    with pytest.raises(NotFoundError):
        delete_server(db, 999999)


def test_delete_server_cascades_deployments_and_nulls_job_executions(db, admin_user):
    from app.models.certificate import Certificate
    from app.models.enums import (
        CertificateStatus,
        CertificateType,
        JobStatus,
        JobType,
        ValidationMethod,
    )
    from app.models.job import JobExecution
    from app.models.server import Deployment

    server = create_server(db, {"hostname": "with-deploys.example.com", "ssh_user": "root"})
    cert = Certificate(
        domain="deploy-target.example.com", cert_name="deploy-target.example.com",
        sans=["deploy-target.example.com"], cert_type=CertificateType.SINGLE.value,
        validation_method=ValidationMethod.HTTP_01.value, status=CertificateStatus.ACTIVE.value,
    )
    db.add(cert)
    db.flush()
    deployment = Deployment(certificate_id=cert.id, server_id=server.id, method="sftp",
                            status="success")
    execution = JobExecution(job_type=JobType.DEPLOY.value, certificate_id=cert.id, server_id=server.id,
                             status=JobStatus.SUCCESS.value)
    db.add_all([deployment, execution])
    db.commit()
    deployment_id, execution_id, server_id = deployment.id, execution.id, server.id

    delete_server(db, server_id)

    db.expire_all()
    assert db.query(Deployment).filter(Deployment.id == deployment_id).first() is None
    remaining_execution = db.query(JobExecution).filter(JobExecution.id == execution_id).first()
    assert remaining_execution is not None
    assert remaining_execution.server_id is None


def test_delete_server_api_requires_permission(client, role_headers_factory):
    from app.core.database import SessionLocal
    from app.services.server_service import create_server as _create

    db = SessionLocal()
    try:
        server = _create(db, {"hostname": "perm-check.example.com", "ssh_user": "root"})
        server_id = server.id
    finally:
        db.close()

    headers = role_headers_factory("srv_readonly", "read_only")
    resp = client.delete(f"/api/v1/servers/{server_id}", headers=headers)
    assert resp.status_code == 403


def test_delete_server_api_success(client, admin_headers):
    resp = client.post("/api/v1/servers", json={"hostname": "api-delete.example.com", "ssh_user": "root"},
                       headers=admin_headers)
    assert resp.status_code == 200, resp.text
    server_id = resp.json()["id"]

    resp = client.delete(f"/api/v1/servers/{server_id}", headers=admin_headers)
    assert resp.status_code == 200, resp.text

    resp = client.get("/api/v1/servers", headers=admin_headers)
    assert all(s["id"] != server_id for s in resp.json()["items"])
