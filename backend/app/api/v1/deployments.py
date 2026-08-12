"""Deployment API: templates, deployment records, execute, rollback."""


from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.api.permissions import P_
from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.models.enums import AuditResult
from app.models.server import Deployment, DeploymentTemplate
from app.services import deployment_service
from app.services.audit_service import record
from app.services.maintenance_service import ensure_not_maintenance

router = APIRouter(prefix="/deployments", tags=["Deployments"])
DEPLOY = P_["cert"]["deploy"]


class DeployRequest(BaseModel):
    certificate_id: int
    server_id: int
    template_id: int | None = None
    target_service: str | None = Field(default=None, max_length=64)
    method: str = Field(default="sftp", pattern="^(ssh|scp|sftp|rsync)$")


class TemplateCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    target_type: str = Field(max_length=32)
    description: str | None = None
    pre_deploy_script: str = ""
    backup_script: str = ""
    deploy_script: str = ""
    post_deploy_script: str = ""
    reload_command: str | None = None
    verify_enabled: bool = True
    rollback_enabled: bool = True
    variables: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


@router.post("")
def deploy(
    body: DeployRequest, db: DbSession, user: CurrentUser, request: Request,
):
    ensure_not_maintenance(db, operation="deployment")
    if settings.celery_task_always_eager:
        deployment = deployment_service.deploy_certificate(
            db, certificate_id=body.certificate_id, server_id=body.server_id,
            template_id=body.template_id, target_service=body.target_service,
            method=body.method, user=user,
        )
        return _serialize_deployment(deployment)
    # Async path: create the record and enqueue
    deployment = deployment_service.create_deployment_record(
        db, certificate_id=body.certificate_id, server_id=body.server_id,
        template_id=body.template_id, target_service=body.target_service,
        method=body.method, user=user,
    )
    from app.tasks.celery_app import enqueue_deploy

    enqueue_deploy(body.certificate_id, body.server_id, body.template_id,
                   body.target_service, body.method, user.id)
    record(db, action="certificate.deploy", user_id=user.id, username=user.username,
           resource_type="certificate", resource_id=body.certificate_id,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request),
           details={"server_id": body.server_id, "method": body.method, "status": "queued"})
    return {"deployment_id": deployment.id, "status": "queued"}


@router.get("")
def list_deployments(db: DbSession, user: CurrentUser, certificate_id: int | None = None,
                     server_id: int | None = None, status: str | None = None,
                     page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    q = db.query(Deployment)
    if certificate_id:
        q = q.filter(Deployment.certificate_id == certificate_id)
    if server_id:
        q = q.filter(Deployment.server_id == server_id)
    if status:
        q = q.filter(Deployment.status == status)
    total = q.count()
    rows = q.order_by(Deployment.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_serialize_deployment(d) for d in rows], "total": total,
            "page": page, "page_size": page_size}


@router.get("/{deployment_id}")
def get_deployment(deployment_id: int, db: DbSession, user: CurrentUser):
    row = db.query(Deployment).filter(Deployment.id == deployment_id).first()
    if row is None:
        raise NotFoundError("Deployment not found")
    return _serialize_deployment(row)


@router.post("/{deployment_id}/rollback")
def rollback(deployment_id: int, db: DbSession, user: CurrentUser, request: Request):
    row = db.query(Deployment).filter(Deployment.id == deployment_id).first()
    if row is None:
        raise NotFoundError("Deployment not found")
    if settings.celery_task_always_eager:
        deployment_service._rollback(db, row, row.server, [])
        status = db.query(Deployment).filter(Deployment.id == deployment_id).first().status
    else:
        rollback_async.delay(deployment_id)
        status = "queued"
    record(db, action="deployment.rollback", user_id=user.id, username=user.username,
           resource_type="deployment", resource_id=deployment_id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return {"deployment_id": deployment_id, "status": status}


# ── Templates ───────────────────────────────────────────────────────────────
@router.get("/templates/list")
def list_templates(db: DbSession, user: CurrentUser):
    rows = db.query(DeploymentTemplate).order_by(DeploymentTemplate.target_type).all()
    return [_serialize_template(t) for t in rows]


@router.post("/templates")
def create_template(body: TemplateCreate, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage templates")
    tmpl = DeploymentTemplate(**body.model_dump(), created_by=user.id)
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)
    record(db, action="deployment.template.create", user_id=user.id, username=user.username,
           resource_type="deployment_template", resource_id=tmpl.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize_template(tmpl)


def _serialize_deployment(d: Deployment) -> dict[str, Any]:
    return {
        "id": d.id, "certificate_id": d.certificate_id, "server_id": d.server_id,
        "template_id": d.template_id, "method": d.method, "target_service": d.target_service,
        "remote_cert_path": d.remote_cert_path, "remote_key_path": d.remote_key_path,
        "remote_chain_path": d.remote_chain_path, "status": d.status,
        "backup_path": d.backup_path, "verification": d.verification,
        "error_message": d.error_message,
        "started_at": d.started_at.isoformat() if d.started_at else None,
        "finished_at": d.finished_at.isoformat() if d.finished_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "server_hostname": d.server.hostname if d.server else None,
        "certificate_domain": d.certificate.domain if d.certificate else None,
    }


def _serialize_template(t: DeploymentTemplate) -> dict[str, Any]:
    return {
        "id": t.id, "name": t.name, "target_type": t.target_type,
        "description": t.description, "verify_enabled": t.verify_enabled,
        "rollback_enabled": t.rollback_enabled, "variables": t.variables or {},
        "is_active": t.is_active,
        "pre_deploy_script": t.pre_deploy_script, "backup_script": t.backup_script,
        "deploy_script": t.deploy_script, "post_deploy_script": t.post_deploy_script,
        "reload_command": t.reload_command,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def rollback_async(deployment_id: int) -> None:
    from app.tasks.deployments import rollback_task

    rollback_task.delay(deployment_id)
