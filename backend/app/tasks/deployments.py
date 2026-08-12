"""Deployment tasks."""

from __future__ import annotations

from app.core.logging import get_logger
from app.tasks.base import db_task
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.deployments.deploy", bind=True, autoretry_for=(Exception,),
                 retry_backoff=True, max_retries=2)
@db_task
def deploy_task(db, self, certificate_id: int, server_id: int, template_id: int | None,
                target_service: str | None, method: str, user_id: int | None = None,
                execution_id: int | None = None) -> dict:
    from app.services.deployment_service import deploy_certificate

    deployment = deploy_certificate(
        db, certificate_id=certificate_id, server_id=server_id, template_id=template_id,
        target_service=target_service, method=method, trigger="api",
        execution_id=execution_id,
    )
    return {"deployment_id": deployment.id, "status": deployment.status}


@celery_app.task(name="app.tasks.deployments.rollback")
@db_task
def rollback_task(db, deployment_id: int) -> dict:
    from app.models.server import Deployment
    from app.services.deployment_service import _rollback

    deployment = db.query(Deployment).filter(Deployment.id == deployment_id).first()
    if deployment is None:
        return {"error": "deployment not found"}
    server = deployment.server
    _rollback(db, deployment, server, [])
    return {"deployment_id": deployment_id, "status": deployment.status}
