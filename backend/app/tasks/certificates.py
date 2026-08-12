"""Certificate lifecycle tasks (issue / renew / revoke / bulk)."""

from __future__ import annotations

from app.core.logging import get_logger
from app.models.enums import JobStatus, JobTrigger, JobType
from app.tasks.base import db_task
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.certificates.issue", bind=True, autoretry_for=(Exception,),
                 retry_backoff=True, retry_jitter=True, max_retries=2)
@db_task
def issue_task(db, self, certificate_id: int, user_id: int | None = None) -> dict:
    from app.services.certificate_service import _execute_issuance, get_certificate

    cert = get_certificate(db, certificate_id, load_relations=False)
    execution = _execute_issuance(db, cert, None, JobTrigger.API.value)
    return {"certificate_id": certificate_id, "status": execution.status}


@celery_app.task(name="app.tasks.certificates.renew_due")
@db_task
def renew_due(db) -> dict:
    """Find certificates expiring within the threshold and renew them."""
    from app.services.certificate_service import due_certificates, renew_certificate
    from app.services.maintenance_service import is_maintenance

    if is_maintenance(db):
        return {"renewed": 0, "skipped": "maintenance"}
    due = due_certificates(db)
    results = {"attempted": 0, "succeeded": 0, "failed": 0}
    for cert in due:
        try:
            execution = renew_certificate(db, cert.id, force=False, trigger=JobTrigger.SCHEDULER.value)
            results["attempted"] += 1
            if execution.status == JobStatus.SUCCESS.value:
                results["succeeded"] += 1
            else:
                results["failed"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Scheduled renewal failed for cert %s: %s", cert.id, exc)
            results["failed"] += 1
    logger.info("Renewal sweep complete: %s", results)
    return results


@celery_app.task(name="app.tasks.certificates.renew_one")
@db_task
def renew_one(db, certificate_id: int, user_id: int | None = None, force: bool = False) -> dict:
    from app.services.certificate_service import renew_certificate

    execution = renew_certificate(db, certificate_id, force=force,
                                  trigger=JobTrigger.API.value if user_id else JobTrigger.SCHEDULER.value)
    return {"certificate_id": certificate_id, "status": execution.status}


@celery_app.task(name="app.tasks.certificates.revoke")
@db_task
def revoke_task(db, certificate_id: int, reason: str = "unspecified", user_id: int | None = None) -> dict:
    from app.services.certificate_service import revoke_certificate

    execution = revoke_certificate(db, certificate_id, reason=reason)
    return {"certificate_id": certificate_id, "status": execution.status}


@celery_app.task(name="app.tasks.certificates.bulk_operation")
@db_task
def bulk_operation(db, action: str, certificate_id: int, user_id: int | None = None,
                   options: dict | None = None) -> dict:
    from app.services.certificate_service import _bulk_execute

    _bulk_execute(db, action, certificate_id, None, options or {})
    return {"action": action, "certificate_id": certificate_id}


@celery_app.task(name="app.tasks.certificates.run_job")
@db_task
def run_job(db, job_type: str, certificate_id: int, user_id: int | None = None,
            execution_id: int | None = None) -> dict:
    if job_type == JobType.ISSUE.value:
        return issue_task(certificate_id, user_id)
    if job_type == JobType.RENEW.value:
        return renew_one(certificate_id, user_id)
    if job_type == JobType.REVOKE.value:
        return revoke_task(certificate_id)
    raise ValueError(f"Unsupported job type: {job_type}")
