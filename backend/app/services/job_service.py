"""Job execution records + retry orchestration."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.enums import JobStatus
from app.models.job import JobExecution

logger = get_logger(__name__)


def list_executions(db: Session, *, certificate_id: int | None = None,
                    job_type: str | None = None, status: str | None = None,
                    page: int = 1, page_size: int = 25) -> tuple[list[JobExecution], int]:
    q = db.query(JobExecution)
    if certificate_id:
        q = q.filter(JobExecution.certificate_id == certificate_id)
    if job_type:
        q = q.filter(JobExecution.job_type == job_type)
    if status:
        q = q.filter(JobExecution.status == status)
    total = q.count()
    rows = q.order_by(JobExecution.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total


def get_execution(db: Session, execution_id: int) -> JobExecution:
    row = db.query(JobExecution).filter(JobExecution.id == execution_id).first()
    if row is None:
        raise NotFoundError("Execution not found")
    return row


def retry_execution(db: Session, execution_id: int, *, user=None) -> JobExecution:
    from app.tasks.celery_app import run_job_async

    row = get_execution(db, execution_id)
    if row.job_type == "issue" and row.certificate_id:
        row.status = JobStatus.QUEUED.value
        row.retry_count = (row.retry_count or 0) + 1
        row.error_message = None
        db.commit()
        run_job_async.delay("issue", row.certificate_id, user.id if user else None, execution_id)
        return row
    if row.job_type == "renew" and row.certificate_id:
        from app.services.certificate_service import renew_certificate

        new_row = renew_certificate(db, row.certificate_id, force=True, user=user)
        return new_row
    if row.job_type == "deploy" and row.certificate_id and row.server_id:
        from app.services.deployment_service import deploy_certificate

        deploy_certificate(db, certificate_id=row.certificate_id, server_id=row.server_id,
                           user=user, execution_id=row.id)
        return get_execution(db, row.id)
    raise NotFoundError(f"Retry not supported for job type {row.job_type}")


def mark_running(db: Session, execution_id: int) -> JobExecution:
    row = get_execution(db, execution_id)
    row.status = JobStatus.RUNNING.value
    row.started_at = utcnow()
    db.commit()
    return row


def mark_done(db: Session, execution_id: int, *, success: bool, stdout: str = "",
              stderr: str = "", error: str | None = None) -> JobExecution:
    row = get_execution(db, execution_id)
    row.status = JobStatus.SUCCESS.value if success else JobStatus.FAILED.value
    row.stdout = (row.stdout or "") + stdout
    row.stderr = (row.stderr or "") + stderr
    row.error_message = error
    row.finished_at = utcnow()
    db.commit()
    return row
