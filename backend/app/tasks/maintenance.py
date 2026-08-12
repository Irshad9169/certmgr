"""Maintenance tasks: health scans, compliance, backups, verification, cleanup."""

from __future__ import annotations

from app.core.logging import get_logger
from app.tasks.base import db_task
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.maintenance.health_scan")
@db_task
def health_scan(db) -> dict:
    from app.services.health_service import scan_all

    return scan_all(db)


@celery_app.task(name="app.tasks.maintenance.compliance_report")
@db_task
def compliance_report(db) -> dict:
    from app.services.compliance_service import run_compliance_report

    report = run_compliance_report(db)
    return {"report_id": report.id, "summary": report.summary}


@celery_app.task(name="app.tasks.maintenance.run_backup")
@db_task
def run_backup(db) -> dict:
    from app.services.backup_service import backup_all

    result = backup_all(db)
    return result


@celery_app.task(name="app.tasks.maintenance.weekly_verification")
@db_task
def weekly_verification(db) -> dict:
    from app.core.timeutils import utcnow
    from app.models.certificate import Certificate
    from app.models.enums import JobStatus, JobTrigger, JobType
    from app.models.job import JobExecution
    from app.services.providers.registry import get_registry

    verified = failed = 0
    for cert in db.query(Certificate).filter(Certificate.status == "active").all():
        try:
            provider = get_registry().create(cert.provider_name)
            ok, msg = provider.verify(cert.cert_path, [cert.domain] + [d for d in cert.sans if d != cert.domain])
            if ok:
                verified += 1
            else:
                failed += 1
        except Exception:  # noqa: BLE001
            failed += 1
    db.add(JobExecution(
        job_type=JobType.VERIFY.value, trigger=JobTrigger.SCHEDULER.value,
        status=JobStatus.SUCCESS.value, started_at=utcnow(), finished_at=utcnow(),
        stdout=f"verified={verified} failed={failed}",
    ))
    db.commit()
    return {"verified": verified, "failed": failed}


@celery_app.task(name="app.tasks.maintenance.cleanup_backups")
@db_task
def cleanup_backups(db) -> dict:
    from app.services.backup_service import cleanup_old_backups

    removed = cleanup_old_backups(db)
    return {"removed": removed}


@celery_app.task(name="app.tasks.maintenance.verify_backups")
@db_task
def verify_backups(db) -> dict:
    from app.services.backup_service import verify_backup_archives

    return verify_backup_archives(db)


@celery_app.task(name="app.tasks.maintenance.apply_retention")
@db_task
def apply_retention(db) -> dict:
    """Daily data-retention purge (execution history / audit / notifications)."""
    from app.services.retention_service import apply_retention

    return apply_retention(db)
