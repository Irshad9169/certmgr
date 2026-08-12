"""In-process APScheduler — syncs the `scheduled_jobs` table into APScheduler jobs.

Used when the API process runs with CERTMGR_RUN_SCHEDULER=1 (single-node mode).
In HA deployments, Celery beat is used instead so only one scheduler runs.
"""

from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.logging import get_logger

logger = get_logger(__name__)

_scheduler: BackgroundScheduler | None = None

# Maps ScheduledJob.job_type → Celery task name
_JOB_TYPE_TASK = {
    "discovery": "app.tasks.discovery.run_discovery",
    "renewal": "app.tasks.certificates.renew_due",
    "health": "app.tasks.maintenance.health_scan",
    "compliance": "app.tasks.maintenance.compliance_report",
    "backup": "app.tasks.maintenance.run_backup",
    "verification": "app.tasks.maintenance.weekly_verification",
    "notification": "app.tasks.notifications.expiry_warnings",
}


def _dispatch(job_type: str, config: dict | None = None) -> None:
    """Call the underlying service directly (no broker round-trip)."""
    from app.core.database import SessionLocal

    config = config or {}
    db = SessionLocal()
    try:
        if job_type == "discovery":
            from app.services.discovery_service import run_discovery

            run_discovery(db, extra_paths=config.get("paths"))
        elif job_type == "renewal":
            from app.models.enums import JobTrigger
            from app.services.certificate_service import due_certificates, renew_certificate

            for cert in due_certificates(db):
                renew_certificate(db, cert.id, force=False, trigger=JobTrigger.SCHEDULER.value)
        elif job_type == "health":
            from app.services.health_service import scan_all

            scan_all(db)
        elif job_type == "compliance":
            from app.services.compliance_service import run_compliance_report

            run_compliance_report(db)
        elif job_type == "backup":
            from app.services.backup_service import backup_all

            backup_all(db)
        elif job_type == "notification":
            from app.services.notification_service import expiry_warnings

            expiry_warnings(db)
        elif job_type == "retention":
            from app.services.retention_service import apply_retention

            apply_retention(db)
        else:
            logger.warning("No scheduler handler for job_type %s", job_type)
    except Exception as exc:  # noqa: BLE001
        logger.error("Scheduled job %s failed: %s", job_type, exc)
    finally:
        db.close()


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    from app.core.database import SessionLocal
    from app.models.job import ScheduledJob

    scheduler = BackgroundScheduler(timezone="UTC", daemon=True)
    scheduler.start()

    db = SessionLocal()
    try:
        rows = db.query(ScheduledJob).filter(ScheduledJob.enabled.is_(True)).all()
        for job in rows:
            try:
                trigger = _build_trigger(job.schedule_type, job.cron_expression, job.interval_seconds)
                if trigger is None:
                    continue
                scheduler.add_job(
                    _dispatch,
                    trigger=trigger,
                    args=[job.job_type, job.config or {}],
                    id=f"certmgr-{job.id}",
                    replace_existing=True,
                    max_instances=1,
                    coalesce=True,
                    misfire_grace_time=3600,
                )
                logger.info("Scheduled job '%s' registered", job.name)
            except Exception as exc:  # noqa: BLE001
                logger.error("Cannot register scheduled job %s: %s", job.name, exc)
    finally:
        db.close()

    _scheduler = scheduler
    return scheduler


def _build_trigger(schedule_type: str, cron: str | None, interval: int | None):
    try:
        if schedule_type == "cron" and cron:
            parts = cron.split()
            if len(parts) == 5:
                minute, hour, day, month, dow = parts
                return CronTrigger(
                    minute=minute, hour=hour, day=day, month=month, day_of_week=dow,
                    timezone="UTC",
                )
        if schedule_type == "interval" and interval:
            return IntervalTrigger(seconds=max(60, int(interval)))
    except Exception as exc:  # noqa: BLE001
        logger.error("Invalid schedule expression %s: %s", cron, exc)
    return None


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
