"""Celery application + beat schedule.

Workers execute issuance, renewal, deployment, notifications, discovery,
health, compliance, backup and cleanup. Tasks are idempotent and respect
maintenance mode.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

celery_app = Celery(
    "certmgr",
    broker=settings.celery_broker,
    backend=settings.celery_backend,
    include=[
        "app.tasks.certificates",
        "app.tasks.deployments",
        "app.tasks.notifications",
        "app.tasks.discovery",
        "app.tasks.maintenance",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_time_limit=settings.certbot_timeout_seconds + 120,
    task_soft_time_limit=settings.certbot_timeout_seconds,
    worker_max_tasks_per_child=200,
    result_expires=86400,
    task_default_retry_delay=60,
    task_max_retries=settings.renewal_retry_max,
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=True,
)

celery_app.conf.beat_schedule = {
    "daily-renewal-scan": {
        "task": "app.tasks.certificates.renew_due",
        "schedule": crontab(hour=3, minute=0),  # CERTMGR_RENEWAL_CRON used by scheduler service
    },
    "daily-discovery": {
        "task": "app.tasks.discovery.run_discovery",
        "schedule": crontab(hour=2, minute=30),
    },
    "hourly-health-scan": {
        "task": "app.tasks.maintenance.health_scan",
        "schedule": crontab(hour="*/4", minute=0),
    },
    "daily-backup": {
        "task": "app.tasks.maintenance.run_backup",
        "schedule": crontab(hour=1, minute=0),
    },
    "daily-compliance-report": {
        "task": "app.tasks.maintenance.compliance_report",
        "schedule": crontab(hour=4, minute=30),
    },
    "expiry-warnings": {
        "task": "app.tasks.notifications.expiry_warnings",
        "schedule": crontab(hour=6, minute=0),
    },
    "daily-summary": {
        "task": "app.tasks.notifications.daily_summary",
        "schedule": crontab(hour=7, minute=0),
    },
    "weekly-verification": {
        "task": "app.tasks.maintenance.weekly_verification",
        "schedule": crontab(day_of_week=0, hour=5, minute=0),
    },
    "cleanup-old-backups": {
        "task": "app.tasks.maintenance.cleanup_backups",
        "schedule": crontab(day_of_week=6, hour=5, minute=30),
    },
    "weekly-backup-verification": {
        "task": "app.tasks.maintenance.verify_backups",
        "schedule": crontab(day_of_week=0, hour=2, minute=30),
    },
    "daily-retention": {
        "task": "app.tasks.maintenance.apply_retention",
        "schedule": crontab(hour=4, minute=0),
    },
}


# ── Async dispatch helpers used by the API layer ────────────────────────────

def run_bulk_async(action: str, certificate_id: int, user_id: int | None,
                   options: dict | None = None) -> None:
    from app.tasks.certificates import bulk_operation

    bulk_operation.delay(action, certificate_id, user_id, options or {})


def run_job_async(job_type: str, certificate_id: int, user_id: int | None,
                  execution_id: int | None = None) -> None:
    from app.tasks.certificates import run_job

    run_job.delay(job_type, certificate_id, user_id, execution_id)


def deliver_webhooks_async(delivery_id: int) -> None:
    from app.tasks.notifications import deliver_webhook

    deliver_webhook.delay(delivery_id)


def enqueue_deploy(certificate_id: int, server_id: int, template_id: int | None,
                   target_service: str | None, method: str, user_id: int | None,
                   execution_id: int | None = None) -> None:
    from app.tasks.deployments import deploy_task

    deploy_task.delay(certificate_id, server_id, template_id, target_service, method, user_id, execution_id)
