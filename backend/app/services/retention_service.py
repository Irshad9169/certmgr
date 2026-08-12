"""Data retention — bounded DB growth.

The certificate metadata itself is tiny (≈700 B/row); the database grows
because of history tables:
  * job_executions  — certbot/deploy stdout+stderr per run
  * audit_logs      — every audited action
  * notifications   — queued/delivered notification bodies

This service purges rows older than a configurable number of days
(CERTMGR_EXECUTION_RETENTION_DAYS / CERTMGR_AUDIT_RETENTION_DAYS /
CERTMGR_NOTIFICATION_RETENTION_DAYS). 0 = keep forever. Deletes are plain SQL
(no row-by-row ORM loads) so purge stays fast even on large tables.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.audit import AuditLog
from app.models.job import JobExecution
from app.models.notification import Notification

logger = get_logger(__name__)


def _cutoff(days: int):
    return utcnow() - timedelta(days=days)


def _count_old(db: Session, model, created_col, days: int) -> int:
    return (
        db.query(func.count(model.id))
        .filter(created_col < _cutoff(days))
        .scalar()
        or 0
    )


def _purge(db: Session, model, created_col, days: int) -> int:
    """Bulk-delete rows older than `days`. Returns deleted count."""
    return db.query(model).filter(created_col < _cutoff(days)).delete(
        synchronize_session=False
    )


def apply_retention(
    db: Session,
    *,
    execution_days: int | None = None,
    audit_days: int | None = None,
    notification_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    """Purge history per configured retention. Overrides fall back to settings.

    `dry_run=True` reports how many rows WOULD be purged without deleting.
    """
    ed = settings.execution_retention_days if execution_days is None else execution_days
    ad = settings.audit_retention_days if audit_days is None else audit_days
    nd = settings.notification_retention_days if notification_days is None else notification_days

    result = {
        "dry_run": dry_run,
        "execution_retention_days": ed,
        "audit_retention_days": ad,
        "notification_retention_days": nd,
        "executions_purged": 0,
        "audit_purged": 0,
        "notifications_purged": 0,
    }

    def _apply(model, created_col, days: int, key: str) -> None:
        if days and days > 0:
            if dry_run:
                result[key] = _count_old(db, model, created_col, days)
            else:
                result[key] = _purge(db, model, created_col, days)

    _apply(JobExecution, JobExecution.created_at, ed, "executions_purged")
    _apply(AuditLog, AuditLog.created_at, ad, "audit_purged")
    _apply(Notification, Notification.created_at, nd, "notifications_purged")

    db.commit()

    if dry_run:
        logger.info(
            "Retention dry-run: would purge %s executions, %s audit, %s notifications",
            result["executions_purged"], result["audit_purged"], result["notifications_purged"],
            extra={"event": "retention_dry_run", **result},
        )
    else:
        logger.info(
            "Retention applied: purged %s executions, %s audit, %s notifications",
            result["executions_purged"], result["audit_purged"], result["notifications_purged"],
            extra={"event": "retention", **result},
        )
    return result


def retention_status(db: Session) -> dict:
    """Configured retention + current row counts (for the admin API)."""
    return {
        "execution_retention_days": settings.execution_retention_days,
        "audit_retention_days": settings.audit_retention_days,
        "notification_retention_days": settings.notification_retention_days,
        "current_rows": {
            "job_executions": db.query(func.count(JobExecution.id)).scalar() or 0,
            "audit_logs": db.query(func.count(AuditLog.id)).scalar() or 0,
            "notifications": db.query(func.count(Notification.id)).scalar() or 0,
        },
    }
