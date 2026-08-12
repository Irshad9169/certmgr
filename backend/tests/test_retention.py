"""Data-retention tests: bounded DB growth via configurable purge."""

from __future__ import annotations

from datetime import timedelta

from app.core.timeutils import utcnow
from app.models.audit import AuditLog
from app.models.job import JobExecution
from app.models.notification import Notification
from app.services.retention_service import apply_retention, retention_status


def _old(model, days, **kw) -> object:
    return model(created_at=utcnow() - timedelta(days=days), **kw)


def test_purges_old_executions_keeps_recent(db):
    db.add_all([
        _old(JobExecution, 400, job_type="renew", status="success"),
        _old(JobExecution, 10, job_type="issue", status="success"),
    ])
    db.commit()

    result = apply_retention(db, execution_days=365, audit_days=0, notification_days=0)

    assert result["executions_purged"] == 1
    remaining = db.query(JobExecution).all()
    assert len(remaining) == 1
    assert remaining[0].job_type == "issue"  # the recent one


def test_purges_audit_and_notifications(db):
    db.add_all([
        _old(AuditLog, 800, action="auth.login"),
        _old(AuditLog, 5, action="certificate.issue"),
        _old(Notification, 400, event_type="expiry_30", channel="smtp"),
        _old(Notification, 2, event_type="issued", channel="smtp"),
    ])
    db.commit()

    result = apply_retention(
        db, execution_days=0, audit_days=730, notification_days=365,
    )

    assert result["audit_purged"] == 1
    assert result["notifications_purged"] == 1
    assert db.query(AuditLog).count() == 1
    assert db.query(Notification).count() == 1
    assert db.query(AuditLog).first().action == "certificate.issue"


def test_dry_run_counts_without_deleting(db):
    db.add(_old(JobExecution, 500, job_type="deploy", status="success"))
    db.commit()

    result = apply_retention(db, execution_days=365, dry_run=True)

    assert result["dry_run"] is True
    assert result["executions_purged"] == 1
    assert db.query(JobExecution).count() == 1  # nothing deleted


def test_zero_days_keeps_everything(db):
    db.add_all([
        _old(JobExecution, 5000, job_type="issue", status="success"),
        _old(AuditLog, 5000, action="auth.login"),
        _old(Notification, 5000, event_type="issued", channel="smtp"),
    ])
    db.commit()

    result = apply_retention(db, execution_days=0, audit_days=0, notification_days=0)

    assert result["executions_purged"] == 0
    assert result["audit_purged"] == 0
    assert result["notifications_purged"] == 0
    assert db.query(JobExecution).count() == 1
    assert db.query(AuditLog).count() == 1
    assert db.query(Notification).count() == 1


def test_negative_days_keeps_everything(db):
    db.add(_old(JobExecution, 999, job_type="issue", status="success"))
    db.commit()
    result = apply_retention(db, execution_days=-1)
    assert result["executions_purged"] == 0
    assert db.query(JobExecution).count() == 1


def test_defaults_come_from_settings(db):
    from app.core.config import settings

    db.add(_old(JobExecution, 1000, job_type="issue", status="success"))
    db.commit()
    result = apply_retention(db)  # no overrides → settings values
    assert result["execution_retention_days"] == settings.execution_retention_days
    assert result["audit_retention_days"] == settings.audit_retention_days
    # settings default 365 → the 1000-day-old row is purged
    assert result["executions_purged"] == 1


def test_retention_status_reports_counts(db):
    db.add_all([
        _old(JobExecution, 100, job_type="issue", status="success"),
        _old(AuditLog, 100, action="auth.login"),
    ])
    db.commit()
    status = retention_status(db)
    assert status["execution_retention_days"] > 0
    assert status["current_rows"]["job_executions"] == 1
    assert status["current_rows"]["audit_logs"] == 1
