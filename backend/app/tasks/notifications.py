"""Notification + webhook delivery tasks, expiry warnings, daily summary."""

from __future__ import annotations

from datetime import timedelta

from app.core.logging import get_logger
from app.core.timeutils import days_until, utcnow
from app.models.certificate import Certificate
from app.models.notification import Notification
from app.tasks.base import db_task
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

_THRESHOLDS = (60, 30, 15, 7, 3, 1)


@celery_app.task(name="app.tasks.notifications.deliver")
@db_task
def deliver_notification(db, notification_id: int) -> dict:
    from app.services.notification_service import deliver

    result = deliver(db, notification_id)
    return {"notification_id": notification_id, "success": result.success, "error": result.error}


@celery_app.task(name="app.tasks.notifications.deliver_webhook")
@db_task
def deliver_webhook(db, delivery_id: int) -> dict:
    from app.services.webhook_service import send_delivery

    return send_delivery(db, delivery_id)


@celery_app.task(name="app.tasks.notifications.expiry_warnings")
@db_task
def expiry_warnings(db) -> dict:
    """Emit expiry notifications for certs crossing each threshold (once)."""
    from app.services.notification_service import queue_event_notifications

    sent = 0
    for cert in db.query(Certificate).filter(Certificate.valid_until.isnot(None)).all():
        days = days_until(cert.valid_until)
        if days is None or days < 0:
            continue
        for threshold in _THRESHOLDS:
            if days <= threshold:
                event = f"expiry_{threshold}"
                # only queue if no prior notification for this cert+event
                already = (
                    db.query(Notification)
                    .filter(Notification.event_type == event,
                            Notification.related_certificate_id == cert.id,
                            Notification.status == "sent")
                    .first()
                )
                if already is None:
                    queue_event_notifications(db, event, cert)
                    sent += 1
                break
    db.commit()
    return {"queued": sent}


@celery_app.task(name="app.tasks.notifications.daily_summary")
@db_task
def daily_summary(db) -> dict:
    from app.services.notification_service import (
        NotificationSetting,
    )

    total = db.query(Certificate).count()
    expiring_30 = (
        db.query(Certificate)
        .filter(Certificate.valid_until.isnot(None),
                Certificate.valid_until <= utcnow() + timedelta(days=30))
        .count()
    )
    failed_24h = (
        db.query(Notification)
        .filter(Notification.status == "failed",
                Notification.created_at >= utcnow() - timedelta(hours=24))
        .count()
    )
    channels = db.query(NotificationSetting).filter(NotificationSetting.enabled.is_(True)).all()
    if not channels:
        return {"summary_sent": False, "reason": "no channels enabled"}
    row = Notification(
        event_type="daily_summary",
        channel=channels[0].channel,
        recipients=[],
        subject=f"[CertMgr] Daily summary: {total} certificates, {expiring_30} expiring ≤30d",
        body=f"Total certificates: {total}\nExpiring within 30 days: {expiring_30}\n"
             f"Failed notifications (24h): {failed_24h}\n",
        status="queued",
    )
    db.add(row)
    db.commit()
    # deliver inline for the first channel
    from app.services.notification_service import deliver

    result = deliver(db, row.id)
    return {"summary_sent": result.success}
