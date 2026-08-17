"""Expiry warning thresholds: admin-configurable via Settings, not a
hardcoded/dead env var.

Regression coverage for two bugs found together: CERTMGR_EXPIRY_WARNING_DAYS
was documented and defined in Settings but never actually read anywhere —
the real logic used a hardcoded (60, 30, 15, 7, 3, 1) tuple requiring a
code change + redeploy to alter. And even once made configurable, a custom
threshold (e.g. 14) would silently never be delivered anywhere, since no
notification channel's `events` list could ever contain "expiry_14" — that
set was a hardcoded list in the frontend too."""

from __future__ import annotations

from datetime import timedelta

from conftest import _generate_self_signed

from app.core.timeutils import utcnow
from app.models.notification import Notification, NotificationSetting
from app.services.certificate_service import import_certificate
from app.services.settings_service import set_setting
from app.tasks.notifications import _DEFAULT_THRESHOLDS, _expiry_thresholds, expiry_warnings


def test_expiry_thresholds_default_when_unset(db):
    assert _expiry_thresholds(db) == _DEFAULT_THRESHOLDS


def test_expiry_thresholds_reads_custom_setting(db):
    set_setting(db, "notification.expiry_warning_days", "14,7,1")
    assert _expiry_thresholds(db) == (14, 7, 1)


def test_expiry_thresholds_falls_back_on_invalid_value(db):
    set_setting(db, "notification.expiry_warning_days", "not-a-number")
    assert _expiry_thresholds(db) == _DEFAULT_THRESHOLDS


def test_expiry_warnings_uses_custom_threshold_and_reaches_a_subscribed_channel(db):
    set_setting(db, "notification.expiry_warning_days", "14")
    db.add(NotificationSetting(channel="smtp", enabled=True, events=["expiry_14"]))

    _obj1, cert_pem1, key_pem1 = _generate_self_signed(["expiring-soon.example.com"])
    near = import_certificate(db, cert_data=cert_pem1, key_data=key_pem1)
    near.valid_until = utcnow() + timedelta(days=10)

    _obj2, cert_pem2, key_pem2 = _generate_self_signed(["expiring-later.example.com"])
    far = import_certificate(db, cert_data=cert_pem2, key_data=key_pem2)
    far.valid_until = utcnow() + timedelta(days=30)
    db.commit()
    near_id, far_id = near.id, far.id

    expiry_warnings()

    db.expire_all()
    notified_cert_ids = {
        n.related_certificate_id
        for n in db.query(Notification).filter(Notification.event_type == "expiry_14").all()
    }
    assert near_id in notified_cert_ids
    assert far_id not in notified_cert_ids


def test_expiry_warnings_does_not_duplicate_already_sent_notifications(db):
    set_setting(db, "notification.expiry_warning_days", "14")
    db.add(NotificationSetting(channel="smtp", enabled=True, events=["expiry_14"]))

    _obj, cert_pem, key_pem = _generate_self_signed(["repeat.example.com"])
    cert = import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    cert.valid_until = utcnow() + timedelta(days=10)
    db.commit()

    expiry_warnings()
    db.expire_all()
    first_count = db.query(Notification).filter(Notification.event_type == "expiry_14").count()
    assert first_count == 1

    # Mark it sent (queue_event_notifications() only queues; expiry_warnings()
    # dedupes on a prior notification with status "sent").
    sent = db.query(Notification).filter(Notification.event_type == "expiry_14").first()
    sent.status = "sent"
    db.commit()

    expiry_warnings()
    db.expire_all()
    second_count = db.query(Notification).filter(Notification.event_type == "expiry_14").count()
    assert second_count == 1
