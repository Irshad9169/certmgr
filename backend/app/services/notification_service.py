"""Notifications: SMTP, Slack, Microsoft Teams, generic webhooks.

Delivery happens in Celery workers (notification.deliver); the API only queues.
"""

from __future__ import annotations

import html
import json
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger, redact
from app.core.security import decrypt_secret
from app.core.timeutils import utcnow
from app.models.enums import NotificationEvent
from app.models.notification import Notification, NotificationSetting

logger = get_logger(__name__)


@dataclass
class DeliveryResult:
    success: bool
    error: str | None = None


def get_channel_config(db: Session, channel: str) -> dict[str, Any] | None:
    row = db.query(NotificationSetting).filter(NotificationSetting.channel == channel).first()
    if row is None or not row.enabled:
        return None
    if not row.config_encrypted:
        return {}
    try:
        return json.loads(decrypt_secret(row.config_encrypted))
    except Exception:  # noqa: BLE001
        logger.error("Cannot decrypt config for notification channel %s", channel)
        return None


def save_channel_config(db: Session, channel: str, config: dict[str, Any],
                        events: list[str], enabled: bool, name: str) -> NotificationSetting:
    from app.core.security import encrypt_secret

    row = db.query(NotificationSetting).filter(NotificationSetting.channel == channel).first()
    if row is None:
        row = NotificationSetting(channel=channel, name=name)
        db.add(row)
    row.name = name
    row.enabled = enabled
    row.events = events
    row.config_encrypted = encrypt_secret(json.dumps(config))
    db.commit()
    db.refresh(row)
    return row


# ── Queueing ────────────────────────────────────────────────────────────────

_EVENT_LABELS = {
    NotificationEvent.EXPIRY_60.value: "expires in 60 days",
    NotificationEvent.EXPIRY_30.value: "expires in 30 days",
    NotificationEvent.EXPIRY_15.value: "expires in 15 days",
    NotificationEvent.EXPIRY_7.value: "expires in 7 days",
    NotificationEvent.EXPIRY_3.value: "expires in 3 days",
    NotificationEvent.EXPIRY_1.value: "expires tomorrow",
    NotificationEvent.ISSUED.value: "issued",
    NotificationEvent.RENEWED.value: "renewed",
    NotificationEvent.FAILURE.value: "operation failed",
    NotificationEvent.DEPLOYED.value: "deployed",
    NotificationEvent.REVOKED.value: "revoked",
    NotificationEvent.IMPORTED.value: "imported",
    NotificationEvent.EXPIRED.value: "expired",
}


def queue_event_notifications(db: Session, event: str, cert=None,
                              extra: dict[str, Any] | None = None) -> list[Notification]:
    """Queue rows for every enabled channel subscribed to `event`."""
    created: list[Notification] = []
    channels = db.query(NotificationSetting).filter(NotificationSetting.enabled.is_(True)).all()
    for ch in channels:
        if event not in (ch.events or []):
            continue
        subject, body = _render(event, cert, extra)
        recipients = _recipients_for(channel=ch.channel, config=json.loads(decrypt_secret(ch.config_encrypted))) if ch.config_encrypted else []
        row = Notification(
            event_type=event,
            channel=ch.channel,
            recipients=recipients,
            subject=subject,
            body=body,
            related_certificate_id=cert.id if cert else None,
        )
        db.add(row)
        created.append(row)
    if created:
        db.flush()
    return created


def _recipients_for(channel: str, config: dict) -> list[str]:
    if channel == "smtp":
        return config.get("recipients", [])
    if channel == "slack":
        return [config.get("channel", "#certmgr")]
    if channel == "teams":
        return [config.get("webhook_url", "")]
    if channel == "webhook":
        return [config.get("url", "")]
    return []


def _render(event: str, cert, extra: dict | None) -> tuple[str, str]:
    label = _EVENT_LABELS.get(event, event)
    domain = cert.domain if cert else (extra or {}).get("domain", "n/a")
    subject = f"[CertMgr] Certificate {label}: {domain}"
    lines = [
        f"Certificate: {domain}",
        f"Event: {event}",
    ]
    if cert:
        if cert.valid_until:
            lines.append(f"Expires: {cert.valid_until.isoformat()}")
        if cert.issuer:
            lines.append(f"Issuer: {cert.issuer}")
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    return subject, "\n".join(lines)


# ── Delivery (worker-side) ──────────────────────────────────────────────────

def deliver(db: Session, notification_id: int) -> DeliveryResult:
    row = db.query(Notification).filter(Notification.id == notification_id).first()
    if row is None:
        return DeliveryResult(False, "Notification not found")
    if row.status == "sent":
        return DeliveryResult(True)
    config = get_channel_config(db, row.channel) or {}
    result = _deliver_channel(row, config)
    row.status = "sent" if result.success else "failed"
    row.sent_at = utcnow() if result.success else None
    row.error = result.error
    row.retries = (row.retries or 0) + 1
    db.commit()
    return result


def _deliver_channel(row: Notification, config: dict) -> DeliveryResult:
    if row.channel == "smtp":
        return _deliver_smtp(row, config)
    if row.channel == "slack":
        return _deliver_slack(row, config)
    if row.channel == "teams":
        return _deliver_teams(row, config)
    if row.channel == "webhook":
        return _deliver_webhook(row, config)
    return DeliveryResult(False, f"Unknown channel {row.channel}")


def _deliver_smtp(row: Notification, config: dict) -> DeliveryResult:
    try:
        host = config.get("host", settings.smtp_host)
        port = int(config.get("port", settings.smtp_port))
        username = config.get("username", settings.smtp_username)
        password = config.get("password", settings.smtp_password)
        use_tls = bool(config.get("use_tls", settings.smtp_use_tls))
        from_addr = config.get("from", settings.smtp_from)
        from_name = config.get("from_name", settings.smtp_from_name)

        msg = EmailMessage()
        msg["Subject"] = row.subject or "CertMgr notification"
        msg["From"] = formataddr((from_name, from_addr))
        msg["To"] = ", ".join(row.recipients or [])
        msg.set_content(row.body or "")

        with smtplib.SMTP(host, port, timeout=30) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        return DeliveryResult(True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SMTP delivery failed: %s", redact(str(exc)))
        return DeliveryResult(False, str(exc))


def _deliver_slack(row: Notification, config: dict) -> DeliveryResult:
    url = config.get("webhook_url")
    if not url:
        return DeliveryResult(False, "Slack webhook URL not configured")
    payload = {"text": f"*{row.subject}*\n```{row.body}```"}
    try:
        resp = httpx.post(url, json=payload, timeout=15)
        return DeliveryResult(resp.is_success, None if resp.is_success else f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        return DeliveryResult(False, str(exc))


def _deliver_teams(row: Notification, config: dict) -> DeliveryResult:
    url = config.get("webhook_url")
    if not url:
        return DeliveryResult(False, "Teams webhook URL not configured")
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": row.subject or "CertMgr notification",
        "title": row.subject or "CertMgr notification",
        "text": html.escape(row.body or "").replace("\n", "<br/>"),
    }
    try:
        resp = httpx.post(url, json=payload, timeout=15)
        return DeliveryResult(resp.is_success, None if resp.is_success else f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        return DeliveryResult(False, str(exc))


def _deliver_webhook(row: Notification, config: dict) -> DeliveryResult:
    url = config.get("url")
    if not url:
        return DeliveryResult(False, "Webhook URL not configured")
    payload = {"event": row.event_type, "subject": row.subject, "body": row.body}
    try:
        resp = httpx.post(url, json=payload, timeout=15)
        return DeliveryResult(resp.is_success, None if resp.is_success else f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        return DeliveryResult(False, str(exc))


def send_test(db: Session, channel: str) -> DeliveryResult:
    config = get_channel_config(db, channel)
    if config is None:
        return DeliveryResult(False, f"Channel '{channel}' is not enabled")
    row = Notification(
        event_type="test",
        channel=channel,
        recipients=_recipients_for(channel, config),
        subject="[CertMgr] Test notification",
        body="This is a test notification from CertMgr.",
        status="queued",
    )
    db.add(row)
    db.commit()
    return _deliver_channel(row, config)
