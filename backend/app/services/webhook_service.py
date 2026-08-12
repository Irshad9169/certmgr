"""Outbound webhooks with HMAC-SHA256 signatures and delivery history."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import decrypt_secret
from app.models.notification import WebhookDelivery, WebhookEndpoint

logger = get_logger(__name__)

WEBHOOK_EVENTS = [
    "certificate.issued", "certificate.renewed", "certificate.expired",
    "certificate.revoked", "certificate.imported", "deployment.completed",
    "deployment.failed", "renewal.failed",
]


def dispatch(db: Session, event: str, payload: dict[str, Any]) -> None:
    """Queue deliveries for all endpoints subscribed to `event` (worker sends)."""
    from app.tasks.celery_app import deliver_webhooks_async

    endpoints = (
        db.query(WebhookEndpoint)
        .filter(WebhookEndpoint.is_active.is_(True))
        .all()
    )
    for ep in endpoints:
        if event in (ep.events or []):
            delivery = WebhookDelivery(
                endpoint_id=ep.id,
                event=event,
                payload=payload,
                status="pending",
            )
            db.add(delivery)
            db.flush()
            if settings.celery_task_always_eager:
                send_delivery(db, delivery.id)
            else:
                deliver_webhooks_async.delay(delivery.id)


def send_delivery(db: Session, delivery_id: int) -> dict[str, Any]:
    delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
    if delivery is None:
        return {"status": "failed", "error": "delivery not found"}
    endpoint = delivery.endpoint
    body = json.dumps(
        {"event": delivery.event, "payload": delivery.payload, "timestamp": int(time.time())},
        default=str,
    )
    secret = None
    if endpoint.secret_encrypted:
        secret = decrypt_secret(endpoint.secret_encrypted).encode()
    signature = (
        "sha256=" + hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
        if secret else None
    )
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CertMgr/1.0",
        "X-CertMgr-Event": delivery.event,
    }
    if signature:
        headers["X-CertMgr-Signature"] = signature

    try:
        resp = httpx.post(endpoint.url, content=body, headers=headers, timeout=15)
        delivery.status = "delivered" if resp.is_success else "failed"
        delivery.response_code = resp.status_code
        delivery.response_body = resp.text[:2000]
        if not resp.is_success:
            delivery.error = f"HTTP {resp.status_code}"
        endpoint.last_delivery_at = None
    except httpx.HTTPError as exc:
        delivery.status = "failed"
        delivery.error = str(exc)
    db.commit()
    return {"status": delivery.status, "code": delivery.response_code, "error": delivery.error}
