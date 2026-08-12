"""Notification settings + history API."""


from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import AuditResult, NotificationChannel, NotificationEvent
from app.models.notification import Notification, NotificationSetting
from app.services import notification_service
from app.services.audit_service import record

logger = get_logger(__name__)
router = APIRouter(prefix="/notifications", tags=["Notifications"])


class ChannelConfig(BaseModel):
    channel: str
    name: str = ""
    enabled: bool = False
    events: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


@router.get("/settings")
def list_settings(db: DbSession, user: CurrentUser):
    rows = db.query(NotificationSetting).all()
    return [
        {
            "channel": r.channel, "name": r.name, "enabled": r.enabled,
            "events": r.events or [], "configured": bool(r.config_encrypted),
        }
        for r in rows
    ]


@router.get("/events")
def list_events(db: DbSession, user: CurrentUser):
    return {"events": NotificationEvent.values()}


@router.put("/settings/{channel}")
def update_settings(channel: str, body: ChannelConfig, db: DbSession, user: CurrentUser,
                    request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage notifications")
    if channel not in NotificationChannel.values():
        raise NotFoundError(f"Unknown channel: {channel}")
    row = notification_service.save_channel_config(
        db, channel, body.config, body.events, body.enabled, body.name
    )
    record(db, action="notification.settings.update", user_id=user.id, username=user.username,
           resource_type="notification", resource_id=row.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={"channel": channel})
    return {"channel": channel, "enabled": row.enabled, "events": row.events or []}


@router.post("/settings/{channel}/test")
def test_channel(channel: str, db: DbSession, user: CurrentUser, request: Request):
    result = notification_service.send_test(db, channel)
    record(db, action="notification.test", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS if result.success else AuditResult.FAILURE,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={"channel": channel, "error": result.error})
    return {"channel": channel, "success": result.success, "error": result.error}


@router.get("")
def list_notifications(db: DbSession, user: CurrentUser, status: str | None = None,
                       event_type: str | None = None, page: int = Query(1, ge=1),
                       page_size: int = Query(25, ge=1, le=200)):
    q = db.query(Notification)
    if status:
        q = q.filter(Notification.status == status)
    if event_type:
        q = q.filter(Notification.event_type == event_type)
    total = q.count()
    rows = q.order_by(Notification.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [
            {
                "id": n.id, "event_type": n.event_type, "channel": n.channel,
                "recipients": n.recipients or [], "subject": n.subject,
                "status": n.status, "error": n.error, "retries": n.retries,
                "sent_at": n.sent_at.isoformat() if n.sent_at else None,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in rows
        ],
        "total": total, "page": page, "page_size": page_size,
    }


@router.post("/{notification_id}/retry")
def retry_notification(notification_id: int, db: DbSession, user: CurrentUser):
    from app.tasks.notifications import deliver_notification

    if settings.celery_task_always_eager:
        result = notification_service.deliver(db, notification_id)
        return {"notification_id": notification_id, "success": result.success}
    deliver_notification.delay(notification_id)
    return {"notification_id": notification_id, "status": "queued"}
