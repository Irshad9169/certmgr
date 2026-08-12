"""Audit log API."""


from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.services.audit_service import query_audit

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("")
def list_audit(
    db: DbSession,
    user: CurrentUser,
    username: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
    resource_type: str | None = Query(None, max_length=64),
    result: str | None = Query(None, max_length=16),
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    from datetime import datetime

    def _parse(dt: str):
        try:
            return datetime.fromisoformat(dt)
        except ValueError:
            return None

    rows, total = query_audit(
        db, user=username, action=action, resource_type=resource_type, result=result,
        date_from=_parse(date_from) if date_from else None,
        date_to=_parse(date_to) if date_to else None,
        limit=page_size, offset=(page - 1) * page_size,
    )
    return {
        "items": [
            {
                "id": a.id, "username": a.username, "action": a.action,
                "resource_type": a.resource_type, "resource_id": a.resource_id,
                "result": a.result, "ip_address": a.ip_address, "browser": a.browser,
                "device": a.device, "duration_ms": a.duration_ms,
                "details": a.details or {},
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in rows
        ],
        "total": total, "page": page, "page_size": page_size,
    }
