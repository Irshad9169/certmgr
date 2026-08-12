"""Audit logging — every significant action is recorded immutably."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger, redact_dict
from app.models.audit import AuditLog
from app.models.enums import AuditResult

logger = get_logger(__name__)

_BROWSER_PATTERNS = [
    ("Chrome", "Chrome/"),
    ("Firefox", "Firefox/"),
    ("Safari", "Safari/"),
    ("Edge", "Edg/"),
    ("Opera", "OPR/"),
    ("curl", "curl/"),
    ("python", "python-requests"),
    ("Unknown", ""),
]


def _browser(user_agent: str) -> str:
    ua = user_agent or ""
    for name, marker in _BROWSER_PATTERNS:
        if marker and marker.lower() in ua.lower():
            return name
    return "Unknown"


def _device(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "mobile"
    if "tablet" in ua or "ipad" in ua:
        return "tablet"
    return "desktop"


def record(
    db: Session,
    *,
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    result: AuditResult | str = AuditResult.SUCCESS,
    ip_address: str | None = None,
    user_agent: str | None = None,
    duration_ms: int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        result=str(result),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:500],
        browser=_browser(user_agent),
        device=_device(user_agent),
        duration_ms=duration_ms,
        details=redact_dict(details or {}),
    )
    db.add(entry)
    db.flush()
    logger.info(
        "AUDIT %s %s %s",
        action,
        resource_type or "",
        resource_id or "",
        extra={"event": "audit", "action": action, "resource": f"{resource_type}:{resource_id}",
               "result": str(result)},
    )
    return entry


def query_audit(
    db: Session,
    *,
    user: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    result: str | None = None,
    date_from=None,
    date_to=None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    q = db.query(AuditLog)
    if user:
        q = q.filter(AuditLog.username == user)
    if action:
        q = q.filter(AuditLog.action == action)
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    if result:
        q = q.filter(AuditLog.result == result)
    if date_from:
        q = q.filter(AuditLog.created_at >= date_from)
    if date_to:
        q = q.filter(AuditLog.created_at <= date_to)
    total = q.count()
    rows = q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return rows, total
