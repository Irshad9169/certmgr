"""Admin settings API (key/value, secrets masked)."""


from typing import Any

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger
from app.models.enums import AuditResult
from app.services import settings_service
from app.services.audit_service import record

logger = get_logger(__name__)
router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("")
def get_settings(db: DbSession, user: CurrentUser):
    return {"settings": settings_service.get_all_settings(db)}


@router.put("/{key}")
def set_setting(key: str, body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can change settings")
    try:
        row = settings_service.set_setting(
            db, key, body.get("value"), updated_by=user.id,
            is_secret=body.get("is_secret"),
        )
    except ValueError as exc:
        raise ValidationAppError(str(exc)) from exc
    record(db, action="settings.update", user_id=user.id, username=user.username,
           resource_type="setting", resource_id=key, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={"key": key, "is_secret": row.is_secret})
    return {"key": key, "updated": True, "is_secret": row.is_secret}


@router.get("/secrets/{key}")
def get_secret_metadata(key: str, db: DbSession, user: CurrentUser):
    """Return whether a secret setting is configured (never its value)."""
    from app.models.settings import AppSetting

    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can inspect secret settings")
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    return {"key": key, "configured": bool(row and row.value)}


# ── Data retention ──────────────────────────────────────────────────────────
@router.get("/retention")
def retention_status(db: DbSession, user: CurrentUser):
    """Configured retention days + current history row counts (admin)."""
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can view retention settings")
    from app.services.retention_service import retention_status

    return retention_status(db)


@router.post("/retention/run")
def run_retention(body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    """Run the data-retention purge now (admin, audited). `dry_run: true` previews."""
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can run retention")
    from app.services.retention_service import apply_retention

    dry_run = bool(body.get("dry_run", False))
    result = apply_retention(db, dry_run=dry_run)
    record(db, action="maintenance.retention", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request),
           details={"dry_run": dry_run, **{k: v for k, v in result.items() if k.endswith("_purged") or k.endswith("_days")}})
    return result


# ── Maintenance mode ────────────────────────────────────────────────────────
@router.get("/maintenance")
def maintenance_status(db: DbSession, user: CurrentUser):
    from app.services.maintenance_service import get_status

    return get_status(db)


@router.put("/maintenance")
def set_maintenance(body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can toggle maintenance mode")
    from datetime import datetime

    from app.services.maintenance_service import set_maintenance as _set

    scheduled_end = None
    if body.get("scheduled_end"):
        try:
            scheduled_end = datetime.fromisoformat(body["scheduled_end"])
        except ValueError as exc:
            raise ValidationAppError("scheduled_end must be ISO-8601") from exc
    status = _set(
        db, active=bool(body.get("active")), reason=body.get("reason"),
        scheduled_end=scheduled_end, pauses=body.get("pauses"),
        created_by=user.id,
    )
    record(db, action="maintenance.set", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"active": body.get("active")})
    return status
