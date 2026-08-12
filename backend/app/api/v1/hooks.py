"""Hook management API (auth/cleanup/pre-post-deploy scripts)."""


from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.models.certificate import Hook
from app.models.enums import AuditResult, HookType
from app.services.audit_service import record
from app.services.command import assert_safe_script_path

logger = get_logger(__name__)
router = APIRouter(prefix="/hooks", tags=["Hooks"])


class HookCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    hook_type: str = Field(default="auth")
    script_path: str = Field(min_length=1, max_length=2048)
    env_vars: dict[str, str] = Field(default_factory=dict)
    execution_user: str | None = Field(default=None, max_length=64)
    working_directory: str | None = Field(default=None, max_length=1024)
    timeout_seconds: int = Field(default=300, ge=10, le=3600)
    is_active: bool = True
    is_default: bool = False
    description: str | None = None


@router.get("")
def list_hooks(db: DbSession, user: CurrentUser, hook_type: str | None = None):
    q = db.query(Hook)
    if hook_type:
        q = q.filter(Hook.hook_type == hook_type)
    rows = q.order_by(Hook.name.asc()).all()
    return [_serialize(h) for h in rows]


@router.post("")
def create_hook(body: HookCreate, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage hooks")
    if body.hook_type not in HookType.values():
        raise ValidationAppError(f"Invalid hook type: {body.hook_type}")
    try:
        assert_safe_script_path(body.script_path, executable_required=True)
    except ValidationAppError as exc:
        raise ValidationAppError(f"Hook script invalid: {exc.message}") from exc
    hook = Hook(**body.model_dump())
    db.add(hook)
    db.commit()
    db.refresh(hook)
    record(db, action="hook.create", user_id=user.id, username=user.username,
           resource_type="hook", resource_id=hook.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(hook)


@router.patch("/{hook_id}")
def update_hook(hook_id: int, body: dict[str, Any], db: DbSession, user: CurrentUser,
                request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage hooks")
    hook = db.query(Hook).filter(Hook.id == hook_id).first()
    if hook is None:
        raise NotFoundError("Hook not found")
    for key in ("name", "hook_type", "script_path", "env_vars", "execution_user",
                "working_directory", "timeout_seconds", "is_active", "is_default", "description"):
        if key in body:
            setattr(hook, key, body[key])
    if body.get("script_path"):
        try:
            assert_safe_script_path(body["script_path"], executable_required=True)
        except ValidationAppError as exc:
            raise ValidationAppError(f"Hook script invalid: {exc.message}") from exc
    db.commit()
    record(db, action="hook.update", user_id=user.id, username=user.username,
           resource_type="hook", resource_id=hook.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(hook)


@router.delete("/{hook_id}")
def delete_hook(hook_id: int, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can delete hooks")
    hook = db.query(Hook).filter(Hook.id == hook_id).first()
    if hook is None:
        raise NotFoundError("Hook not found")
    db.delete(hook)
    db.commit()
    record(db, action="hook.delete", user_id=user.id, username=user.username,
           resource_type="hook", resource_id=hook_id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return {"ok": True}


def _serialize(h: Hook) -> dict[str, Any]:
    return {
        "id": h.id, "name": h.name, "hook_type": h.hook_type,
        "script_path": h.script_path, "env_vars": h.env_vars or {},
        "execution_user": h.execution_user, "working_directory": h.working_directory,
        "timeout_seconds": h.timeout_seconds, "is_active": h.is_active,
        "is_default": h.is_default, "description": h.description,
        "created_at": h.created_at.isoformat() if h.created_at else None,
    }
