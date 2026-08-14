"""User & role administration (admin-only)."""


from typing import Any

from fastapi import APIRouter, Query, Request

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.api.permissions import P_
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.security import validate_password_policy
from app.models.enums import AuditResult
from app.models.user import Role, User
from app.services import auth_service
from app.services.audit_service import record
from app.services.auth_service import create_user

router = APIRouter(prefix="/users", tags=["Users"])

ADMIN = P_["admin"]["users"]


@router.get("")
def list_users(db: DbSession, user: CurrentUser, search: str | None = Query(None, max_length=100),
               page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=500)):
    from app.api.permissions import has_permission
    from app.core.exceptions import PermissionDeniedError

    if not has_permission(user.role_name.value, "admin:users"):
        raise PermissionDeniedError("Only administrators can list users")
    q = db.query(User)
    if search:
        like = f"%{search}%"
        q = q.filter(User.username.ilike(like) | User.full_name.ilike(like) | User.email.ilike(like))
    total = q.count()
    rows = q.order_by(User.username.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [_serialize(u) for u in rows],
        "total": total, "page": page, "page_size": page_size,
    }


@router.get("/roles")
def list_roles(db: DbSession, user: CurrentUser):
    from app.api.permissions import has_permission
    from app.core.exceptions import PermissionDeniedError

    if not has_permission(user.role_name.value, "admin:users"):
        raise PermissionDeniedError("Only administrators can view role definitions")
    rows = db.query(Role).order_by(Role.id.asc()).all()
    return [{"name": r.name, "description": r.description, "permissions": r.permissions or []} for r in rows]


@router.post("")
def create_user_endpoint(body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can create users")
    password = body.get("password", "")
    violations = validate_password_policy(password)
    if violations:
        raise ValidationAppError("Password policy not met", details=violations)
    new_user = create_user(
        db, username=body["username"], email=body.get("email"), full_name=body.get("full_name", ""),
        password=password, role_name=body.get("role", "read_only"), created_by=user.id,
    )
    record(db, action="user.create", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"username": new_user.username})
    return _serialize(new_user)


@router.patch("/{user_id}")
def update_user(user_id: int, body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator" and user.id != user_id:
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized")
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise NotFoundError("User not found")

    # Never allow the last active administrator to be disabled or demoted —
    # there's no recovery path from that except direct DB/script access.
    losing_admin_status = (
        target.role_name.value == "administrator" and target.is_active
        and (
            ("is_active" in body and not body["is_active"])
            or ("role" in body and body["role"] != "administrator")
        )
    )
    if losing_admin_status:
        other_active_admins = (
            db.query(User)
            .join(Role)
            .filter(Role.name == "administrator", User.is_active.is_(True), User.id != target.id)
            .count()
        )
        if other_active_admins == 0:
            raise ValidationAppError(
                "Cannot disable or change the role of the last active administrator"
            )

    if "full_name" in body:
        target.full_name = body["full_name"]
    if "email" in body:
        target.email = body["email"]
    if "role" in body and user.role_name.value == "administrator":
        role = db.query(Role).filter(Role.name == body["role"]).first()
        if role is None:
            raise ValidationAppError("Invalid role")
        target.role_id = role.id
    if "is_active" in body and user.role_name.value == "administrator":
        target.is_active = bool(body["is_active"])
    if body.get("reset_password"):
        violations = validate_password_policy(body["reset_password"])
        if violations:
            raise ValidationAppError("Password policy not met", details=violations)
        target.hashed_password = auth_service.hash_password(body["reset_password"])
        target.must_change_password = True
    db.commit()
    db.refresh(target)
    record(db, action="user.update", user_id=user.id, username=user.username,
           resource_type="user", resource_id=target.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(target)


def _serialize(u: User) -> dict[str, Any]:
    return {
        "id": u.id, "username": u.username, "email": u.email, "full_name": u.full_name,
        "role": u.role.name if u.role else None, "is_active": u.is_active,
        "mfa_enabled": u.mfa_enabled, "must_change_password": u.must_change_password,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }
