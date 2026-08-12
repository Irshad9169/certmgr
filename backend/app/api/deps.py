"""API dependencies: auth, RBAC, client context, audit helper."""


from collections.abc import Callable
from functools import wraps
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import AuthError, PermissionDeniedError
from app.core.logging import Timer, get_logger
from app.core.security import decode_token
from app.models.enums import AuditResult
from app.models.user import User
from app.services.audit_service import record as audit_record
from app.services.auth_service import authenticate_api_token

logger = get_logger(__name__)

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    db: Annotated[Session, Depends(get_db)] = None,
) -> User:
    """Resolve the authenticated user from a JWT or API token.

    Accepts the JWT via `Authorization: Bearer <jwt>` or the custom
    `X-CertMgr-Token: <jwt>` header (some reverse proxies / preview edges strip
    `Authorization`), and API tokens via `X-API-Key`.
    """
    bearer_jwt = credentials.credentials if credentials else None
    x_jwt = request.headers.get("X-CertMgr-Token")
    api_key = request.headers.get("X-API-Key") if not bearer_jwt and not x_jwt else None

    jwt_token = bearer_jwt or x_jwt
    if not jwt_token and not api_key:
        raise AuthError("Not authenticated", code="NO_CREDENTIALS")

    user: User | None = None
    try:
        if jwt_token:
            payload = decode_token(jwt_token, expected_type="access")
            user = db.query(User).filter(User.id == int(payload["sub"])).first()
        else:
            user = authenticate_api_token(db, api_key)
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, AuthError):
            raise
        logger.warning("Auth resolution failed: %s", exc)

    if user is None:
        raise AuthError("Invalid or expired credentials", code="BAD_TOKEN")
    if not user.is_active:
        raise AuthError("Account is disabled", code="ACCOUNT_DISABLED")
    if user.must_change_password:
        # Allow a narrow set of endpoints even when password change is required
        if not request.url.path.endswith(("/auth/me", "/auth/change-password", "/auth/logout")):
            raise PermissionDeniedError("Password change required before continuing")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[Session, Depends(get_db)]


def require_permissions(*permissions: str):
    """Dependency factory: require ALL listed permission codes."""
    def checker(user: CurrentUser) -> User:
        user_perms = set(user.role.permissions or [])
        missing = [p for p in permissions if p not in user_perms]
        if missing:
            raise PermissionDeniedError(
                f"Insufficient permissions — requires: {', '.join(missing)}",
                details={"missing": missing},
            )
        return user
    return checker


def get_client_ip(request: Request) -> str:
    if settings.trust_proxy_headers and request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "")


def audit_action(action: str, resource_type: str | None = None):
    """Decorator: record an audit entry with duration after handler success/failure.

    The decorated endpoint must accept a `request: Request` and `db: Session`
    dependency (or accept **kwargs with them).
    """
    def decorator(fn: Callable):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            timer = Timer()
            request: Request | None = kwargs.get("request")
            db: Session | None = kwargs.get("db")
            user: User | None = kwargs.get("user") or kwargs.get("current_user")
            resource_id = kwargs.get("certificate_id") or kwargs.get("id")
            try:
                result = await fn(*args, **kwargs) if _is_async(fn) else fn(*args, **kwargs)
            except Exception as exc:
                if db and request and user:
                    audit_record(
                        db, action=action, user_id=user.id, username=user.username,
                        resource_type=resource_type, resource_id=resource_id,
                        result=AuditResult.FAILURE, ip_address=get_client_ip(request),
                        user_agent=get_user_agent(request), duration_ms=timer.elapsed_ms(),
                        details={"error": str(exc)[:500]},
                    )
                raise
            if db and request and user:
                audit_record(
                    db, action=action, user_id=user.id, username=user.username,
                    resource_type=resource_type, resource_id=resource_id,
                    result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
                    user_agent=get_user_agent(request), duration_ms=timer.elapsed_ms(),
                )
            return result
        return wrapper
    return decorator


def _is_async(fn: Callable) -> bool:
    import asyncio

    return asyncio.iscoroutinefunction(fn)
