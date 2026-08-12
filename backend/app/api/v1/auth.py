"""Authentication endpoints: login (rate-limited), refresh, logout, MFA, tokens."""



from datetime import UTC

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, audit_action, get_client_ip, get_user_agent
from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.rate_limit import limiter
from app.core.security import generate_csrf_token
from app.models.enums import AuditResult
from app.services import auth_service
from app.services.audit_service import record

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/csrf")
def get_csrf(request: Request):
    """Public endpoint that establishes the CSRF double-submit cookie.

    The UI calls this once before login (and on app boot) so state-changing
    requests (login, refresh, …) can send the matching X-CSRF-Token header.
    The cookie is HttpOnly and never readable by JS; the token value is
    returned in the body for the double-submit comparison.
    """
    from fastapi.responses import JSONResponse

    from app.core.security import generate_csrf_token

    token = generate_csrf_token()
    resp = JSONResponse({"csrf_token": token})
    resp.set_cookie(
        "certmgr_csrf", token,
        httponly=True, secure=settings.cookie_secure,
        samesite=settings.cookie_samesite, max_age=3600, path="/",
    )
    return resp


class LoginRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, max_length=8)


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12, max_length=256)


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(BaseModel):
    password: str


@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest, db: DbSession):
    ip = get_client_ip(request)
    ua = get_user_agent(request)
    try:
        user = auth_service.authenticate(db, body.username.strip(), body.password)
        if user.mfa_enabled and not auth_service.verify_mfa(user, body.mfa_code or ""):
            record(db, action="auth.login", user_id=user.id, username=user.username,
                   result=AuditResult.FAILURE, ip_address=ip, user_agent=ua,
                   details={"reason": "mfa_failed"})
            raise AuthError("MFA verification failed", code="MFA_FAILED")
        tokens = auth_service.issue_tokens(db, user, ip=ip, user_agent=ua)
        record(db, action="auth.login", user_id=user.id, username=user.username,
               result=AuditResult.SUCCESS, ip_address=ip, user_agent=ua)
        from fastapi.responses import JSONResponse

        # Keep the SAME CSRF token the client already holds (no rotation) —
        # otherwise the client's next state-changing request would fail the
        # double-submit check. Fall back to a fresh token only if none exists.
        csrf = request.cookies.get("certmgr_csrf") or generate_csrf_token()
        content = {
            **tokens,
            "user": {"id": user.id, "username": user.username, "full_name": user.full_name,
                     "role": user.role_name.value, "mfa_enabled": user.mfa_enabled,
                     "must_change_password": user.must_change_password},
            "csrf_token": csrf,
        }
        resp = JSONResponse(content=content)
        resp.set_cookie(
            "certmgr_csrf", csrf,
            httponly=True, secure=settings.cookie_secure,
            samesite=settings.cookie_samesite, max_age=3600, path="/",
        )
        return resp
    except AuthError:
        record(db, action="auth.login", username=body.username.strip(),
               result=AuditResult.FAILURE, ip_address=ip, user_agent=ua)
        raise


@router.post("/refresh")
def refresh_token(body: RefreshRequest, db: DbSession, request: Request):
    return auth_service.refresh_access_token(db, body.refresh_token)


@router.post("/logout")
def logout(body: RefreshRequest, db: DbSession, user: CurrentUser, request: Request):
    auth_service.revoke_refresh_token(db, body.refresh_token)
    record(db, action="auth.logout", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request))
    return {"ok": True}


@router.get("/me")
def me(user: CurrentUser, db: DbSession):
    return {
        "id": user.id, "username": user.username, "email": user.email,
        "full_name": user.full_name, "role": user.role_name.value,
        "permissions": user.role.permissions or [],
        "mfa_enabled": user.mfa_enabled, "must_change_password": user.must_change_password,
        "preferences": user.preferences or {},
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


@router.post("/change-password")
@audit_action("auth.change_password")
def change_password(body: ChangePasswordRequest, user: CurrentUser, db: DbSession, request: Request):
    auth_service.change_password(db, user, body.old_password, body.new_password)
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(user: CurrentUser, db: DbSession):
    return auth_service.setup_mfa(db, user)


@router.post("/mfa/enable")
def mfa_enable(body: MfaVerifyRequest, user: CurrentUser, db: DbSession):
    auth_service.enable_mfa(db, user, body.code)
    return {"ok": True, "mfa_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableRequest, user: CurrentUser, db: DbSession):
    auth_service.disable_mfa(db, user, body.password)
    return {"ok": True, "mfa_enabled": False}


# ── API tokens ──────────────────────────────────────────────────────────────
@router.get("/tokens")
def list_tokens(user: CurrentUser, db: DbSession):
    from app.models.user import ApiToken

    rows = (
        db.query(ApiToken)
        .filter(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    return [
        {"id": t.id, "name": t.name, "prefix": t.prefix, "scopes": t.scopes,
         "expires_at": t.expires_at.isoformat() if t.expires_at else None,
         "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
         "created_at": t.created_at.isoformat()}
        for t in rows
    ]


@router.post("/tokens")
def create_token(body: ApiTokenCreate, user: CurrentUser, db: DbSession, request: Request):
    from datetime import datetime, timedelta

    expires = None
    if body.expires_in_days:
        expires = datetime.now(UTC) + timedelta(days=body.expires_in_days)
    result = auth_service.create_api_token(db, user, body.name, body.scopes, expires)
    record(db, action="auth.token.create", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"name": body.name})
    return result  # includes the raw token once


@router.delete("/tokens/{token_id}")
def revoke_token(token_id: int, user: CurrentUser, db: DbSession, request: Request):
    from app.core.timeutils import utcnow
    from app.models.user import ApiToken

    row = db.query(ApiToken).filter(ApiToken.id == token_id, ApiToken.user_id == user.id).first()
    if row:
        row.revoked_at = utcnow()
        db.commit()
    record(db, action="auth.token.revoke", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"token_id": token_id})
    return {"ok": True}
