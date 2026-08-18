"""Server inventory, connection testing, restricted command center, service control."""


from typing import Any

from fastapi import APIRouter, Query, Request

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.api.permissions import P_
from app.core.logging import get_logger
from app.models.enums import AuditResult
from app.schemas.server import ServerCreate, ServerUpdate
from app.services import server_service
from app.services.audit_service import record

logger = get_logger(__name__)
router = APIRouter(prefix="/servers", tags=["Servers"])

SERVER = P_["server"]


@router.get("")
def list_servers(db: DbSession, user: CurrentUser, search: str | None = Query(None, max_length=200),
                 environment: str | None = None, page: int = Query(1, ge=1),
                 page_size: int = Query(25, ge=1, le=1000)):
    rows, total = server_service.list_servers(db, search=search, environment=environment,
                                              page=page, page_size=page_size)
    return {
        "items": [_serialize(s) for s in rows],
        "total": total, "page": page, "page_size": page_size,
    }


@router.post("")
def create_server(body: ServerCreate, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage servers")
    server = server_service.create_server(db, body.model_dump(), created_by=user.id)
    record(db, action="server.create", user_id=user.id, username=user.username,
           resource_type="server", resource_id=server.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(server)


@router.patch("/{server_id}")
def update_server(server_id: int, body: ServerUpdate, db: DbSession, user: CurrentUser,
                  request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage servers")
    server = server_service.update_server(db, server_id, body.model_dump(exclude_unset=True))
    record(db, action="server.update", user_id=user.id, username=user.username,
           resource_type="server", resource_id=server.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(server)


@router.delete("/{server_id}")
def delete_server(server_id: int, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to manage servers")
    server_service.delete_server(db, server_id)
    record(db, action="server.delete", user_id=user.id, username=user.username,
           resource_type="server", resource_id=server_id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return {"ok": True}


@router.post("/{server_id}/test")
def test_server(server_id: int, db: DbSession, user: CurrentUser, request: Request):
    result = server_service.test_connection(db, server_id)
    record(db, action="server.test", user_id=user.id, username=user.username,
           resource_type="server", resource_id=server_id,
           result=AuditResult.SUCCESS if result.get("reachable") else AuditResult.FAILURE,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return result


# ── Remote Command Center (allowlist enforced) ──────────────────────────────
@router.post("/{server_id}/command")
def run_command(server_id: int, body: dict[str, str], db: DbSession, user: CurrentUser,
                request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to run remote commands")
    command = body.get("command", "")
    return server_service.run_maintenance_command(db, server_id, command, user=user)


@router.post("/{server_id}/service/{service}/{action}")
def service_control(server_id: int, service: str, action: str, db: DbSession,
                    user: CurrentUser, request: Request):
    if user.role_name.value not in ("administrator", "certificate_manager"):
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Not authorized to control services")
    return server_service.service_control(db, server_id, service, action, user=user)


def _serialize(s) -> dict[str, Any]:
    return {
        "id": s.id, "hostname": s.hostname, "ip_address": s.ip_address,
        "environment": s.environment, "os_type": s.os_type, "ssh_port": s.ssh_port,
        "auth_method": s.auth_method, "ssh_user": s.ssh_user,
        "ssh_key_path": s.ssh_key_path, "proxy_jump": s.proxy_jump,
        "certificate_directory": s.certificate_directory, "web_server_type": s.web_server_type,
        "owner_id": s.owner_id, "connection_status": s.connection_status,
        "last_check_at": s.last_check_at.isoformat() if s.last_check_at else None,
        "tags": [t.name for t in s.tags], "notes": s.notes,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
