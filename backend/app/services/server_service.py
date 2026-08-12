"""Server inventory, connectivity checks, restricted remote command center,
and service control (status/restart/reload/stop/start).

SECURITY: the command center only allows a predefined allowlist of commands —
never unrestricted shell access.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.core.domain_utils import is_valid_ip, validate_domain, validate_port
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.core.security import encrypt_secret
from app.core.timeutils import utcnow
from app.models.certificate import Tag
from app.models.server import Server
from app.services.ssh import SSHClient, SSHConfig, SSHConnectionError, build_ssh_config

logger = get_logger(__name__)

# ── Allowed maintenance commands (Remote Command Center) ───────────────────
_ALLOWED_COMMAND_PATTERNS: list[tuple[str, str]] = [
    ("view_cert_files", r"^(cat|ls -la|head -5|tail -5)\s+(/etc/ssl|/etc/letsencrypt|/etc/pki|/etc/nginx|/etc/httpd|/etc/apache2|/etc/openvpn)(?:/|$)"),
    ("check_permissions", r"^ls -la\s+(/etc/ssl|/etc/letsencrypt|/etc/pki|/etc/nginx|/etc/httpd|/etc/apache2|/etc/openvpn)(?:/|$)"),
    ("check_ownership", r"^stat -c .*"),
    ("view_service_logs", r"^(journalctl -u|tail -n 200 /var/log/nginx|tail -n 200 /var/log/apache2)"),
    ("service_status", r"^systemctl (is-active|status)\s+[a-zA-Z0-9_.-]+$"),
    ("restart_service", r"^systemctl restart\s+[a-zA-Z0-9_.-]+$"),
    ("reload_service", r"^systemctl reload\s+[a-zA-Z0-9_.-]+$"),
    ("stop_service", r"^systemctl stop\s+[a-zA-Z0-9_.-]+$"),
    ("start_service", r"^systemctl start\s+[a-zA-Z0-9_.-]+$"),
    ("whoami", r"^whoami$"),
    ("uptime", r"^uptime$"),
    ("disk_space", r"^df -h$"),
    ("memory", r"^free -h$"),
]

ALLOWED_SERVICE_NAMES = {
    "nginx", "apache2", "httpd", "openvpn", "haproxy", "tomcat9", "tomcat10",
    "node", "nodejs", "certmgr", "sshd",
}


def validate_remote_command(command: str) -> tuple[str, str]:
    """Return (command_name, error). Raises on disallowed input."""
    command = command.strip()
    if not command or len(command) > 512:
        raise ValidationAppError("Command is empty or too long")
    for name, pattern in _ALLOWED_COMMAND_PATTERNS:
        if re.match(pattern, command):
            return name, ""
    raise ValidationAppError("Command is not in the allowed maintenance allowlist")


# ── CRUD ────────────────────────────────────────────────────────────────────

def create_server(db: Session, payload: dict[str, Any], *, created_by: int | None = None) -> Server:
    hostname = validate_domain(payload["hostname"])
    if payload.get("ip_address") and not is_valid_ip(payload["ip_address"]):
        raise ValidationAppError(f"Invalid IP address: {payload['ip_address']}")
    port = validate_port(payload.get("ssh_port", 22))

    server = Server(
        hostname=hostname,
        ip_address=payload.get("ip_address"),
        environment=payload.get("environment", "production"),
        os_type=payload.get("os_type", "linux"),
        ssh_port=port,
        auth_method=payload.get("auth_method", "ssh_key"),
        ssh_user=payload.get("ssh_user", "root"),
        ssh_password_encrypted=encrypt_secret(payload["ssh_password"]) if payload.get("ssh_password") else None,
        ssh_key_path=payload.get("ssh_key_path"),
        ssh_key_passphrase_encrypted=encrypt_secret(payload["ssh_key_passphrase"]) if payload.get("ssh_key_passphrase") else None,
        proxy_jump=payload.get("proxy_jump"),
        jump_host=payload.get("jump_host"),
        certificate_directory=payload.get("certificate_directory"),
        web_server_type=payload.get("web_server_type"),
        owner_id=payload.get("owner_id"),
        notes=payload.get("notes"),
        capabilities=payload.get("capabilities") or {},
    )
    db.add(server)
    db.flush()
    for name in payload.get("tags") or []:
        tag = db.query(Tag).filter(Tag.name == name).first() or Tag(name=name)
        if tag not in server.tags:
            db.add(tag)
            db.flush()
            server.tags.append(tag)
    db.commit()
    db.refresh(server)
    return server


def update_server(db: Session, server_id: int, payload: dict[str, Any]) -> Server:
    server = db.query(Server).filter(Server.id == server_id).first()
    if server is None:
        raise NotFoundError("Server not found")
    allowed = {
        "hostname", "ip_address", "environment", "os_type", "ssh_port", "auth_method",
        "ssh_user", "ssh_key_path", "proxy_jump", "jump_host", "certificate_directory",
        "web_server_type", "owner_id", "notes", "capabilities",
    }
    for key, value in payload.items():
        if key in allowed:
            setattr(server, key, value)
    if payload.get("ssh_password"):
        server.ssh_password_encrypted = encrypt_secret(payload["ssh_password"])
    if payload.get("ssh_key_passphrase"):
        server.ssh_key_passphrase_encrypted = encrypt_secret(payload["ssh_key_passphrase"])
    if payload.get("tags") is not None:
        server.tags = []
        db.flush()
        for name in payload["tags"]:
            tag = db.query(Tag).filter(Tag.name == name).first() or Tag(name=name)
            server.tags.append(tag)
    db.commit()
    db.refresh(server)
    return server


def list_servers(db: Session, *, search: str | None = None, environment: str | None = None,
                 page: int = 1, page_size: int = 25) -> tuple[list[Server], int]:
    q = db.query(Server)
    if search:
        like = f"%{search}%"
        q = q.filter(Server.hostname.ilike(like) | Server.ip_address.ilike(like))
    if environment:
        q = q.filter(Server.environment == environment)
    total = q.count()
    rows = q.order_by(Server.hostname.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total


# ── Connectivity / operations ───────────────────────────────────────────────

def test_connection(db: Session, server_id: int) -> dict[str, Any]:
    server = db.query(Server).filter(Server.id == server_id).first()
    if server is None:
        raise NotFoundError("Server not found")
    try:
        with SSHClient(build_ssh_config(server)) as ssh:
            res = ssh.exec("echo ok; hostname")
            ok = res.exit_code == 0 and "ok" in res.stdout
            server.connection_status = "reachable" if ok else "unreachable"
            server.last_check_at = utcnow()
            db.commit()
            return {
                "reachable": ok, "hostname": res.stdout.strip().splitlines()[-1] if res.stdout else None,
                "exit_code": res.exit_code, "duration_ms": res.duration_ms,
            }
    except SSHConnectionError as exc:
        server.connection_status = "unreachable"
        server.last_check_at = utcnow()
        db.commit()
        return {"reachable": False, "error": str(exc)}


def run_maintenance_command(db: Session, server_id: int, command: str,
                            *, user=None) -> dict[str, Any]:
    """Restricted command execution — allowlist enforced."""
    from app.models.enums import AuditResult
    from app.services.audit_service import record

    command_name, _ = validate_remote_command(command)
    server = db.query(Server).filter(Server.id == server_id).first()
    if server is None:
        raise NotFoundError("Server not found")

    try:
        with SSHClient(build_ssh_config(server)) as ssh:
            res = ssh.exec(command)
        record(db, action="server.command", resource_type="server", resource_id=server.id,
               result=AuditResult.SUCCESS if res.exit_code == 0 else AuditResult.FAILURE,
               user_id=user.id if user else None, username=user.username if user else None,
               details={"command_name": command_name, "command": command})
        return {
            "command": command, "command_name": command_name,
            "exit_code": res.exit_code, "stdout": res.stdout[-8000:], "stderr": res.stderr[-2000:],
            "duration_ms": res.duration_ms,
        }
    except SSHConnectionError as exc:
        record(db, action="server.command", resource_type="server", resource_id=server.id,
               result=AuditResult.FAILURE, user_id=user.id if user else None,
               username=user.username if user else None,
               details={"command": command, "error": str(exc)})
        return {"command": command, "exit_code": 255, "stdout": "", "stderr": str(exc)}


def service_control(db: Session, server_id: int, service: str, action: str,
                    *, user=None) -> dict[str, Any]:
    if service not in ALLOWED_SERVICE_NAMES:
        raise ValidationAppError(f"Service '{service}' is not in the allowed list")
    if action not in {"status", "restart", "reload", "stop", "start"}:
        raise ValidationAppError(f"Unsupported service action: {action}")
    return run_maintenance_command(db, server_id, f"systemctl {action} {service}", user=user)


def get_ssh_config_for(server: Server) -> SSHConfig:
    return build_ssh_config(server)
