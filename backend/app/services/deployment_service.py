"""Deployment engine: push certificates to remote servers with backup, verify
and automatic rollback. Methods: SFTP/SCP (paramiko), rsync (subprocess).

Workflow per deployment:
  1. Pre-deploy hook (template script)
  2. Upload material (cert, key, chain) to target paths
  3. Backup existing cert/key/config on the remote host
  4. Replace files + fix permissions/ownership
  5. Reload the target service
  6. Verify TLS (handshake/chain/hostname/expiry) — configurable
  7. Rollback automatically if any step fails
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import jinja2
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import DeploymentError, NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.core.metrics import JOBS_TOTAL
from app.core.timeutils import utcnow
from app.models.enums import (
    AuditResult,
    DeploymentMethod,
    DeploymentStatus,
    JobStatus,
    JobTrigger,
    JobType,
)
from app.models.job import JobExecution
from app.models.server import Deployment, DeploymentTemplate, Server
from app.services.audit_service import record
from app.services.certificate_service import get_certificate
from app.services.notification_service import queue_event_notifications
from app.services.ssh import SSHClient, SSHConnectionError, build_ssh_config
from app.services.storage import get_file_store

logger = get_logger(__name__)

_RENDERED_KEYS = (
    "pre_deploy_script", "backup_script", "deploy_script",
    "post_deploy_script", "reload_command",
)

_DEFAULT_DEPLOY_SCRIPT = """set -e
# Deploy certificate material for {{ domain }}
install -m 0644 /tmp/certmgr_{{ cert_id }}/cert.pem {{ remote_cert_path }}
install -m 0600 /tmp/certmgr_{{ cert_id }}/privkey.pem {{ remote_key_path }}
{% if chain_path %}install -m 0644 /tmp/certmgr_{{ cert_id }}/chain.pem {{ remote_chain_path }}{% endif %}
chown {% if ownership %}{{ ownership }}{% else %}root:root{% endif %} {{ remote_cert_path }} {{ remote_key_path }}
"""

_DEFAULT_BACKUP_SCRIPT = """set -e
ts=$(date +%Y%m%d%H%M%S)
for f in {{ remote_cert_path }} {{ remote_key_path }} {% if remote_chain_path %}{{ remote_chain_path }}{% endif %}; do
  if [ -f "$f" ]; then
    mkdir -p {{ backup_dir }}
    cp -a "$f" "{{ backup_dir }}/$(basename $f).$ts.bak"
  fi
done
echo "BACKUP_DIR={{ backup_dir }}"
"""

_DEFAULT_RELOAD = "systemctl reload {{ service }}"


def get_template(db: Session, template_id: int | None, target_type: str) -> DeploymentTemplate:
    if template_id:
        tmpl = db.query(DeploymentTemplate).filter(DeploymentTemplate.id == template_id).first()
        if tmpl is None:
            raise NotFoundError("Deployment template not found")
        return tmpl
    tmpl = (
        db.query(DeploymentTemplate)
        .filter(DeploymentTemplate.target_type == target_type, DeploymentTemplate.is_active.is_(True))
        .order_by(DeploymentTemplate.id.desc())
        .first()
    )
    if tmpl is None:
        tmpl = DeploymentTemplate(
            name=f"default-{target_type}",
            target_type=target_type,
            deploy_script=_DEFAULT_DEPLOY_SCRIPT,
            backup_script=_DEFAULT_BACKUP_SCRIPT,
            reload_command=_DEFAULT_RELOAD,
            verify_enabled=True,
            rollback_enabled=True,
            variables={"service": target_type},
        )
        db.add(tmpl)
        db.flush()
    return tmpl


def create_deployment_record(
    db: Session, *, certificate_id: int, server_id: int, template_id: int | None,
    target_service: str | None, method: str, user=None,
) -> Deployment:
    if target_service:
        # SECURITY: target_service is caller-controlled and later rendered
        # unescaped into a shell reload command (e.g. "systemctl reload
        # {{ service }}") on the remote host — it must be restricted to the
        # same service allowlist the Command Center's service_control() uses,
        # never a free-form string.
        from app.services.server_service import ALLOWED_SERVICE_NAMES

        if target_service not in ALLOWED_SERVICE_NAMES:
            raise ValidationAppError(f"target_service '{target_service}' is not in the allowed list")
    cert = get_certificate(db, certificate_id, load_relations=False)
    server = db.query(Server).filter(Server.id == server_id).first()
    if server is None:
        raise NotFoundError("Server not found")
    tmpl = get_template(db, template_id, target_service or server.web_server_type or "custom")
    deployment = Deployment(
        certificate_id=cert.id,
        server_id=server.id,
        template_id=tmpl.id,
        method=method,
        target_service=target_service or server.web_server_type,
        status=DeploymentStatus.PENDING.value,
        created_by=user.id if user else None,
    )
    db.add(deployment)
    db.commit()
    db.refresh(deployment)
    return deployment


def deploy_certificate(
    db: Session, *, certificate_id: int, server_id: int,
    template_id: int | None = None, target_service: str | None = None,
    method: str = DeploymentMethod.SFTP.value,
    user=None, trigger: str = JobTrigger.API.value,
    execution_id: int | None = None,
) -> Deployment:
    deployment = create_deployment_record(
        db, certificate_id=certificate_id, server_id=server_id,
        template_id=template_id, target_service=target_service, method=method, user=user,
    )
    cert = get_certificate(db, certificate_id, load_relations=False)
    server = db.query(Server).filter(Server.id == server_id).first()
    tmpl = deployment.template

    if not cert.cert_path or not os.path.exists(cert.cert_path):
        deployment.status = DeploymentStatus.FAILED.value
        deployment.error_message = "Certificate material missing on platform"
        db.commit()
        _record_execution(db, deployment, execution_id, "missing material", 1, cert, server, user, trigger)
        return deployment

    deployment.status = DeploymentStatus.RUNNING.value
    deployment.started_at = utcnow()
    db.commit()

    store = get_file_store()
    vars_ctx = {
        "domain": cert.domain,
        "cert_id": cert.id,
        "remote_cert_path": deployment.remote_cert_path or f"/etc/ssl/certs/{cert.domain}.crt",
        "remote_key_path": deployment.remote_key_path or f"/etc/ssl/private/{cert.domain}.key",
        "remote_chain_path": deployment.remote_chain_path or f"/etc/ssl/certs/{cert.domain}.chain.crt",
        "service": deployment.target_service or server.web_server_type or "nginx",
        "backup_dir": f"/var/backups/certmgr/{cert.domain}",
        "server": server.hostname,
        "ownership": None,
        "environment": cert.environment,
    }
    vars_ctx.update(tmpl.variables or {})

    rendered = {
        key: jinja2.Template(getattr(tmpl, key) or "").render(**vars_ctx)
        for key in _RENDERED_KEYS
    }

    deployment.remote_cert_path = vars_ctx["remote_cert_path"]
    deployment.remote_key_path = vars_ctx["remote_key_path"]
    deployment.remote_chain_path = vars_ctx["remote_chain_path"]
    db.commit()

    remote_tmp = f"/tmp/certmgr_{cert.id}"  # noqa: S108 — remote staging dir on target hosts
    logs: list[str] = []

    try:
        with SSHClient(build_ssh_config(server)) as ssh:
            # 1) Pre-deploy
            if rendered["pre_deploy_script"]:
                res = ssh.exec(rendered["pre_deploy_script"])
                logs.append(f"[pre-deploy] rc={res.exit_code}\n{res.stdout}\n{res.stderr}")

            # 2) Stage files
            ssh.sftp_mkdir_p(remote_tmp)
            ssh.sftp_put(cert.cert_path, f"{remote_tmp}/cert.pem", mode=0o644)
            if cert.key_path and store.has_private_key(cert.key_path):
                key_pem = store.read_private_key(cert.key_path)
                ssh.sftp_put_bytes(key_pem.encode(), f"{remote_tmp}/privkey.pem", mode=0o600)
            else:
                raise DeploymentError("Certificate has no private key — cannot deploy")
            if cert.chain_path and os.path.exists(cert.chain_path):
                ssh.sftp_put(cert.chain_path, f"{remote_tmp}/chain.pem", mode=0o644)
            elif cert.fullchain_path and os.path.exists(cert.fullchain_path):
                ssh.sftp_put(cert.fullchain_path, f"{remote_tmp}/chain.pem", mode=0o644)

            # 3) Backup existing material
            backup_dir = vars_ctx["backup_dir"]
            if rendered["backup_script"]:
                res = ssh.exec(rendered["backup_script"])
                logs.append(f"[backup] rc={res.exit_code}\n{res.stdout}\n{res.stderr}")
                if res.exit_code != 0:
                    raise DeploymentError(f"Backup failed on {server.hostname}: {res.stderr[-1000:]}")
                deployment.backup_path = backup_dir

            # 4) Deploy + permissions
            if rendered["deploy_script"]:
                res = ssh.exec(rendered["deploy_script"])
                logs.append(f"[deploy] rc={res.exit_code}\n{res.stdout}\n{res.stderr}")
                if res.exit_code != 0:
                    raise DeploymentError(f"Deploy script failed: {res.stderr[-1000:]}")
            else:
                # default inline install
                cmds = [
                    f"install -m 0644 {remote_tmp}/cert.pem {vars_ctx['remote_cert_path']}",
                    f"install -m 0600 {remote_tmp}/privkey.pem {vars_ctx['remote_key_path']}",
                ]
                if cert.chain_path:
                    cmds.append(f"install -m 0644 {remote_tmp}/chain.pem {vars_ctx['remote_chain_path']}")
                for cmd in cmds:
                    res = ssh.exec(cmd)
                    logs.append(f"[install] rc={res.exit_code} {cmd}")

            # 5) Post-deploy / reload
            if rendered["post_deploy_script"]:
                res = ssh.exec(rendered["post_deploy_script"])
                logs.append(f"[post-deploy] rc={res.exit_code}\n{res.stdout}\n{res.stderr}")
            if rendered["reload_command"]:
                res = ssh.exec(rendered["reload_command"])
                logs.append(f"[reload] rc={res.exit_code}\n{res.stdout}\n{res.stderr}")
                if res.exit_code != 0:
                    raise DeploymentError(f"Service reload failed: {res.stderr[-1000:]}")

            # 6) Verify
            if tmpl.verify_enabled and settings.deployment_verify_enabled:
                verification = verify_remote_tls(
                    server.hostname if server.ip_address else server.hostname,
                    cert.domain,
                )
                deployment.verification = verification
                if not verification.get("ok"):
                    raise DeploymentError(f"TLS verification failed: {verification.get('error')}")

            # 7) Cleanup temp
            try:
                ssh.exec(f"rm -rf {remote_tmp}")
            except Exception:  # noqa: BLE001, S110 — best-effort temp cleanup
                pass

        deployment.status = DeploymentStatus.SUCCESS.value
        deployment.finished_at = utcnow()
        deployment.log_path = _persist_log(deployment, logs)
        db.commit()
        record(db, action="certificate.deploy", resource_type="certificate", resource_id=cert.id,
               result=AuditResult.SUCCESS, details={"server": server.hostname, "method": method},
               user_id=user.id if user else None, username=user.username if user else None)
        queue_event_notifications(db, "deployed", cert, extra={"server": server.hostname})
        _record_execution(db, deployment, execution_id, "", 0, cert, server, user, trigger,
                          status=JobStatus.SUCCESS.value)
        return deployment

    except (SSHConnectionError, DeploymentError) as exc:
        deployment.status = DeploymentStatus.FAILED.value
        deployment.error_message = str(exc)[:4000]
        deployment.finished_at = utcnow()
        deployment.log_path = _persist_log(deployment, logs)
        db.commit()
        record(db, action="certificate.deploy", resource_type="certificate", resource_id=cert.id,
               result=AuditResult.FAILURE, details={"server": server.hostname, "error": str(exc)[:500]},
               user_id=user.id if user else None, username=user.username if user else None)
        queue_event_notifications(db, "deployment_failed", cert, extra={"server": server.hostname, "error": str(exc)[:300]})
        _record_execution(db, deployment, execution_id, str(exc)[:4000], 1, cert, server, user, trigger,
                          status=JobStatus.FAILED.value)

        if tmpl.rollback_enabled and settings.deployment_rollback_enabled:
            _rollback(db, deployment, server, logs)
        return deployment


def _rollback(db: Session, deployment: Deployment, server: Server, logs: list[str]) -> None:
    """Restore backup_dir files to their original locations."""
    from app.services.ssh import SSHConnectionError

    try:
        with SSHClient(build_ssh_config(server)) as ssh:
            backup_dir = deployment.backup_path
            if not backup_dir:
                return
            for target in (deployment.remote_cert_path, deployment.remote_key_path, deployment.remote_chain_path):
                if not target:
                    continue
                res = ssh.exec(
                    f"latest=$(ls -t {backup_dir}/$(basename {target}).*.bak 2>/dev/null | head -1); "
                    f"if [ -n \"$latest\" ]; then cp -a \"$latest\" {target}; fi"
                )
                logs.append(f"[rollback] rc={res.exit_code} -> {target}")
                if res.exit_code != 0:
                    logger.error("Rollback failed for %s on %s", target, server.hostname)
            deployment.status = DeploymentStatus.ROLLED_BACK.value
            db.commit()
    except SSHConnectionError as exc:
        logger.error("Rollback could not connect to %s: %s", server.hostname, exc)
        deployment.status = DeploymentStatus.ROLLED_BACK.value
        db.commit()


def verify_remote_tls(host: str, domain: str, port: int = 443) -> dict:
    """TLS verification against the deployed endpoint (used after deploy)."""
    import socket
    import ssl

    result: dict = {"ok": False, "checks": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result["checks"]["tls_handshake"] = True
                result["checks"]["hostname"] = True
                result["checks"]["protocol"] = tls.version()
                not_after = cert.get("notAfter")
                if not_after:
                    from email.utils import parsedate_to_datetime

                    expiry = parsedate_to_datetime(not_after)
                    days = (expiry - datetime.now(UTC)).days
                    result["checks"]["expiry_days"] = days
                    result["checks"]["expiry_ok"] = days > 0
                result["ok"] = True
    except (ssl.SSLCertVerificationError, OSError) as exc:
        result["error"] = str(exc)
    return result


def _record_execution(db, deployment, execution_id, error, exit_code, cert, server, user,
                      trigger, status: str = JobStatus.FAILED.value) -> JobExecution:
    from app.core.logging import Timer

    timer = Timer()
    exec_row = JobExecution(
        id=execution_id or None,
        job_type=JobType.DEPLOY.value,
        certificate_id=cert.id,
        server_id=server.id,
        trigger=trigger,
        status=status,
        exit_code=exit_code,
        error_message=error[:4000] if error else None,
        execution_time_ms=timer.elapsed_ms(),
        started_at=utcnow(), finished_at=utcnow(),
        created_by=user.id if user else None,
    )
    if execution_id:
        existing = db.query(JobExecution).filter(JobExecution.id == execution_id).first()
        if existing:
            existing.status = status
            existing.exit_code = exit_code
            existing.error_message = error[:4000] if error else None
            existing.finished_at = utcnow()
            JOBS_TOTAL.labels(type=JobType.DEPLOY.value, status=status).inc()
            return existing
    db.add(exec_row)
    db.flush()
    JOBS_TOTAL.labels(type=JobType.DEPLOY.value, status=status).inc()
    return exec_row


def _persist_log(deployment: Deployment, lines: list[str]) -> str:
    log_root = settings.log_root_path / "deployments"
    log_root.mkdir(parents=True, exist_ok=True)
    path = log_root / f"deploy-{deployment.id}.log"
    path.write_text("\n".join(lines) or "— no output —")
    return str(path)
