"""Discovery, health, providers, compliance, reports, webhooks, search, AI, backups."""


from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.api.permissions import P_, has_permission
from app.core.config import settings
from app.core.exceptions import NotFoundError, PermissionDeniedError
from app.core.logging import get_logger
from app.models.enums import AuditResult
from app.services.audit_service import record

logger = get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Discovery
# ═══════════════════════════════════════════════════════════════════════════
discovery_router = APIRouter(prefix="/discovery", tags=["Discovery"])


@discovery_router.post("/run")
def trigger_discovery(db: DbSession, user: CurrentUser, request: Request,
                      body: dict[str, Any] | None = None):
    if not has_permission(user.role_name.value, P_["discovery"]["run"]):
        raise PermissionDeniedError("You are not authorized to run discovery")
    from app.services.discovery_service import run_discovery

    if settings.celery_task_always_eager:
        run = run_discovery(db, extra_paths=(body or {}).get("paths"), created_by=user.id)
        return {"run_id": run.id, "found": run.found_count, "imported": run.imported_count,
                "skipped": run.skipped_count, "status": run.status}
    from app.tasks.discovery import run_discovery as run_discovery_task

    run_discovery_task.delay((body or {}).get("paths"), user.id)
    record(db, action="discovery.trigger", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request))
    return {"status": "queued"}


@discovery_router.get("/runs")
def discovery_runs(db: DbSession, user: CurrentUser, limit: int = Query(20, ge=1, le=200)):
    from app.models.job import DiscoveryRun

    rows = db.query(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id, "status": r.status, "scan_paths": r.scan_paths or [],
            "found": r.found_count, "imported": r.imported_count, "skipped": r.skipped_count,
            "log": (r.log or "")[-5000:],
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        }
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Health
# ═══════════════════════════════════════════════════════════════════════════
health_router = APIRouter(prefix="/health", tags=["Health"])


@health_router.get("/certificate/{certificate_id}/scan")
def scan_certificate(certificate_id: int, db: DbSession, user: CurrentUser, request: Request):
    if not has_permission(user.role_name.value, P_["health"]["run"]):
        raise PermissionDeniedError("You are not authorized to run health scans")
    from app.services.certificate_service import get_certificate
    from app.services.health_service import check_certificate_health

    cert = get_certificate(db, certificate_id, load_relations=False)
    result = check_certificate_health(db, cert)
    record(db, action="health.scan", user_id=user.id, username=user.username,
           resource_type="certificate", resource_id=certificate_id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return result


@health_router.get("/certificate/{certificate_id}/checks")
def health_history(certificate_id: int, db: DbSession, user: CurrentUser, limit: int = Query(20, ge=1, le=200)):
    from app.models.certificate import CertificateHealthCheck

    rows = (
        db.query(CertificateHealthCheck)
        .filter(CertificateHealthCheck.certificate_id == certificate_id)
        .order_by(CertificateHealthCheck.checked_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {"checked_at": r.checked_at.isoformat() if r.checked_at else None,
         "status": r.status, "score": r.score, "checks": r.checks or {}}
        for r in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Providers
# ═══════════════════════════════════════════════════════════════════════════
providers_router = APIRouter(prefix="/providers", tags=["Providers"])


@providers_router.get("")
def list_providers(db: DbSession, user: CurrentUser):
    from app.services.providers.registry import get_registry

    registry = get_registry()
    return [
        {"key": key, "display_name": registry.get_class(key).display_name,
         "capabilities": registry.capabilities(key)}
        for key in registry.available()
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Compliance
# ═══════════════════════════════════════════════════════════════════════════
compliance_router = APIRouter(prefix="/compliance", tags=["Compliance"])


@compliance_router.get("/dashboard")
def compliance_dashboard(db: DbSession, user: CurrentUser):
    from app.services.compliance_service import compliance_dashboard

    return compliance_dashboard(db)


@compliance_router.post("/report")
def generate_compliance(db: DbSession, user: CurrentUser, request: Request):
    if not has_permission(user.role_name.value, P_["admin"]["reports"]):
        raise PermissionDeniedError("You are not authorized to generate compliance reports")
    from app.services.compliance_service import run_compliance_report

    report = run_compliance_report(db, created_by=user.id)
    record(db, action="compliance.report", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request))
    return {"report_id": report.id, "summary": report.summary}


# ═══════════════════════════════════════════════════════════════════════════
# Reports (CSV/XLSX/PDF/JSON)
# ═══════════════════════════════════════════════════════════════════════════
reports_router = APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.get("/{report_type}.{fmt}")
def download_report(report_type: str, fmt: str, db: DbSession, user: CurrentUser,
                    request: Request, certificate_ids: str | None = Query(None)):
    from fastapi.responses import Response

    from app.services.report_service import generate_report

    if not has_permission(user.role_name.value, P_["admin"]["reports"]):
        raise PermissionDeniedError("You are not authorized to download reports")
    ids = [int(x) for x in certificate_ids.split(",")] if certificate_ids else None
    if fmt not in ("csv", "xlsx", "pdf", "json"):
        from app.core.exceptions import ValidationAppError

        raise ValidationAppError("Unsupported format")
    data, filename = generate_report(db, report_type, fmt, ids)
    record(db, action="report.download", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"report_type": report_type, "format": fmt})
    media = {"csv": "text/csv", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
             "pdf": "application/pdf", "json": "application/json"}
    return Response(content=data, media_type=media[fmt],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ═══════════════════════════════════════════════════════════════════════════
# Webhooks
# ═══════════════════════════════════════════════════════════════════════════
webhooks_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


class WebhookCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    url: str = Field(min_length=8, max_length=2048)
    secret: str | None = Field(default=None, max_length=512)
    events: list[str] = Field(default_factory=list)
    is_active: bool = True


@webhooks_router.get("/endpoints")
def list_endpoints(db: DbSession, user: CurrentUser):
    from app.models.notification import WebhookEndpoint

    rows = db.query(WebhookEndpoint).order_by(WebhookEndpoint.name).all()
    return [
        {"id": e.id, "name": e.name, "url": e.url, "events": e.events or [],
         "is_active": e.is_active, "failure_count": e.failure_count,
         "last_delivery_at": e.last_delivery_at.isoformat() if e.last_delivery_at else None}
        for e in rows
    ]


@webhooks_router.post("/endpoints")
def create_endpoint(body: WebhookCreate, db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can manage webhooks")
    from app.core.security import encrypt_secret
    from app.models.notification import WebhookEndpoint

    endpoint = WebhookEndpoint(
        name=body.name, url=body.url, events=body.events, is_active=body.is_active,
        secret_encrypted=encrypt_secret(body.secret) if body.secret else None,
    )
    db.add(endpoint)
    db.commit()
    record(db, action="webhook.create", user_id=user.id, username=user.username,
           resource_type="webhook", resource_id=endpoint.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return {"id": endpoint.id, "name": endpoint.name}


@webhooks_router.get("/deliveries")
def list_deliveries(db: DbSession, user: CurrentUser, status: str | None = None,
                    limit: int = Query(50, ge=1, le=500)):
    from app.models.notification import WebhookDelivery

    q = db.query(WebhookDelivery)
    if status:
        q = q.filter(WebhookDelivery.status == status)
    rows = q.order_by(WebhookDelivery.created_at.desc()).limit(limit).all()
    return [
        {"id": d.id, "endpoint_id": d.endpoint_id, "event": d.event, "status": d.status,
         "response_code": d.response_code, "error": d.error,
         "created_at": d.created_at.isoformat() if d.created_at else None}
        for d in rows
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Search
# ═══════════════════════════════════════════════════════════════════════════
search_router = APIRouter(prefix="/search", tags=["Search"])


@search_router.get("")
def search(db: DbSession, user: CurrentUser, q: str = Query(min_length=2, max_length=200),
           limit: int = Query(25, ge=1, le=100)):
    from app.services.search_service import enterprise_search

    return enterprise_search(db, q, limit=limit)


# ═══════════════════════════════════════════════════════════════════════════
# AI assistant
# ═══════════════════════════════════════════════════════════════════════════
ai_router = APIRouter(prefix="/ai", tags=["AI Assistant"])


def _require_ai_permission(user) -> None:
    if not has_permission(user.role_name.value, P_["ai"]["use"]):
        raise PermissionDeniedError("You are not authorized to use the AI assistant")


@ai_router.get("/explain/{execution_id}")
def explain_failure(execution_id: int, db: DbSession, user: CurrentUser):
    _require_ai_permission(user)
    from app.services.ai_service import explain_failure

    return explain_failure(db, execution_id)


@ai_router.get("/troubleshoot/{execution_id}")
def troubleshoot(execution_id: int, db: DbSession, user: CurrentUser):
    _require_ai_permission(user)
    from app.services.ai_service import troubleshoot

    return troubleshoot(db, execution_id)


@ai_router.get("/recurring-failures")
def recurring_failures(db: DbSession, user: CurrentUser, days: int = Query(30, ge=1, le=365)):
    _require_ai_permission(user)
    from app.services.ai_service import detect_recurring_failures

    return {"failures": detect_recurring_failures(db, days)}


@ai_router.get("/predict-renewal-failures")
def predict_failures(db: DbSession, user: CurrentUser):
    _require_ai_permission(user)
    from app.services.ai_service import predict_renewal_failures

    return {"at_risk": predict_renewal_failures(db)}


@ai_router.get("/summarize/{certificate_id}")
def summarize(certificate_id: int, db: DbSession, user: CurrentUser):
    _require_ai_permission(user)
    from app.services.ai_service import summarize_renewal_logs

    return summarize_renewal_logs(db, certificate_id)


# ═══════════════════════════════════════════════════════════════════════════
# Backups
# ═══════════════════════════════════════════════════════════════════════════
backups_router = APIRouter(prefix="/backups", tags=["Backups"])


@backups_router.post("/run")
def run_backup(db: DbSession, user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can run backups")
    from app.services.backup_service import backup_all

    result = backup_all(db)
    record(db, action="backup.run", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details=result)
    return result


@backups_router.get("")
def list_backups(db: DbSession, user: CurrentUser, limit: int = Query(50, ge=1, le=500)):
    from app.models.certificate import Backup

    rows = db.query(Backup).order_by(Backup.created_at.desc()).limit(limit).all()
    return [
        {"id": b.id, "certificate_id": b.certificate_id, "kind": b.kind,
         "storage_path": b.storage_path, "size_bytes": b.size_bytes,
         "checksum_sha256": b.checksum_sha256, "metadata": b.backup_metadata or {},
         "restored_at": b.restored_at.isoformat() if b.restored_at else None,
         "created_at": b.created_at.isoformat() if b.created_at else None}
        for b in rows
    ]


@backups_router.post("/verify")
def verify_backups(db: DbSession, user: CurrentUser, request: Request,
                   sample_only: bool = Query(False)):
    """Verify backup integrity: archives open, members present, checksums match,
    database dumps readable. Also scheduled weekly (systemd timer / Celery beat)."""
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can verify backups")
    from app.services.backup_service import verify_backup_archives

    result = verify_backup_archives(db, sample_only=sample_only)
    record(db, action="backup.verify", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS if result.get("ok") else AuditResult.FAILURE,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={k: v for k, v in result.items() if k in ("archives_total", "archives_verified", "archives_failed")})
    return result


@backups_router.post("/{backup_id}/restore")
def restore_backup(backup_id: int, db: DbSession, user: CurrentUser, request: Request,
                   dry_run: bool = Query(False),
                   certificate_id: int | None = Query(None)):
    """Restore a certificate from a backup archive (audited)."""
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can restore backups")
    from app.models.certificate import Backup
    from app.services.backup_service import restore_certificate

    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if backup is None:
        raise NotFoundError("Backup not found")
    result = restore_certificate(
        db, backup.storage_path, certificate_id=certificate_id,
        dry_run=dry_run, restored_by=user.id,
    )
    record(db, action="backup.restore", user_id=user.id, username=user.username,
           resource_type="backup", resource_id=backup_id,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request),
           details={"archive": backup.storage_path, "dry_run": dry_run})
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Scheduled jobs (APScheduler/Celery beat config)
# ═══════════════════════════════════════════════════════════════════════════
scheduled_jobs_router = APIRouter(prefix="/scheduled-jobs", tags=["Scheduled Jobs"])


@scheduled_jobs_router.get("")
def list_scheduled_jobs(db: DbSession, user: CurrentUser):
    from app.models.job import ScheduledJob

    rows = db.query(ScheduledJob).order_by(ScheduledJob.name).all()
    return [
        {
            "id": j.id, "name": j.name, "job_type": j.job_type,
            "schedule_type": j.schedule_type, "cron_expression": j.cron_expression,
            "interval_seconds": j.interval_seconds, "enabled": j.enabled,
            "config": j.config or {}, "last_run_at": j.last_run_at.isoformat() if j.last_run_at else None,
            "next_run_at": j.next_run_at.isoformat() if j.next_run_at else None,
        }
        for j in rows
    ]


@scheduled_jobs_router.post("")
def create_scheduled_job(body: dict[str, Any], db: DbSession, user: CurrentUser,
                         request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can manage scheduled jobs")
    from app.models.job import ScheduledJob

    job = ScheduledJob(
        name=body["name"], job_type=body["job_type"],
        schedule_type=body.get("schedule_type", "cron"),
        cron_expression=body.get("cron_expression"),
        interval_seconds=body.get("interval_seconds"),
        enabled=bool(body.get("enabled", True)),
        config=body.get("config") or {},
        created_by=user.id,
    )
    db.add(job)
    db.commit()
    record(db, action="scheduled_job.create", user_id=user.id, username=user.username,
           resource_type="scheduled_job", resource_id=job.id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return {"id": job.id, "name": job.name}


@scheduled_jobs_router.patch("/{job_id}")
def update_scheduled_job(job_id: int, body: dict[str, Any], db: DbSession,
                         user: CurrentUser, request: Request):
    if user.role_name.value != "administrator":
        from app.core.exceptions import PermissionDeniedError

        raise PermissionDeniedError("Only administrators can manage scheduled jobs")
    from app.models.job import ScheduledJob

    job = db.query(ScheduledJob).filter(ScheduledJob.id == job_id).first()
    if job is None:
        raise NotFoundError("Scheduled job not found")
    for key in ("name", "job_type", "schedule_type", "cron_expression",
                "interval_seconds", "enabled", "config"):
        if key in body:
            setattr(job, key, body[key])
    db.commit()
    return {"id": job.id, "enabled": job.enabled}


def _provider_keys() -> list[str]:
    from app.services.providers.registry import get_registry

    return get_registry().available()
