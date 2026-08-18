"""Certificate lifecycle API: inventory, issue, import, renew, revoke, export,
bulk actions, favorites, executions."""


from typing import Any

from fastapi import APIRouter, File, Query, Request, UploadFile
from fastapi.responses import Response

from app.api.deps import (
    CurrentUser,
    DbSession,
    get_client_ip,
    get_user_agent,
)
from app.api.permissions import P_, has_permission
from app.core.config import settings
from app.core.exceptions import PermissionDeniedError, ValidationAppError
from app.core.logging import get_logger
from app.models.enums import AuditResult, JobTrigger, JobType
from app.schemas.certificate import (
    CertificateOut,
    CloneRequest,
    GoDaddyImportRequest,
    ImportRequest,
    IssueRequestSchema,
    PaginatedCertificates,
    RenewRequest,
    RevokeRequest,
)
from app.services import certificate_service as cert_service
from app.services.audit_service import record
from app.services.maintenance_service import ensure_not_maintenance

logger = get_logger(__name__)
router = APIRouter(prefix="/certificates", tags=["Certificates"])

Perm = P_["cert"]


# ── Inventory ───────────────────────────────────────────────────────────────
@router.get("", response_model=PaginatedCertificates)
def list_certificates(
    db: DbSession,
    user: CurrentUser,
    search: str | None = Query(default=None, max_length=200),
    status: str | None = None,
    environment: str | None = None,
    issuer: str | None = None,
    provider: str | None = None,
    key_type: str | None = None,
    renewal_status: str | None = None,
    cert_type: str | None = None,
    owner_id: int | None = None,
    tags: str | None = None,
    auto_renew: str | None = None,
    sort_by: str = Query(default="valid_until", max_length=32),
    sort_dir: str = Query(default="asc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=500),
):
    filters = {
        "status": status, "environment": environment, "issuer": issuer,
        "provider": provider, "key_type": key_type, "renewal_status": renewal_status,
        "cert_type": cert_type, "owner_id": owner_id, "tags": tags, "auto_renew": auto_renew,
    }
    rows, total, summary = cert_service.list_certificates(
        db, search=search, filters=filters, sort_by=sort_by, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )
    return PaginatedCertificates(
        items=[CertificateOut.model_validate(c) for c in rows],
        total=total, page=page, page_size=page_size,
        pages=(total + page_size - 1) // page_size, summary=summary,
    )


@router.get("/{certificate_id}", response_model=CertificateOut)
def get_certificate(certificate_id: int, db: DbSession, user: CurrentUser):
    return CertificateOut.model_validate(cert_service.get_certificate(db, certificate_id))


# ── Wizard validation endpoints ─────────────────────────────────────────────
@router.post("/wizard/validate/domains")
def wizard_validate_domains(body: dict[str, Any], db: DbSession, user: CurrentUser):
    from app.core.domain_utils import validate_domain_list

    domains = validate_domain_list(body.get("domains", []), allow_wildcard=True)
    cert_type = cert_service._cert_type_for(domains)
    return {"ok": True, "domains": domains, "cert_type": cert_type}


@router.post("/wizard/validate/validation-method")
def wizard_validate_method(body: dict[str, Any], db: DbSession, user: CurrentUser):
    from app.models.enums import ValidationMethod

    method = body.get("validation_method", "")
    if method not in ValidationMethod.values():
        raise ValidationAppError(f"Invalid validation method: {method}")
    return {"ok": True, "validation_method": method}


# ── Issue ───────────────────────────────────────────────────────────────────
@router.post("/issue")
def issue_certificate(
    body: IssueRequestSchema,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    return _issue(body, db, user, request)


@router.post("")
def create_and_issue(
    body: IssueRequestSchema,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    return _issue(body, db, user, request)


def _issue(body: IssueRequestSchema, db, user, request):
    if not has_permission(user.role_name.value, "certificate:issue"):
        raise PermissionDeniedError("You are not authorized to issue certificates")
    ensure_not_maintenance(db, operation="certificate issuance")
    payload = body.model_dump()

    if settings.celery_task_always_eager:
        cert = cert_service.issue_certificate(
            db, payload=payload, user=user, trigger=JobTrigger.API.value,
        )
        return {
            "certificate_id": cert.id,
            "status": cert.status,
            "execution": _serialize_execution(getattr(cert, "extra_execution", None)),
        }

    # Async path: create the row only (execute=False — no certbot invocation
    # in this request), then hand off to the worker. Previously this branch
    # was unreachable dead code: issue_certificate() always executed inline
    # regardless of settings.celery_task_always_eager, so every UI-triggered
    # issuance actually ran synchronously inside the certmgr-api process
    # (whatever OS user that runs as) rather than on the worker — breaking
    # sites where the worker is deliberately configured with elevated
    # privileges certbot hooks need (see
    # docs/administration.md#running-the-worker-as-root-for-root-only-hook-scripts)
    # that the api process intentionally doesn't have.
    cert = cert_service.issue_certificate(
        db, payload=payload, user=user, trigger=JobTrigger.API.value, execute=False,
    )
    from app.tasks.celery_app import run_job_async

    run_job_async(JobType.ISSUE.value, cert.id, user.id if user else None)
    return {
        "certificate_id": cert.id,
        "status": "queued",
        "message": "Issuance queued — poll /certificates/{id} for status and "
                   "/certificates/{id}/executions for live logs",
    }


# ── Lifecycle actions ───────────────────────────────────────────────────────
@router.post("/{certificate_id}/renew")
def renew_certificate(
    certificate_id: int,
    body: RenewRequest,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    if not has_permission(user.role_name.value, Perm["renew"]):
        raise PermissionDeniedError("You are not authorized to renew certificates")
    ensure_not_maintenance(db, operation="renewal")
    execution = cert_service.renew_certificate(
        db, certificate_id, force=body.force, user=user, trigger=JobTrigger.API.value
    )
    return {"certificate_id": certificate_id, "execution": _serialize_execution(execution)}


@router.post("/{certificate_id}/revoke")
def revoke_certificate(
    certificate_id: int,
    body: RevokeRequest,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    if not has_permission(user.role_name.value, Perm["revoke"]):
        raise PermissionDeniedError("You are not authorized to revoke certificates")
    ensure_not_maintenance(db, operation="revocation")
    execution = cert_service.revoke_certificate(
        db, certificate_id, reason=body.reason, delete_after=body.delete_after,
        user=user, trigger=JobTrigger.API.value,
    )
    return {"certificate_id": certificate_id, "execution": _serialize_execution(execution)}


@router.delete("/{certificate_id}")
def delete_certificate(
    certificate_id: int,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    if not has_permission(user.role_name.value, Perm["delete"]):
        raise PermissionDeniedError("You are not authorized to delete certificates")
    cert_service.delete_certificate(db, certificate_id, user=user)
    return {"certificate_id": certificate_id, "deleted": True}


@router.post("/{certificate_id}/clone")
def clone_certificate(
    certificate_id: int,
    body: CloneRequest,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    if not has_permission(user.role_name.value, Perm["issue"]):
        raise PermissionDeniedError("You are not authorized to issue certificates")
    new_cert = cert_service.clone_certificate(db, certificate_id, new_domains=body.domains, user=user)
    return {"certificate_id": new_cert.id, "status": new_cert.status}


# ── Import ──────────────────────────────────────────────────────────────────
@router.post("/import/upload")
async def import_upload(
    request: Request,
    db: DbSession,
    user: CurrentUser,
    certificate: UploadFile = File(..., description="Certificate (PEM/CRT/CER)"),
    private_key: UploadFile | None = File(None, description="Private key (PEM)"),
    chain: UploadFile | None = File(None, description="Chain (PEM)"),
    pfx: UploadFile | None = File(None, description="PFX/PKCS12 bundle"),
    pfx_password: str | None = Query(default=None, max_length=512),
    environment: str = Query(default="production"),
    auto_renew: bool = Query(default=False),
    tags: str | None = Query(default=None),
    notes: str | None = Query(default=None, max_length=4000),
):
    if not has_permission(user.role_name.value, Perm["import"]):
        raise PermissionDeniedError("You are not authorized to import certificates")
    ensure_not_maintenance(db, operation="import")

    def _read_limited(upload: UploadFile) -> bytes:
        data = upload.file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise ValidationAppError("Upload exceeds size limit")
        return data

    cert_data = _read_limited(certificate) if certificate else None
    key_data = _read_limited(private_key) if private_key else None
    chain_data = _read_limited(chain) if chain else None
    pfx_data = _read_limited(pfx) if pfx else None

    payload = {
        "environment": environment,
        "auto_renew": auto_renew,
        "tags": [t.strip() for t in (tags or "").split(",") if t.strip()],
        "notes": notes,
    }
    cert = cert_service.import_certificate(
        db, cert_data=cert_data, key_data=key_data, chain_data=chain_data,
        pfx_data=pfx_data, pfx_password=pfx_password, payload=payload, user=user,
    )
    return {"certificate_id": cert.id, "domain": cert.domain, "fingerprint": cert.fingerprint_sha256}


@router.post("/import/paths")
def import_from_paths(
    body: ImportRequest,
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    if not has_permission(user.role_name.value, Perm["import"]):
        raise PermissionDeniedError("You are not authorized to import certificates")
    ensure_not_maintenance(db, operation="import")
    cert = cert_service.import_from_paths(
        db, cert_path=body.cert_path, key_path=body.key_path, chain_path=body.chain_path,
        payload={"environment": body.environment, "auto_renew": body.auto_renew,
                 "tags": body.tags, "notes": body.notes, "owner_id": body.owner_id},
        user=user,
    )
    return {"certificate_id": cert.id, "domain": cert.domain}


@router.post("/import/godaddy")
def import_from_godaddy(body: GoDaddyImportRequest, db: DbSession, user: CurrentUser, request: Request):
    if not has_permission(user.role_name.value, Perm["import"]):
        raise PermissionDeniedError("You are not authorized to import certificates")
    ensure_not_maintenance(db, operation="import")
    from app.services.godaddy_service import fetch_certificate_from_godaddy

    result = fetch_certificate_from_godaddy(
        db, domain=body.domain, certificate_id=body.certificate_id,
        environment=body.environment, auto_renew=body.auto_renew, user=user,
    )
    record(db, action="certificate.import.godaddy", user_id=user.id, username=user.username,
           resource_type="certificate", resource_id=result["certificate_id"], result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={"godaddy_certificate_id": result["godaddy_certificate_id"]})
    return result


# ── Bulk actions ────────────────────────────────────────────────────────────
@router.post("/bulk")
def bulk_actions(
    body: dict[str, Any],
    db: DbSession,
    user: CurrentUser,
    request: Request,
):
    action = body.get("action")
    ids = body.get("ids", [])
    options = body.get("options") or {}
    if action not in {"renew", "revoke", "deploy", "issue", "delete"}:
        raise ValidationAppError(f"Unsupported bulk action: {action}")
    if not isinstance(ids, list) or not ids or len(ids) > 500:
        raise ValidationAppError("ids must be a non-empty list (max 500)")
    # Require both the general bulk permission and the permission for the
    # specific action requested — otherwise bulk would let a role escalate
    # past what it's individually allowed to do (e.g. a role with bulk but
    # not revoke could mass-revoke via this endpoint).
    if not has_permission(user.role_name.value, Perm["bulk"]) or not has_permission(
        user.role_name.value, Perm[action]
    ):
        raise PermissionDeniedError(f"You are not authorized to bulk {action} certificates")
    ensure_not_maintenance(db, operation=f"bulk {action}")
    result = cert_service.bulk_action(db, action=action, ids=ids, user=user, options=options)
    record(db, action=f"certificate.bulk.{action}", user_id=user.id, username=user.username,
           result=AuditResult.SUCCESS, ip_address=get_client_ip(request),
           user_agent=get_user_agent(request), details={"ids": ids, "result": result})
    return result


# ── Favorites / tags ────────────────────────────────────────────────────────
@router.post("/{certificate_id}/favorite")
def set_favorite(certificate_id: int, body: dict[str, bool], db: DbSession, user: CurrentUser):
    cert = cert_service.get_certificate(db, certificate_id, load_relations=False)
    cert.favorite = bool(body.get("favorite", not cert.favorite))
    db.commit()
    return {"certificate_id": certificate_id, "favorite": cert.favorite}


@router.post("/{certificate_id}/tags")
def set_tags(certificate_id: int, body: dict[str, list[str]], db: DbSession, user: CurrentUser):
    from app.models.certificate import Tag

    cert = cert_service.get_certificate(db, certificate_id, load_relations=True)
    cert.tags = []
    db.flush()
    for name in body.get("tags", []):
        tag = db.query(Tag).filter(Tag.name == name).first() or Tag(name=name)
        cert.tags.append(tag)
    db.commit()
    return {"certificate_id": certificate_id, "tags": [t.name for t in cert.tags]}


# ── Executions / history ────────────────────────────────────────────────────
@router.get("/{certificate_id}/executions")
def certificate_executions(certificate_id: int, db: DbSession, user: CurrentUser,
                           page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    from app.services.job_service import list_executions

    rows, total = list_executions(db, certificate_id=certificate_id, page=page, page_size=page_size)
    return {
        "items": [_serialize_execution(r) for r in rows],
        "total": total, "page": page, "page_size": page_size,
    }


# ── Downloads (audited, permission-gated) ───────────────────────────────────
@router.get("/{certificate_id}/download/{fmt}")
def download_certificate(
    certificate_id: int,
    fmt: str,
    db: DbSession,
    user: CurrentUser,
    request: Request,
    include_key: bool = Query(default=True),
    password: str | None = Query(default=None, max_length=128),
):
    allowed = {"zip", "pem", "key", "chain", "fullchain", "pfx"}
    if fmt not in allowed:
        raise ValidationAppError(f"Unsupported format: {fmt}")
    if fmt == "key":
        _require_key_permission(user)
    elif include_key and fmt in ("zip", "pfx"):
        _require_key_permission(user)

    data = cert_service.export_bundle(db, certificate_id, format=fmt, include_key=include_key,
                                      password=password or "")
    record(db, action="certificate.download", user_id=user.id, username=user.username,
           resource_type="certificate", resource_id=certificate_id, result=AuditResult.SUCCESS,
           ip_address=get_client_ip(request), user_agent=get_user_agent(request),
           details={"format": fmt, "include_key": include_key})
    media = {
        "zip": "application/zip", "pem": "application/x-pem-file", "key": "application/x-pem-file",
        "chain": "application/x-pem-file", "fullchain": "application/x-pem-file",
        "pfx": "application/x-pkcs12",
    }
    ext = {"zip": "zip", "pem": "pem", "key": "key", "chain": "chain.pem",
           "fullchain": "fullchain.pem", "pfx": "pfx"}[fmt]
    return Response(
        content=data,
        media_type=media[fmt],
        headers={"Content-Disposition": f'attachment; filename="certificate-{certificate_id}.{ext}"'},
    )


def _require_key_permission(user) -> None:
    if not has_permission(user.role_name.value, "certificate:download_key"):
        raise PermissionDeniedError("You are not authorized to download private keys")


def _serialize_execution(execution) -> dict[str, Any] | None:
    if execution is None:
        return None
    return {
        "id": execution.id,
        "job_type": execution.job_type,
        "status": execution.status,
        "exit_code": execution.exit_code,
        "stdout": (execution.stdout or "")[-20000:],
        "stderr": (execution.stderr or "")[-20000:],
        "error_message": execution.error_message,
        "execution_time_ms": execution.execution_time_ms,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
        "task_id": execution.task_id,
    }
