"""Certificate lifecycle: issue, renew, revoke, import, inventory, export.

This service orchestrates providers (Certbot/OpenSSL), the encrypted file
store, x.509 parsing and audit — the single source of truth for lifecycle
operations. It is used by both the REST API and Celery workers.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any, NamedTuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.domain_utils import (
    validate_domain_list,
    validate_email,
)
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ValidationAppError,
)
from app.core.logging import get_logger
from app.core.timeutils import ensure_aware, utcnow
from app.models.certificate import Certificate, CertificateDomain, Tag
from app.models.enums import (
    AuditResult,
    CertificateStatus,
    CertificateType,
    JobStatus,
    JobTrigger,
    JobType,
    KeyType,
    RenewalStatus,
    ValidationMethod,
)
from app.models.job import JobExecution
from app.models.user import User
from app.services import storage as storage_module
from app.services.audit_service import record
from app.services.providers.base import IssueRequest
from app.services.providers.registry import get_registry
from app.services.x509_utils import (
    parse_certificate,
    parse_pfx,
    parse_private_key,
    public_key_matches,
)

logger = get_logger(__name__)

# Validation methods that require hooks on the issue request
_HOOKED_METHODS = {
    ValidationMethod.CUSTOM.value,
    ValidationMethod.MANUAL_DNS.value,
    ValidationMethod.MANUAL_HTTP.value,
}

# ── Inventory / listing ─────────────────────────────────────────────────────

_FILTER_MAP = {
    "status": Certificate.status,
    "environment": Certificate.environment,
    "issuer": Certificate.issuer,
    "provider": Certificate.provider_name,
    "key_type": Certificate.key_type,
    "renewal_status": Certificate.renewal_status,
    "cert_type": Certificate.cert_type,
    "owner_id": Certificate.owner_id,
    "auto_renew": Certificate.auto_renew,
}


def _sort_expression(column, direction: str, dialect_name: str):
    """Column sort expression — MySQL/MariaDB lack `NULLS LAST` support."""
    order = column.asc() if direction == "asc" else column.desc()
    if dialect_name in ("mysql", "mariadb"):
        return order
    return order.nulls_last()


def list_certificates(
    db: Session,
    *,
    search: str | None = None,
    filters: dict[str, Any] | None = None,
    sort_by: str = "valid_until",
    sort_dir: str = "asc",
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[Certificate], int, dict]:
    q = db.query(Certificate)

    if search:
        like = f"%{search}%"
        q = q.filter(
            or_(
                Certificate.domain.ilike(like),
                Certificate.issuer.ilike(like),
                Certificate.subject.ilike(like),
                Certificate.serial_number.ilike(like),
                Certificate.fingerprint_sha256.ilike(like),
                Certificate.cert_name.ilike(like),
            )
        )

    for key, value in (filters or {}).items():
        col = _FILTER_MAP.get(key)
        if col is not None and value not in (None, ""):
            if key == "auto_renew":
                q = q.filter(col.is_(str(value).lower() == "true"))
            else:
                q = q.filter(col == value)

    # Tag filtering
    tag_names = (filters or {}).get("tags")
    if tag_names:
        names = [t.strip() for t in str(tag_names).split(",") if t.strip()]
        if names:
            q = q.join(Certificate.tags).filter(Tag.name.in_(names)).distinct()

    total = q.count()

    sortable = {
        "domain": Certificate.domain,
        "valid_until": Certificate.valid_until,
        "created_at": Certificate.created_at,
        "issuer": Certificate.issuer,
        "status": Certificate.status,
        "environment": Certificate.environment,
    }
    order_col = sortable.get(sort_by, Certificate.valid_until)
    dialect = db.get_bind().dialect.name
    q = q.order_by(_sort_expression(order_col, sort_dir, dialect))

    rows = (
        q.options(joinedload(Certificate.tags), joinedload(Certificate.owner))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    summary = _status_summary(db)
    return rows, total, summary


def _status_summary(db: Session) -> dict:
    rows = (
        db.query(Certificate.status, func.count(Certificate.id))
        .group_by(Certificate.status)
        .all()
    )
    return {status: count for status, count in rows}


def get_certificate(db: Session, certificate_id: int, *, load_relations: bool = True) -> Certificate:
    q = db.query(Certificate)
    if load_relations:
        q = q.options(
            joinedload(Certificate.tags),
            joinedload(Certificate.owner),
            joinedload(Certificate.domains),
        )
    cert = q.filter(Certificate.id == certificate_id).first()
    if cert is None:
        raise NotFoundError(f"Certificate {certificate_id} not found")
    return cert


# ── Issue ───────────────────────────────────────────────────────────────────

def _resolve_key_type(key_type: str) -> str:
    if key_type in (KeyType.RSA_2048.value, KeyType.RSA_4096.value,
                    KeyType.ECDSA_P256.value, KeyType.ECDSA_P384.value):
        return key_type
    raise ValidationAppError(f"Unsupported key type: {key_type}")


def _cert_type_for(domains: list[str]) -> str:
    if any(d.startswith("*.") for d in domains):
        return CertificateType.WILDCARD.value
    if len(domains) > 1:
        return CertificateType.MULTI.value
    return CertificateType.SINGLE.value


def build_issue_request(db: Session, payload: dict[str, Any], cert_name: str | None = None) -> IssueRequest:
    domains = validate_domain_list(payload.get("domains", []), allow_wildcard=True)
    method = payload.get("validation_method", ValidationMethod.HTTP_01.value)
    if method not in ValidationMethod.values():
        raise ValidationAppError(f"Invalid validation method: {method}")
    email = payload.get("email") or settings.default_letsencrypt_email
    validate_email(email)

    auth_hook = cleanup_hook = None
    hook_env: dict[str, str] = {}
    hook_user = hook_cwd = None
    hook_timeout = 300
    ssh_key = ssh_host = None

    if method in _HOOKED_METHODS or payload.get("auth_hook_id") or payload.get("cleanup_hook_id"):
        hook = _resolve_hooks(db, payload)
        if hook:
            auth_hook, cleanup_hook, hook_env, hook_user, hook_cwd, hook_timeout, ssh_key, ssh_host = hook

    return IssueRequest(
        domains=domains,
        email=email,
        key_type=_resolve_key_type(payload.get("key_type", KeyType.RSA_2048.value)),
        validation_method=method,
        environment=payload.get("environment", settings.default_environment),
        staging=bool(payload.get("staging", settings.default_staging)),
        dry_run=bool(payload.get("dry_run", False)),
        webroot_path=payload.get("webroot_path"),
        standalone_port=payload.get("standalone_port"),
        auth_hook=auth_hook,
        cleanup_hook=cleanup_hook,
        hook_env=hook_env,
        hook_execution_user=hook_user,
        hook_working_directory=hook_cwd,
        hook_timeout=hook_timeout,
        ssh_private_key_encrypted=ssh_key,
        ssh_target_host=ssh_host,
        cert_name=cert_name,
        extra=payload.get("extra") or {},
    )


class ResolvedHooks(NamedTuple):
    auth_hook: str | None
    cleanup_hook: str | None
    env: dict[str, str]
    execution_user: str | None
    working_directory: str | None
    timeout_seconds: int
    ssh_private_key_encrypted: str | None
    ssh_target_host: str | None


def _resolve_hooks(db: Session, payload: dict[str, Any]) -> ResolvedHooks | None:
    """Resolve hook rows (or inline paths) to certbot hook configuration."""
    from app.models.certificate import Hook

    auth_hook = payload.get("auth_hook")
    cleanup_hook = payload.get("cleanup_hook")
    auth_row = cleanup_row = None
    if payload.get("auth_hook_id"):
        auth_row = db.query(Hook).filter(Hook.id == payload["auth_hook_id"], Hook.is_active.is_(True)).first()
        if auth_row is None:
            raise NotFoundError("Authentication hook not found")
        auth_hook = auth_row.script_path
    if payload.get("cleanup_hook_id"):
        cleanup_row = db.query(Hook).filter(Hook.id == payload["cleanup_hook_id"], Hook.is_active.is_(True)).first()
        if cleanup_row is None:
            raise NotFoundError("Cleanup hook not found")
        cleanup_hook = cleanup_row.script_path

    if not auth_hook and not cleanup_hook:
        return None

    # Merge inline env vars
    env: dict[str, str] = {}
    if auth_row:
        env.update(auth_row.env_vars or {})
    if cleanup_row:
        env.update(cleanup_row.env_vars or {})
    env.update(payload.get("hook_env") or {})

    hook_row = auth_row or cleanup_row
    # An SSH credential may live on either hook row; auth_row wins if both
    # happen to have one set (matches which hook actually needs to SSH out
    # in the common case — the authenticator, not the cleanup script).
    ssh_row = auth_row if (auth_row and auth_row.ssh_private_key_encrypted) else cleanup_row

    return ResolvedHooks(
        auth_hook=auth_hook,
        cleanup_hook=cleanup_hook,
        env=env,
        execution_user=hook_row.execution_user if hook_row else None,
        working_directory=hook_row.working_directory if hook_row else None,
        timeout_seconds=hook_row.timeout_seconds if hook_row else 300,
        ssh_private_key_encrypted=ssh_row.ssh_private_key_encrypted if ssh_row else None,
        ssh_target_host=ssh_row.ssh_target_host if ssh_row else None,
    )


def issue_certificate(
    db: Session,
    *,
    payload: dict[str, Any],
    user: User | None = None,
    trigger: str = JobTrigger.API.value,
    execute: bool = True,
) -> Certificate:
    """Create + execute an issuance. `execute=False` prepares but doesn't run."""
    cert_name = payload.get("cert_name") or _default_cert_name(payload.get("domains", []))
    # Note: re-issuance of an existing domain is permitted; duplicates are
    # handled at fingerprint level during import/ingest.
    method = payload.get("validation_method", ValidationMethod.HTTP_01.value)

    # Resolve hooks now (not just at execution time) so async/queued issuance
    # — which only gets a certificate_id, not this payload — can reconstruct
    # the exact same certbot invocation from the persisted row.
    auth_hook = cleanup_hook = None
    hook_env: dict[str, str] = {}
    hook_user = hook_cwd = hook_timeout = None
    ssh_key = ssh_host = None
    if method in _HOOKED_METHODS or payload.get("auth_hook_id") or payload.get("cleanup_hook_id"):
        hook = _resolve_hooks(db, payload)
        if hook:
            auth_hook, cleanup_hook, hook_env, hook_user, hook_cwd, hook_timeout, ssh_key, ssh_host = hook

    cert = Certificate(
        domain=payload["domains"][0].lower().rstrip("."),
        cert_name=cert_name,
        sans=sorted({d.lower().rstrip(".") for d in payload["domains"]}),
        is_wildcard=any(d.startswith("*.") for d in payload["domains"]),
        cert_type=_cert_type_for(payload["domains"]),
        environment=payload.get("environment", settings.default_environment),
        provider_name=payload.get("provider", "letsencrypt"),
        validation_method=method,
        key_type=payload.get("key_type", KeyType.RSA_2048.value),
        status=CertificateStatus.ISSUING.value,
        auto_renew=payload.get("auto_renew", True),
        renewal_status=RenewalStatus.NONE.value,
        staging=bool(payload.get("staging", False)),
        dry_run=bool(payload.get("dry_run", False)),
        owner_id=payload.get("owner_id") or (user.id if user else None),
        notes=payload.get("notes"),
        managed_by_platform=True,
        email=payload.get("email"),
        webroot_path=payload.get("webroot_path"),
        standalone_port=payload.get("standalone_port"),
        auth_hook_path=auth_hook,
        cleanup_hook_path=cleanup_hook,
        hook_env=hook_env or None,
        hook_execution_user=hook_user,
        hook_working_directory=hook_cwd,
        hook_timeout=hook_timeout,
        ssh_private_key_encrypted=ssh_key,
        ssh_target_host=ssh_host,
    )
    db.add(cert)
    db.flush()

    for idx, domain in enumerate(cert.sans):
        db.add(CertificateDomain(
            certificate_id=cert.id,
            domain=domain,
            is_primary=(idx == 0),
            is_wildcard=domain.startswith("*."),
        ))

    # Tags
    for name in payload.get("tags") or []:
        tag = db.query(Tag).filter(Tag.name == name).first()
        if tag is None:
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
        if tag not in cert.tags:
            cert.tags.append(tag)

    db.commit()

    if execute:
        # Pass the original payload through directly — it's still in scope
        # here (synchronous path) and has fields the Certificate row can't
        # carry (auth_hook/cleanup_hook/webroot_path/standalone_port/hook_env/
        # a caller-supplied email). Only the async Celery path (which only
        # gets a serializable certificate_id) needs _execute_issuance's
        # from-the-row reconstruction.
        execution = _execute_issuance(db, cert, user, trigger, payload=payload)
        cert = get_certificate(db, cert.id)
        cert.extra_execution = execution  # type: ignore[attr-defined]
    return cert


def _default_cert_name(domains: list[str]) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "-", domains[0].lstrip("*."))[:120]


def _provider_for(db: Session, cert: Certificate):
    """Instantiate the certificate's provider with its stored (decrypted) config."""
    import json as _json

    from app.core.security import decrypt_secret
    from app.models.certificate import Provider

    config: dict[str, Any] = {}
    row = db.query(Provider).filter(Provider.name == cert.provider_name).first()
    if row and row.config_encrypted:
        try:
            config = _json.loads(decrypt_secret(row.config_encrypted))
        except Exception:  # noqa: BLE001
            logger.warning("Cannot decrypt provider config for %s", cert.provider_name)
    return get_registry().create(cert.provider_name, config)


def _execute_issuance(db: Session, cert: Certificate, user: User | None,
                      trigger: str, payload: dict[str, Any] | None = None) -> JobExecution:
    """Run the provider synchronously and update the certificate row."""
    from app.core.logging import Timer

    timer = Timer()
    execution = JobExecution(
        job_type=JobType.ISSUE.value,
        certificate_id=cert.id,
        trigger=trigger,
        status=JobStatus.RUNNING.value,
        started_at=utcnow(),
        created_by=user.id if user else None,
    )
    db.add(execution)
    db.commit()

    try:
        provider = _provider_for(db, cert)
    except KeyError:
        execution.status = JobStatus.FAILED.value
        execution.exit_code = 127
        execution.stderr = f"Unknown provider: {cert.provider_name}"
        execution.error_message = f"Unknown provider: {cert.provider_name}"
        execution.execution_time_ms = timer.elapsed_ms()
        execution.finished_at = utcnow()
        cert.status = CertificateStatus.FAILED.value
        cert.renewal_status = RenewalStatus.FAILED.value
        cert.renewal_error = f"Unknown provider: {cert.provider_name}"
        db.commit()
        return execution

    reconstructed = payload is None
    if reconstructed:
        # Async path (Celery task only has certificate_id, not the original
        # in-memory payload) — reconstruct from the persisted row, which
        # issue_certificate() populated with the resolved hook/webroot/
        # standalone/email configuration at creation time.
        payload = {
            "domains": [cert.domain] + [d for d in cert.sans if d != cert.domain],
            "validation_method": cert.validation_method,
            "key_type": cert.key_type,
            "environment": cert.environment,
            "staging": cert.staging,
            "dry_run": cert.dry_run,
            "email": cert.email,
            "webroot_path": cert.webroot_path,
            "standalone_port": cert.standalone_port,
            "auth_hook": cert.auth_hook_path,
            "cleanup_hook": cert.cleanup_hook_path,
            "hook_env": cert.hook_env or {},
        }
    request = build_issue_request(db, payload, cert_name=cert.cert_name)
    if reconstructed and (cert.auth_hook_path or cert.cleanup_hook_path):
        # _resolve_hooks() has no hook_id to look up here, so it can't
        # re-derive execution_user/working_directory/timeout from the bare
        # persisted path — restore them from what issue_certificate()
        # captured at creation time.
        request.hook_execution_user = cert.hook_execution_user
        request.hook_working_directory = cert.hook_working_directory
        request.hook_timeout = cert.hook_timeout or request.hook_timeout
        request.ssh_private_key_encrypted = cert.ssh_private_key_encrypted
        request.ssh_target_host = cert.ssh_target_host
    request.email = request.email or settings.default_letsencrypt_email

    result = provider.issue(request)
    execution.exit_code = result.exit_code
    execution.stdout = result.stdout[-100_000:]
    execution.stderr = result.stderr[-100_000:]
    execution.execution_time_ms = result.duration_ms or timer.elapsed_ms()
    execution.finished_at = utcnow()

    if result.success:
        cert.status = CertificateStatus.ACTIVE.value
        cert.renewal_status = RenewalStatus.NONE.value
        cert.last_renewed_at = utcnow()
        _ingest_material(db, cert, cert_path=result.cert_path, key_path=result.key_path,
                        chain_path=result.chain_path, fullchain_path=result.fullchain_path,
                        cert_name=result.cert_name)
        execution.status = JobStatus.SUCCESS.value
        record(db, action="certificate.issue", user_id=user.id if user else None,
               username=user.username if user else None,
               resource_type="certificate", resource_id=cert.id,
               result=AuditResult.SUCCESS, duration_ms=execution.execution_time_ms)
        _notify(db, "issued", cert)
    else:
        _error = (result.error or (result.stderr or "").strip()[-2000:] or "Unknown provider error")
        cert.status = CertificateStatus.FAILED.value
        cert.renewal_status = RenewalStatus.FAILED.value
        cert.renewal_error = _error[:4000]
        execution.status = JobStatus.FAILED.value
        execution.error_message = _error[:4000]
        record(db, action="certificate.issue", user_id=user.id if user else None,
               username=user.username if user else None,
               resource_type="certificate", resource_id=cert.id,
               result=AuditResult.FAILURE, duration_ms=execution.execution_time_ms,
               details={"error": result.error})
        _notify(db, "failure", cert)
    db.commit()
    return execution


def _ingest_material(db: Session, cert: Certificate, *, cert_path: str | None,
                     key_path: str | None, chain_path: str | None = None,
                     fullchain_path: str | None = None, cert_name: str | None = None) -> None:
    """Copy issued material into the encrypted file store + refresh metadata."""
    if not cert_path or not os.path.exists(cert_path):
        raise ValidationAppError(f"Issued certificate file missing: {cert_path}")

    store = storage_module.get_file_store()
    raw = Path(cert_path).read_bytes()
    _cert_obj, meta = parse_certificate(raw)

    store_dir = store.cert_dir(meta.fingerprint_sha256)
    (store_dir / "cert.pem").write_bytes(raw)
    cert.cert_path = str(store_dir / "cert.pem")

    if fullchain_path and os.path.exists(fullchain_path):
        fc = Path(fullchain_path).read_bytes()
        (store_dir / "fullchain.pem").write_bytes(fc)
        cert.fullchain_path = str(store_dir / "fullchain.pem")

    if chain_path and os.path.exists(chain_path):
        ch = Path(chain_path).read_bytes()
        (store_dir / "chain.pem").write_bytes(ch)
        cert.chain_path = str(store_dir / "chain.pem")
    elif fullchain_path and os.path.exists(fullchain_path):
        # derive chain = fullchain minus leaf
        leaf_pem = raw
        fc = Path(fullchain_path).read_bytes()
        chain_bytes = fc.replace(leaf_pem, b"")
        if chain_bytes.strip():
            (store_dir / "chain.pem").write_bytes(chain_bytes)
            cert.chain_path = str(store_dir / "chain.pem")

    if key_path and os.path.exists(key_path):
        key_pem = Path(key_path).read_bytes()
        cert.key_path = store.write_private_key(meta.fingerprint_sha256, key_pem)

    _apply_metadata(cert, meta, cert_name=cert_name)


def _apply_metadata(cert: Certificate, meta, *, cert_name: str | None = None) -> None:
    cert.subject = meta.subject
    cert.issuer = meta.issuer
    cert.serial_number = meta.serial_number
    cert.fingerprint_sha256 = meta.fingerprint_sha256
    cert.public_key_algorithm = meta.public_key_algorithm
    cert.key_type = meta.key_type if meta.key_type in KeyType.values() else cert.key_type or meta.key_type
    cert.key_size = meta.key_size
    cert.signature_algorithm = meta.signature_algorithm
    cert.valid_from = meta.valid_from
    cert.valid_until = meta.valid_until
    cert.is_wildcard = meta.is_wildcard or cert.is_wildcard
    if meta.sans:
        cert.sans = sorted(set(meta.sans))
    if cert_name:
        cert.cert_name = cert_name


# ── Renew ───────────────────────────────────────────────────────────────────

def due_certificates(db: Session, threshold_days: int | None = None) -> list[Certificate]:
    threshold = threshold_days or settings.renewal_threshold_days
    cutoff = utcnow() + timedelta(days=threshold)
    return (
        db.query(Certificate)
        .filter(
            Certificate.auto_renew.is_(True),
            Certificate.status.in_([CertificateStatus.ACTIVE.value, CertificateStatus.EXPIRING.value]),
            Certificate.valid_until.isnot(None),
            Certificate.valid_until <= cutoff,
        )
        .all()
    )


def renew_certificate(db: Session, certificate_id: int, *, force: bool = False,
                      user: User | None = None, trigger: str = JobTrigger.API.value) -> JobExecution:
    cert = get_certificate(db, certificate_id, load_relations=False)
    if not cert.managed_by_platform or not cert.cert_name:
        raise ValidationAppError("Only platform-managed certificates can be renewed")

    if cert.renewal_status == RenewalStatus.IN_PROGRESS.value:
        raise ConflictError("Renewal already in progress for this certificate")

    from app.core.logging import Timer

    timer = Timer()
    cert.renewal_status = RenewalStatus.IN_PROGRESS.value
    cert.status = CertificateStatus.RENEWING.value
    execution = JobExecution(
        job_type=JobType.RENEW.value,
        certificate_id=cert.id,
        trigger=trigger,
        status=JobStatus.RUNNING.value,
        started_at=utcnow(),
        created_by=user.id if user else None,
    )
    db.add(execution)
    db.commit()

    provider = _provider_for(db, cert)
    result = provider.renew(cert.cert_name, force=force, staging=cert.staging)

    execution.exit_code = result.exit_code
    execution.stdout = (result.stdout or "")[-100_000:]
    execution.stderr = (result.stderr or "")[-100_000:]
    execution.execution_time_ms = result.duration_ms or timer.elapsed_ms()
    execution.finished_at = utcnow()

    if result.success:
        if result.renewed and result.cert_path and os.path.exists(result.cert_path):
            _ingest_material(db, cert, cert_path=result.cert_path, key_path=result.key_path,
                             chain_path=result.chain_path, fullchain_path=result.fullchain_path)
            cert.last_renewed_at = utcnow()
            cert.renewal_status = RenewalStatus.SUCCESS.value
            cert.status = CertificateStatus.ACTIVE.value
            cert.renewal_error = None
            record(db, action="certificate.renew", user_id=user.id if user else None,
                   username=user.username if user else None,
                   resource_type="certificate", resource_id=cert.id,
                   result=AuditResult.SUCCESS, duration_ms=execution.execution_time_ms)
            _notify(db, "renewed", cert)
        else:
            # "not yet due" or dry-run — treat as success/no-op
            cert.renewal_status = RenewalStatus.SKIPPED.value
            cert.status = CertificateStatus.ACTIVE.value
        execution.status = JobStatus.SUCCESS.value
    else:
        cert.renewal_status = RenewalStatus.FAILED.value
        cert.renewal_error = (result.error or "Unknown renewal error")[:4000]
        cert.status = CertificateStatus.ACTIVE.value if cert.valid_until and ensure_aware(cert.valid_until) > utcnow() else CertificateStatus.EXPIRING.value
        execution.status = JobStatus.FAILED.value
        execution.error_message = (result.error or "Unknown renewal error")[:4000]
        record(db, action="certificate.renew", user_id=user.id if user else None,
               username=user.username if user else None,
               resource_type="certificate", resource_id=cert.id,
               result=AuditResult.FAILURE, duration_ms=execution.execution_time_ms,
               details={"error": result.error})
        _notify(db, "failure", cert)
    db.commit()
    return execution


# ── Revoke ──────────────────────────────────────────────────────────────────

def revoke_certificate(db: Session, certificate_id: int, *, reason: str = "unspecified",
                       delete_after: bool = True, user: User | None = None,
                       trigger: str = JobTrigger.API.value) -> JobExecution:
    cert = get_certificate(db, certificate_id, load_relations=False)
    provider = _provider_for(db, cert)

    result = provider.revoke(cert.cert_path or "", reason=reason)
    execution = JobExecution(
        job_type=JobType.REVOKE.value,
        certificate_id=cert.id,
        trigger=trigger,
        status=JobStatus.SUCCESS.value if result.success else JobStatus.FAILED.value,
        exit_code=result.exit_code,
        stdout=(result.stdout or "")[-100_000:],
        stderr=(result.stderr or "")[-100_000:],
        started_at=utcnow(), finished_at=utcnow(),
        error_message=None if result.success else (result.error or "")[:4000],
        created_by=user.id if user else None,
    )
    db.add(execution)

    if result.success:
        cert.status = CertificateStatus.REVOKED.value
        cert.auto_renew = False
        cert.renewal_status = RenewalStatus.DISABLED.value
        if delete_after and cert.cert_path:
            try:
                storage_module.get_file_store().delete_cert_material(cert.fingerprint_sha256)
                cert.cert_path = cert.key_path = cert.chain_path = cert.fullchain_path = None
            except Exception as exc:  # noqa: BLE001
                logger.warning("File cleanup after revoke failed: %s", exc)
        record(db, action="certificate.revoke", user_id=user.id if user else None,
               username=user.username if user else None,
               resource_type="certificate", resource_id=cert.id,
               result=AuditResult.SUCCESS, details={"reason": reason})
        _notify(db, "revoked", cert)
    else:
        record(db, action="certificate.revoke", user_id=user.id if user else None,
               username=user.username if user else None,
               resource_type="certificate", resource_id=cert.id,
               result=AuditResult.FAILURE, details={"error": result.error})
    db.commit()
    return execution


_DELETABLE_STATUSES = {
    CertificateStatus.FAILED.value, CertificateStatus.REVOKED.value,
    CertificateStatus.ARCHIVED.value,
}


def delete_certificate(db: Session, certificate_id: int, *, user: User | None = None) -> None:
    """Permanently remove a certificate row.

    Platform-managed (CertMgr-issued) certificates: failed/revoked/archived
    only — never active/issuing/renewing, to avoid deleting something the
    platform's own renewal automation still relies on.

    Imported/discovered certificates: deletable regardless of status.
    CertMgr was never the issuing/renewal authority for these — the row is
    just a tracking record, so removing it only stops CertMgr from
    monitoring it, never touches the actual certificate wherever it's
    really deployed. Also records the fingerprint in discovery_ignores so
    a future discovery scan doesn't just re-import the same file again
    (see app/services/discovery_service.py).

    Related rows (domains, executions, deployments, backups, health checks,
    tags) cascade at the DB level; every FK referencing certificates.id
    already has an explicit ON DELETE CASCADE/SET NULL (see the initial
    schema migration), so no explicit cleanup is needed for those."""
    cert = get_certificate(db, certificate_id, load_relations=False)
    if not cert.imported and cert.status not in _DELETABLE_STATUSES:
        raise ValidationAppError(
            f"Cannot delete a certificate with status '{cert.status}' — "
            "only failed, revoked or archived certificates can be deleted. "
            "Revoke an active certificate first."
        )
    if cert.cert_path:
        try:
            storage_module.get_file_store().delete_cert_material(cert.fingerprint_sha256)
        except Exception as exc:  # noqa: BLE001
            logger.warning("File cleanup during delete failed: %s", exc)

    if cert.imported and cert.fingerprint_sha256:
        from app.models.job import DiscoveryIgnore

        already_ignored = (
            db.query(DiscoveryIgnore)
            .filter(DiscoveryIgnore.fingerprint_sha256 == cert.fingerprint_sha256)
            .first()
        )
        if already_ignored is None:
            db.add(DiscoveryIgnore(
                fingerprint_sha256=cert.fingerprint_sha256,
                domain=cert.domain,
                source_path=cert.cert_path,
                ignored_by=user.id if user else None,
            ))

    domain, cert_status = cert.domain, cert.status
    db.delete(cert)
    record(db, action="certificate.delete", user_id=user.id if user else None,
           username=user.username if user else None,
           resource_type="certificate", resource_id=certificate_id,
           result=AuditResult.SUCCESS, details={"domain": domain, "status": cert_status})
    db.commit()


# ── Import ──────────────────────────────────────────────────────────────────

def import_certificate(
    db: Session,
    *,
    cert_data: bytes | None = None,
    key_data: bytes | None = None,
    chain_data: bytes | None = None,
    pfx_data: bytes | None = None,
    pfx_password: str | None = None,
    payload: dict[str, Any] | None = None,
    user: User | None = None,
    trigger: str = JobTrigger.API.value,
) -> Certificate:
    payload = payload or {}
    store = storage_module.get_file_store()

    if pfx_data:
        cert_obj, key_obj, extra_certs = parse_pfx(pfx_data, pfx_password)
        cert_pem = _cert_to_pem(cert_obj)
        key_pem = _key_to_pem(key_obj)
        chain_pem = b"".join(_cert_to_pem(c) for c in extra_certs) if extra_certs else None
        cert_data, key_data, chain_data = cert_pem, key_pem, chain_pem

    if not cert_data:
        raise ValidationAppError("Certificate file is required")

    _, meta = parse_certificate(cert_data)
    primary = meta.sans[0] if meta.sans else payload.get("domain") or "imported-certificate"

    # Duplicate detection by fingerprint
    existing = db.query(Certificate).filter(Certificate.fingerprint_sha256 == meta.fingerprint_sha256).first()
    if existing:
        raise ConflictError(
            f"Certificate already imported (fingerprint {meta.fingerprint_sha256[:24]}…)",
            code="DUPLICATE_CERTIFICATE",
        )

    store_dir = store.cert_dir(meta.fingerprint_sha256)
    (store_dir / "cert.pem").write_bytes(cert_data)
    if chain_data:
        (store_dir / "chain.pem").write_bytes(chain_data)

    key_stored_path: str | None = None
    if key_data:
        cert_obj2, _ = parse_certificate(cert_data)
        key_obj2, _, _ = _load_key(key_data, pfx_password)
        if not public_key_matches(cert_obj2, key_obj2):
            raise ValidationAppError("Private key does not match certificate public key")
        key_stored_path = store.write_private_key(meta.fingerprint_sha256, key_data)

    cert = Certificate(
        domain=primary,
        sans=meta.sans or [primary],
        is_wildcard=meta.is_wildcard,
        cert_type=CertificateType.IMPORTED.value,
        subject=meta.subject, issuer=meta.issuer, serial_number=meta.serial_number,
        fingerprint_sha256=meta.fingerprint_sha256,
        public_key_algorithm=meta.public_key_algorithm,
        key_type=meta.key_type, key_size=meta.key_size,
        signature_algorithm=meta.signature_algorithm,
        valid_from=meta.valid_from, valid_until=meta.valid_until,
        status=CertificateStatus.ACTIVE.value,
        environment=payload.get("environment", settings.default_environment),
        provider_name=payload.get("provider", "imported"),
        imported=True,
        auto_renew=bool(payload.get("auto_renew", False)),
        renewal_status=RenewalStatus.NONE.value,
        cert_path=str(store_dir / "cert.pem"),
        chain_path=str(store_dir / "chain.pem") if chain_data else None,
        key_path=key_stored_path,
        owner_id=payload.get("owner_id") or (user.id if user else None),
        notes=payload.get("notes"),
        managed_by_platform=False,
    )
    db.add(cert)
    db.flush()
    for idx, d in enumerate(cert.sans):
        db.add(CertificateDomain(certificate_id=cert.id, domain=d, is_primary=(idx == 0)))
    for name in payload.get("tags") or []:
        tag = db.query(Tag).filter(Tag.name == name).first() or Tag(name=name)
        if tag not in cert.tags:
            db.add(tag)
            db.flush()
            cert.tags.append(tag)
    db.add(JobExecution(
        job_type=JobType.IMPORT.value, certificate_id=cert.id, trigger=trigger,
        status=JobStatus.SUCCESS.value, started_at=utcnow(), finished_at=utcnow(),
        stdout=f"Imported {meta.fingerprint_sha256[:16]}…", created_by=user.id if user else None,
    ))
    record(db, action="certificate.import", user_id=user.id if user else None,
           username=user.username if user else None,
           resource_type="certificate", resource_id=cert.id, result=AuditResult.SUCCESS,
           details={"fingerprint": meta.fingerprint_sha256})
    _notify(db, "imported", cert)
    db.commit()
    return get_certificate(db, cert.id)


def _cert_to_pem(cert_obj) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return cert_obj.public_bytes(serialization.Encoding.PEM)


def _key_to_pem(key_obj) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key_obj.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_key(data: bytes, password: str | None):
    return parse_private_key(data, password.encode() if password else None)


def _assert_importable_path(db: Session, path: str) -> Path:
    """Reject paths outside the admin-configured discovery scan roots.

    import_from_paths lets an authenticated user point the server at an
    arbitrary local file — without this jail it would be an arbitrary local
    file read. Constrain it to the same trust boundary Discovery already
    uses (`discovery.scan_paths` / DEFAULT_SCAN_PATHS), since those are the
    directories an admin has explicitly designated as certificate locations.
    """
    from app.services.discovery_service import settings_scan_paths

    resolved = Path(path).resolve()
    for root in settings_scan_paths(db):
        root_resolved = Path(root).resolve()
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    raise ValidationAppError(f"Path is not within an allowed certificate directory: {path}")


def import_from_paths(db: Session, *, cert_path: str, key_path: str | None = None,
                      chain_path: str | None = None, payload: dict | None = None,
                      user: User | None = None) -> Certificate:
    cert_data = _assert_importable_path(db, cert_path).read_bytes()
    key_data = _assert_importable_path(db, key_path).read_bytes() if key_path else None
    chain_data = _assert_importable_path(db, chain_path).read_bytes() if chain_path else None
    return import_certificate(
        db, cert_data=cert_data, key_data=key_data, chain_data=chain_data,
        payload=payload, user=user,
    )


# ── Clone / bulk / exports ──────────────────────────────────────────────────

def clone_certificate(db: Session, certificate_id: int, *, new_domains: list[str] | None = None,
                      user: User | None = None) -> Certificate:
    src = get_certificate(db, certificate_id, load_relations=False)
    domains = new_domains or ([src.domain] + [d for d in src.sans if d != src.domain])
    payload = {
        "domains": domains,
        "validation_method": src.validation_method,
        "key_type": src.key_type,
        "environment": src.environment,
        "staging": src.staging,
        "auto_renew": src.auto_renew,
        "provider": src.provider_name,
        "notes": f"Cloned from certificate #{src.id}",
    }
    return issue_certificate(db, payload=payload, user=user, trigger=JobTrigger.API.value)


def bulk_action(db: Session, *, action: str, ids: list[int], user: User | None = None,
                options: dict | None = None) -> dict[str, int]:
    """Enqueue/execute bulk operations. Returns {queued, failed} counts."""
    from app.tasks.celery_app import run_bulk_async

    options = options or {}
    queued, failed = 0, 0
    for cert_id in ids:
        try:
            get_certificate(db, cert_id, load_relations=False)
            if settings.celery_task_always_eager:
                _bulk_execute(db, action, cert_id, user, options)
            else:
                run_bulk_async.delay(action, cert_id, user.id if user else None, options)
            queued += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Bulk %s failed for cert %s: %s", action, cert_id, exc)
            failed += 1
    return {"queued": queued, "failed": failed}


def _bulk_execute(db, action: str, cert_id: int, user, options: dict) -> None:
    if action == "renew":
        renew_certificate(db, cert_id, force=bool(options.get("force")), user=user)
    elif action == "revoke":
        revoke_certificate(db, cert_id, reason=options.get("reason", "superseded"), user=user)
    elif action == "deploy":
        from app.services.deployment_service import deploy_certificate

        server_id = options.get("server_id")
        template_id = options.get("template_id")
        deploy_certificate(db, certificate_id=cert_id, server_id=server_id,
                           template_id=template_id, user=user)
    elif action == "delete":
        delete_certificate(db, cert_id, user=user)
    else:
        raise ValidationAppError(f"Unsupported bulk action: {action}")


def export_bundle(db: Session, certificate_id: int, *, format: str = "zip",
                  include_key: bool = True, password: str = "") -> bytes:
    cert = get_certificate(db, certificate_id, load_relations=False)
    store = storage_module.get_file_store()
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        raise ValidationAppError("Certificate material not available (revoked or missing files)")

    fp = cert.fingerprint_sha256 or Path(cert.cert_path).parent.name
    if format == "zip":
        return store.export_zip(fp, include_key=include_key)
    if format == "pem":
        return Path(cert.cert_path).read_bytes()
    if format == "key":
        if not include_key:
            raise ValidationAppError("Key download not permitted")
        return store.read_private_key(cert.key_path).encode()
    if format == "chain":
        if cert.chain_path and os.path.exists(cert.chain_path):
            return Path(cert.chain_path).read_bytes()
        return Path(cert.cert_path).read_bytes()
    if format == "fullchain":
        if cert.fullchain_path and os.path.exists(cert.fullchain_path):
            return Path(cert.fullchain_path).read_bytes()
        return Path(cert.cert_path).read_bytes()
    if format == "pfx":
        store.build_bundle(fp, include_key=include_key, password=password)
        return Path(store.pfx_path(fp)).read_bytes()
    raise ValidationAppError(f"Unsupported export format: {format}")


def _notify(db: Session, event: str, cert: Certificate) -> None:
    """Queue notification rows for a certificate event (delivered by workers)."""
    try:
        from app.services.notification_service import queue_event_notifications

        queue_event_notifications(db, event, cert)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Notification queueing failed for event %s: %s", event, exc)
