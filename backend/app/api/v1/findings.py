"""Certificate Transparency findings — the first lifecycle-bearing security
finding in CertMgr (open -> acknowledged/investigating -> false_positive/
resolved). Populated by app.services.discovery_service.run_ct_monitor()."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from app.api.deps import CurrentUser, DbSession, get_client_ip, get_user_agent
from app.api.permissions import P_, has_permission
from app.core.exceptions import NotFoundError, PermissionDeniedError, ValidationAppError
from app.core.logging import get_logger
from app.models.enums import AuditResult, FindingStatus
from app.services.audit_service import record

logger = get_logger(__name__)

router = APIRouter(prefix="/findings", tags=["Findings"])

_VALID_STATUSES = {s.value for s in FindingStatus}


def _serialize(f) -> dict:
    return {
        "id": f.id,
        "certificate_id": f.certificate_id,
        "domain": f.domain,
        "match_type": f.match_type,
        "detections": f.detections or [],
        "risk_score": f.risk_score,
        "severity": f.severity,
        "status": f.status,
        "resolution_reason": f.resolution_reason,
        "assigned_to": f.assigned_to,
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


@router.get("")
def list_findings(
    db: DbSession, user: CurrentUser,
    status: str | None = None, severity: str | None = None,
    domain: str | None = None, certificate_id: int | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=250),
):
    if not has_permission(user.role_name.value, P_["finding"]["view"]):
        raise PermissionDeniedError("You are not authorized to view findings")
    from app.models.finding import CTFinding

    q = db.query(CTFinding)
    if status:
        q = q.filter(CTFinding.status == status)
    if severity:
        q = q.filter(CTFinding.severity == severity)
    if domain:
        q = q.filter(CTFinding.domain.ilike(f"%{domain}%"))
    if certificate_id is not None:
        q = q.filter(CTFinding.certificate_id == certificate_id)

    total = q.count()
    rows = (
        q.order_by(CTFinding.last_seen_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [_serialize(f) for f in rows],
        "total": total, "page": page, "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 1,
    }


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: DbSession, user: CurrentUser):
    if not has_permission(user.role_name.value, P_["finding"]["view"]):
        raise PermissionDeniedError("You are not authorized to view findings")
    from app.models.finding import CTFinding

    f = db.query(CTFinding).filter(CTFinding.id == finding_id).first()
    if f is None:
        raise NotFoundError("Finding not found")
    return _serialize(f)


@router.patch("/{finding_id}")
def update_finding(finding_id: int, body: dict[str, Any], db: DbSession, user: CurrentUser, request: Request):
    if not has_permission(user.role_name.value, P_["finding"]["manage"]):
        raise PermissionDeniedError("You are not authorized to manage findings")
    from app.models.finding import CTFinding

    f = db.query(CTFinding).filter(CTFinding.id == finding_id).first()
    if f is None:
        raise NotFoundError("Finding not found")

    before = {"status": f.status, "assigned_to": f.assigned_to}

    if "status" in body:
        new_status = body["status"]
        if new_status not in _VALID_STATUSES:
            raise ValidationAppError(f"Invalid status: {new_status}")
        f.status = new_status
    if "assigned_to" in body:
        f.assigned_to = body["assigned_to"]
    if "resolution_reason" in body:
        f.resolution_reason = body["resolution_reason"]

    db.commit()
    record(db, action="finding.update", user_id=user.id, username=user.username,
           resource_type="finding", resource_id=finding_id, result=AuditResult.SUCCESS,
           details={"before": before, "after": {"status": f.status, "assigned_to": f.assigned_to}},
           ip_address=get_client_ip(request), user_agent=get_user_agent(request))
    return _serialize(f)
