"""Wildcard certificate usage discovery — scan detail/history endpoints.

Per-certificate results and the scan trigger live at
/certificates/{id}/usage[/scan] (in certificates.py, alongside every other
nested certificate sub-resource); this router covers looking up one scan's
own progress/history by scan id, independent of which certificate it
belongs to.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.api.permissions import P_, has_permission
from app.core.exceptions import NotFoundError, PermissionDeniedError
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/certificate-usage", tags=["Certificate Usage Discovery"])


def _serialize_scan(s) -> dict:
    return {
        "id": s.id, "certificate_id": s.certificate_id, "status": s.status, "sources": s.sources or [],
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "candidate_count": s.candidate_count, "scanned_count": s.scanned_count,
        "confirmed_count": s.confirmed_count, "different_certificate_count": s.different_certificate_count,
        "unreachable_count": s.unreachable_count, "error_count": s.error_count,
        "log": s.log, "created_by": s.created_by,
    }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: DbSession, user: CurrentUser):
    if not has_permission(user.role_name.value, P_["cert"]["view"]):
        raise PermissionDeniedError("You are not authorized to view certificate usage scans")
    from app.models.certificate_usage import CertificateUsageScan

    scan = db.query(CertificateUsageScan).filter(CertificateUsageScan.id == scan_id).first()
    if scan is None:
        raise NotFoundError("Scan not found")
    return _serialize_scan(scan)


@router.get("/scans/{scan_id}/results")
def get_scan_results(
    scan_id: int, db: DbSession, user: CurrentUser,
    status: str | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=250),
):
    if not has_permission(user.role_name.value, P_["cert"]["view"]):
        raise PermissionDeniedError("You are not authorized to view certificate usage scans")
    from app.api.v1.certificates import _serialize_usage_result
    from app.models.certificate_usage import CertificateUsageResult, CertificateUsageScan

    scan = db.query(CertificateUsageScan).filter(CertificateUsageScan.id == scan_id).first()
    if scan is None:
        raise NotFoundError("Scan not found")

    q = db.query(CertificateUsageResult).filter(CertificateUsageResult.scan_id == scan_id)
    if status:
        q = q.filter(CertificateUsageResult.status == status)

    total = q.count()
    rows = (
        q.order_by(CertificateUsageResult.hostname.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [_serialize_usage_result(r) for r in rows],
        "total": total, "page": page, "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 1,
    }
