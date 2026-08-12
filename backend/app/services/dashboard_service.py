"""Dashboard aggregates — one SQL-heavy module serving the analytics widgets."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.timeutils import utcnow
from app.models.certificate import Certificate
from app.models.enums import CertificateStatus
from app.models.job import JobExecution
from app.models.server import Server
from app.models.user import User


def _expiring_counts(db: Session, days: int) -> int:
    cutoff = utcnow() + timedelta(days=days)
    return (
        db.query(func.count(Certificate.id))
        .filter(
            Certificate.valid_until.isnot(None),
            Certificate.valid_until <= cutoff,
            Certificate.status.notin_(["revoked", "expired", "failed", "archived"]),
        )
        .scalar()
        or 0
    )


def dashboard_stats(db: Session) -> dict[str, Any]:
    total = db.query(func.count(Certificate.id)).scalar() or 0
    active = db.query(func.count(Certificate.id)).filter(Certificate.status == CertificateStatus.ACTIVE.value).scalar() or 0
    expired = db.query(func.count(Certificate.id)).filter(Certificate.status == CertificateStatus.EXPIRED.value).scalar() or 0
    revoked = db.query(func.count(Certificate.id)).filter(Certificate.status == CertificateStatus.REVOKED.value).scalar() or 0
    imported = db.query(func.count(Certificate.id)).filter(Certificate.imported.is_(True)).scalar() or 0
    failures = (
        db.query(func.count(JobExecution.id))
        .filter(JobExecution.status == "failed")
        .filter(JobExecution.created_at >= utcnow() - timedelta(days=7))
        .scalar()
        or 0
    )

    statuses = dict(
        db.query(Certificate.status, func.count(Certificate.id))
        .group_by(Certificate.status)
        .all()
    )
    providers = dict(
        db.query(Certificate.provider_name, func.count(Certificate.id))
        .group_by(Certificate.provider_name)
        .all()
    )
    environments = dict(
        db.query(Certificate.environment, func.count(Certificate.id))
        .group_by(Certificate.environment)
        .all()
    )
    cert_types = dict(
        db.query(Certificate.cert_type, func.count(Certificate.id))
        .group_by(Certificate.cert_type)
        .all()
    )
    key_types = dict(
        db.query(Certificate.key_type, func.count(Certificate.id))
        .group_by(Certificate.key_type)
        .all()
    )

    return {
        "totals": {
            "total": total, "active": active, "expired": expired, "revoked": revoked,
            "imported": imported, "failures_7d": failures,
            "expiring_60": _expiring_counts(db, 60),
            "expiring_30": _expiring_counts(db, 30),
            "expiring_7": _expiring_counts(db, 7),
        },
        "by_status": statuses,
        "by_provider": providers,
        "by_environment": environments,
        "by_type": cert_types,
        "by_key_type": key_types,
    }


def monthly_issuance(db: Session, months: int = 12) -> list[dict[str, Any]]:
    """Issuance + renewal per month for the last N months."""
    from sqlalchemy import extract

    now = utcnow()
    start = datetime(now.year, now.month, 1, tzinfo=UTC) - timedelta(days=months * 31)

    issued_rows = (
        db.query(
            extract("year", Certificate.created_at).label("y"),
            extract("month", Certificate.created_at).label("m"),
            func.count(Certificate.id),
        )
        .filter(Certificate.created_at >= start)
        .group_by("y", "m")
        .all()
    )
    renewed_rows = (
        db.query(
            extract("year", Certificate.last_renewed_at).label("y"),
            extract("month", Certificate.last_renewed_at).label("m"),
            func.count(Certificate.id),
        )
        .filter(Certificate.last_renewed_at >= start)
        .group_by("y", "m")
        .all()
    )
    issued_map = {(int(y), int(m)): c for y, m, c in issued_rows}
    renewed_map = {(int(y), int(m)): c for y, m, c in renewed_rows}

    out: list[dict[str, Any]] = []
    cursor = start
    while cursor <= now:
        key = (cursor.year, cursor.month)
        out.append({
            "month": f"{cursor.year:04d}-{cursor.month:02d}",
            "issued": issued_map.get(key, 0),
            "renewed": renewed_map.get(key, 0),
        })
        cursor = datetime(cursor.year + (1 if cursor.month == 12 else 0),
                         1 if cursor.month == 12 else cursor.month + 1, 1, tzinfo=UTC)
    return out


def expiry_timeline(db: Session, horizon_days: int = 90) -> list[dict[str, Any]]:
    cutoff = utcnow() + timedelta(days=horizon_days)
    rows = (
        db.query(Certificate.domain, Certificate.valid_until)
        .filter(Certificate.valid_until.isnot(None), Certificate.valid_until <= cutoff)
        .order_by(Certificate.valid_until.asc())
        .all()
    )
    return [{"domain": d, "expires": e.isoformat() if e else None} for d, e in rows]


def renewals_today(db: Session) -> list[dict[str, Any]]:
    start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    rows = (
        db.query(Certificate.domain, Certificate.renewal_status, Certificate.last_renewed_at)
        .filter(Certificate.last_renewed_at >= start)
        .order_by(Certificate.last_renewed_at.desc())
        .all()
    )
    return [{"domain": d, "status": s, "renewed_at": r.isoformat() if r else None} for d, s, r in rows]


def top_owners(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    rows = (
        db.query(User.username, func.count(Certificate.id))
        .join(Certificate, Certificate.owner_id == User.id)
        .group_by(User.username)
        .order_by(func.count(Certificate.id).desc())
        .limit(limit)
        .all()
    )
    return [{"owner": u, "count": c} for u, c in rows]


def deployment_status(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(JobExecution.status, func.count(JobExecution.id))
        .filter(JobExecution.job_type == "deploy")
        .group_by(JobExecution.status)
        .all()
    )
    return [{"status": s, "count": c} for s, c in rows]


def server_summary(db: Session) -> dict[str, Any]:
    total = db.query(func.count(Server.id)).scalar() or 0
    by_env = dict(db.query(Server.environment, func.count(Server.id)).group_by(Server.environment).all())
    reachable = db.query(func.count(Server.id)).filter(Server.connection_status == "reachable").scalar() or 0
    return {"total": total, "reachable": reachable, "by_environment": by_env}


def certificate_trends(db: Session, days: int = 30) -> list[dict[str, Any]]:
    """Daily certificate count trend (snapshot approximation via created vs expired)."""
    from sqlalchemy import extract

    now = utcnow()
    start = now - timedelta(days=days)
    created = dict(
        db.query(extract("day", Certificate.created_at), func.count(Certificate.id))
        .filter(Certificate.created_at >= start)
        .group_by(extract("day", Certificate.created_at))
        .all()
    )
    out = []
    for i in range(days, -1, -1):
        day = (now - timedelta(days=i)).date()
        out.append({"date": day.isoformat(), "created": created.get(day.day, 0)})
    return out
