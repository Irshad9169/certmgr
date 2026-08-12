"""Enterprise search across certificates, servers, tags, users and audit."""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.certificate import Certificate
from app.models.server import Server
from app.models.user import User


def enterprise_search(db: Session, query: str, *, limit: int = 25) -> dict[str, Any]:
    q = (query or "").strip()
    if not q or len(q) < 2:
        return {"certificates": [], "servers": [], "users": [], "total": 0}
    like = f"%{q}%"

    certs = (
        db.query(Certificate)
        .filter(or_(
            Certificate.domain.ilike(like),
            Certificate.issuer.ilike(like),
            Certificate.subject.ilike(like),
            Certificate.serial_number.ilike(like),
            Certificate.fingerprint_sha256.ilike(like),
            Certificate.cert_name.ilike(like),
        ))
        .limit(limit)
        .all()
    )
    servers = (
        db.query(Server)
        .filter(or_(Server.hostname.ilike(like), Server.ip_address.ilike(like)))
        .limit(limit)
        .all()
    )
    users = (
        db.query(User)
        .filter(or_(User.username.ilike(like), User.full_name.ilike(like), User.email.ilike(like)))
        .limit(limit)
        .all()
    )

    return {
        "certificates": [
            {"id": c.id, "domain": c.domain, "issuer": c.issuer, "status": c.status,
             "expires": c.valid_until.isoformat() if c.valid_until else None}
            for c in certs
        ],
        "servers": [
            {"id": s.id, "hostname": s.hostname, "ip_address": s.ip_address,
             "environment": s.environment, "connection_status": s.connection_status}
            for s in servers
        ],
        "users": [{"id": u.id, "username": u.username, "full_name": u.full_name} for u in users],
        "total": len(certs) + len(servers) + len(users),
    }
