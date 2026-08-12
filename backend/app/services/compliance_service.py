"""Security compliance engine: key length, curves, signature algorithms,
lifetime, duplicates, unused certificates → compliance report + dashboard data."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.certificate import Certificate, ComplianceReport
from app.models.enums import ComplianceStatus

logger = get_logger(__name__)

MIN_RSA = 2048
MIN_ECC = 256
MAX_LIFETIME_DAYS = 398  # CA/B Forum
WEAK_SIGNATURES = ("md5", "sha1")


def evaluate_certificate(cert: Certificate) -> dict[str, Any]:
    """Evaluate one certificate against compliance rules."""
    issues: list[str] = []
    score = 100

    if cert.key_type == "rsa":
        if not cert.key_size or cert.key_size < MIN_RSA:
            issues.append(f"RSA key size {cert.key_size} < {MIN_RSA}")
            score -= 30
    elif cert.key_type == "ecdsa":
        if not cert.key_size or cert.key_size < MIN_ECC:
            issues.append(f"ECC key size {cert.key_size} < {MIN_ECC}")
            score -= 30
    elif cert.key_type in ("ed25519", "ed448"):
        pass
    else:
        issues.append("Unrecognized key algorithm")
        score -= 10

    if cert.signature_algorithm and any(w in cert.signature_algorithm.lower() for w in WEAK_SIGNATURES):
        issues.append(f"Weak signature algorithm: {cert.signature_algorithm}")
        score -= 30

    if cert.valid_from and cert.valid_until:
        lifetime = (cert.valid_until - cert.valid_from).days
        if lifetime > MAX_LIFETIME_DAYS:
            issues.append(f"Certificate lifetime {lifetime}d exceeds {MAX_LIFETIME_DAYS}d")
            score -= 20

    if cert.status in ("expired", "revoked"):
        issues.append(f"Certificate is {cert.status}")
        score -= 25

    if not cert.sans:
        issues.append("Certificate has no SAN entries")
        score -= 10

    return {
        "id": cert.id,
        "domain": cert.domain,
        "compliant": len(issues) == 0,
        "score": max(0, score),
        "issues": issues,
        "status": ComplianceStatus.COMPLIANT.value if not issues else ComplianceStatus.NON_COMPLIANT.value,
    }


def compliance_dashboard(db: Session) -> dict[str, Any]:
    certs = db.query(Certificate).all()
    results = [evaluate_certificate(c) for c in certs]
    compliant = sum(1 for r in results if r["compliant"])
    non_compliant = len(results) - compliant
    issues: dict[str, int] = {}
    for r in results:
        for issue in r["issues"]:
            issues[issue] = issues.get(issue, 0) + 1

    duplicates: list[dict[str, Any]] = []
    fp_counts = (
        db.query(Certificate.fingerprint_sha256, func.count(Certificate.id))
        .group_by(Certificate.fingerprint_sha256)
        .having(func.count(Certificate.id) > 1)
        .all()
    )
    for fp, count in fp_counts:
        duplicates.append({"fingerprint": fp, "count": count})

    unused = [
        {"id": c.id, "domain": c.domain}
        for c in certs
        if c.status not in ("expired", "revoked") and c.days_remaining is not None and c.days_remaining > 90
        and not c.deployments
    ]

    return {
        "total": len(results),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round(compliant / len(results) * 100, 1) if results else 100.0,
        "issue_counts": dict(sorted(issues.items(), key=lambda x: -x[1])),
        "duplicates": duplicates,
        "unused": unused,
    }


def run_compliance_report(db: Session, *, created_by: int | None = None,
                          persist: bool = True) -> ComplianceReport:
    data = compliance_dashboard(db)
    report = ComplianceReport(
        report_type="compliance",
        status="generated",
        summary=data,
        generated_by=created_by,
    )
    if persist:
        db.add(report)
        db.commit()
        db.refresh(report)
    return report


def generate_compliance_files(db: Session, fmt: str = "csv") -> tuple[bytes, str]:
    rows = []
    for cert in db.query(Certificate).all():
        res = evaluate_certificate(cert)
        rows.append(res)
    # reuse report generator with a synthetic payload via inventory subset
    return _serialize_rows(rows, fmt)


def _serialize_rows(rows: list[dict], fmt: str) -> tuple[bytes, str]:
    import csv as _csv
    import io
    import json

    headers = ["id", "domain", "status", "score", "issues"]
    if fmt == "json":
        return json.dumps(rows, indent=2).encode(), "compliance.json"
    buf = io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in headers})
    return buf.getvalue().encode("utf-8-sig"), "compliance.csv"
