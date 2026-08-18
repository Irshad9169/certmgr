"""Prometheus metrics collectors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge, Histogram

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

HTTP_REQUESTS = Counter(
    "certmgr_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_REQUEST_DURATION = Histogram(
    "certmgr_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
)
CERTBOT_EXECUTIONS = Counter(
    "certmgr_certbot_executions_total",
    "Certbot command executions by result",
    ["result"],
)
CERTIFICATE_GAUGE = Gauge(
    "certmgr_certificates_total",
    "Total certificates by status",
    ["status"],
)
CERTIFICATE_DAYS_TO_EXPIRY = Gauge(
    "certmgr_certificate_days_to_expiry",
    "Days until expiry (1 = soonest expiring cert)",
    ["certificate_id"],
)
JOBS_TOTAL = Counter("certmgr_jobs_total", "Background jobs by type and status", ["type", "status"])


def refresh_certificate_gauges(db: Session) -> None:
    """certmgr_certificates_total / certmgr_certificate_days_to_expiry are
    point-in-time snapshots, not cumulative counters — call this fresh on
    every /metrics scrape rather than incrementing in-line wherever a
    certificate's status changes, since there's no single choke point
    every status transition passes through.

    .clear() first — a Gauge otherwise keeps a stale label's last value
    forever (a status with zero certs now, or a certificate_id that's
    since been deleted, would linger at its old reading rather than
    disappearing).
    """
    from sqlalchemy import func

    from app.models.certificate import Certificate

    CERTIFICATE_GAUGE.clear()
    CERTIFICATE_DAYS_TO_EXPIRY.clear()
    for status, count in (
        db.query(Certificate.status, func.count(Certificate.id)).group_by(Certificate.status).all()
    ):
        CERTIFICATE_GAUGE.labels(status=status).set(count)
    for cert in db.query(Certificate).filter(Certificate.valid_until.isnot(None)).all():
        remaining = cert.days_remaining
        if remaining is not None:
            CERTIFICATE_DAYS_TO_EXPIRY.labels(certificate_id=str(cert.id)).set(remaining)
