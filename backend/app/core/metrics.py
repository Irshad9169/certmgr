"""Prometheus metrics collectors."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

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
