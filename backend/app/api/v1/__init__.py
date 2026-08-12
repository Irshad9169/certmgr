"""API v1 router package — exports every router module."""

from app.api.v1 import (
    audit,
    auth,
    certificates,
    dashboard,
    deployments,
    hooks,
    jobs,
    notifications,
    servers,
    settings,
    users,
)
from app.api.v1.extras import (
    ai_router,
    backups_router,
    compliance_router,
    discovery_router,
    health_router,
    providers_router,
    reports_router,
    scheduled_jobs_router,
    search_router,
    webhooks_router,
)

__all__ = [
    "ai_router", "audit", "auth", "backups_router", "certificates", "compliance_router",
    "dashboard", "deployments", "discovery_router", "health_router", "hooks", "jobs",
    "notifications", "providers_router", "reports_router", "scheduled_jobs_router",
    "search_router", "servers", "settings", "users", "webhooks_router",
]
