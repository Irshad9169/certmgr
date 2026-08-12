"""Dashboard analytics API."""


from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
def stats(db: DbSession, user: CurrentUser):
    return dashboard_service.dashboard_stats(db)


@router.get("/monthly-issuance")
def monthly_issuance(db: DbSession, user: CurrentUser, months: int = Query(12, ge=1, le=36)):
    return dashboard_service.monthly_issuance(db, months)


@router.get("/expiry-timeline")
def expiry_timeline(db: DbSession, user: CurrentUser, horizon: int = Query(90, ge=7, le=365)):
    return dashboard_service.expiry_timeline(db, horizon)


@router.get("/renewals-today")
def renewals_today(db: DbSession, user: CurrentUser):
    return {"renewals": dashboard_service.renewals_today(db)}


@router.get("/top-owners")
def top_owners(db: DbSession, user: CurrentUser, limit: int = Query(10, ge=1, le=50)):
    return {"owners": dashboard_service.top_owners(db, limit)}


@router.get("/deployment-status")
def deployment_status(db: DbSession, user: CurrentUser):
    return {"deployments": dashboard_service.deployment_status(db)}


@router.get("/servers")
def server_summary(db: DbSession, user: CurrentUser):
    return dashboard_service.server_summary(db)


@router.get("/trends")
def trends(db: DbSession, user: CurrentUser, days: int = Query(30, ge=7, le=365)):
    return {"trends": dashboard_service.certificate_trends(db, days)}
