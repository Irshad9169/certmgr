"""CertMgr API application factory.

Boot order:
  1. structured logging
  2. middleware (request context, security headers, CSRF, metrics)
  3. exception handlers
  4. routers (API v1)
  5. startup: DB connectivity check, seed roles/settings/bootstrap admin,
     APScheduler sync (optional)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from app.api.v1 import (
    ai_router,
    audit,
    auth,
    backups_router,
    certificates,
    compliance_router,
    dashboard,
    deployments,
    discovery_router,
    extras,
    health_router,
    hooks,
    jobs,
    notifications,
    providers_router,
    reports_router,
    search_router,
    servers,
    settings,
    users,
    webhooks_router,
)
from app.core.config import settings as app_settings
from app.core.database import SessionLocal, engine
from app.core.exceptions import register_exception_handlers
from app.core.logging import get_logger, setup_logging
from app.core.middleware import (
    CSRFMiddleware,
    MetricsMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.rate_limit import limiter, rate_limit_handler

logger = get_logger(__name__)


def _seed_data() -> None:
    """Idempotent startup data: roles, settings, bootstrap admin.

    Runs in every uvicorn worker on boot; multiple workers race, so treat
    duplicate-key collisions as "someone else already seeded" and retry.
    """
    from sqlalchemy.exc import IntegrityError

    from app.api.permissions import seed_default_roles
    from app.services.settings_service import seed_defaults

    for attempt in range(3):
        db = SessionLocal()
        try:
            seed_default_roles(db)
            seed_defaults(db)
            from app.services.auth_service import get_or_create_bootstrap_admin

            get_or_create_bootstrap_admin(db)
            db.commit()
            return
        except IntegrityError:
            db.rollback()
            logger.info("Seeding raced with another worker (attempt %s) — retrying", attempt + 1)
        except Exception as exc:  # noqa: BLE001
            logger.error("Startup seeding failed: %s", exc)
            db.rollback()
            return
        finally:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Verify DB connectivity (fail fast in production)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connectivity OK")
    except Exception as exc:  # noqa: BLE001
        if app_settings.is_production:
            logger.critical("Database unreachable at startup: %s", exc)
            raise
        logger.warning("Database unavailable (continuing in dev): %s", exc)

    _seed_data()

    # Optional in-process scheduler (APScheduler) — used when running the API
    # with CERTMGR_RUN_SCHEDULER=1 (otherwise Celery beat handles scheduling).
    scheduler = None
    if os.environ.get("CERTMGR_RUN_SCHEDULER") == "1" and not app_settings.is_testing:
        try:
            from app.core.scheduler import start_scheduler, stop_scheduler

            scheduler = start_scheduler()
            logger.info("APScheduler started (in-process mode)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("APScheduler failed to start: %s", exc)

    yield

    if scheduler is not None:
        try:
            from app.core.scheduler import stop_scheduler

            stop_scheduler()
        except Exception:  # noqa: BLE001, S110 — best-effort scheduler shutdown
            pass


def create_app() -> FastAPI:
    setup_logging()

    app = FastAPI(
        title=app_settings.app_name,
        version="1.0.0",
        description=(
            "Enterprise SSL Certificate Lifecycle Management Platform.\n\n"
            "Authentication: `POST /api/v1/auth/login` returns an access token; "
            "send it as `Authorization: Bearer <token>` or use an API token via "
            "`X-API-Key`. Interactive docs: `/docs`, ReDoc: `/redoc`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )

    # ── Middleware ──────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "Content-Disposition"],
    )
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

    register_exception_handlers(app)

    # ── Routers ─────────────────────────────────────────────────────────────
    prefix = app_settings.api_v1_prefix
    app.include_router(auth.router, prefix=prefix)
    app.include_router(users.router, prefix=prefix)
    app.include_router(certificates.router, prefix=prefix)
    app.include_router(servers.router, prefix=prefix)
    app.include_router(deployments.router, prefix=prefix)
    app.include_router(hooks.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)
    app.include_router(dashboard.router, prefix=prefix)
    app.include_router(settings.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(discovery_router, prefix=prefix)
    app.include_router(health_router, prefix=prefix)
    app.include_router(providers_router, prefix=prefix)
    app.include_router(compliance_router, prefix=prefix)
    app.include_router(reports_router, prefix=prefix)
    app.include_router(webhooks_router, prefix=prefix)
    app.include_router(search_router, prefix=prefix)
    app.include_router(ai_router, prefix=prefix)
    app.include_router(backups_router, prefix=prefix)
    app.include_router(extras.scheduled_jobs_router, prefix=prefix)

    # ── Operational endpoints ───────────────────────────────────────────────
    @app.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready")
    def readiness() -> Response:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return JSONResponse({"status": "ready"})
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "not_ready"}, status_code=503)

    @app.get("/health")
    def health_summary() -> dict[str, Any]:
        from app.services.maintenance_service import is_maintenance

        db = SessionLocal()
        try:
            maintenance = is_maintenance(db)
        finally:
            db.close()
        return {
            "app": app_settings.app_name,
            "version": "1.0.0",
            "environment": app_settings.environment,
            "maintenance_mode": maintenance,
            "providers": sorted(extras._provider_keys()),
        }

    if app_settings.prometheus_enabled:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        @app.get("/metrics")
        def metrics(request: Request) -> Response:
            from app.core.metrics import refresh_certificate_gauges

            token = app_settings.metrics_auth_token
            if token and request.headers.get("Authorization") != f"Bearer {token}":
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            db = SessionLocal()
            try:
                refresh_certificate_gauges(db)
            finally:
                db.close()
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/")
    def root() -> dict[str, Any]:
        return {
            "name": app_settings.app_name,
            "docs": "/docs",
            "health": "/health",
            "api": f"{prefix}",
        }

    return app


app = create_app()
