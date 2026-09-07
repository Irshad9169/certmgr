"""Discovery task."""

from __future__ import annotations

from app.core.logging import get_logger
from app.tasks.base import db_task
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.discovery.run_discovery")
@db_task
def run_discovery(db, extra_paths: list[str] | None = None, created_by: int | None = None) -> dict:
    from app.services.discovery_service import run_discovery as _run

    run = _run(db, extra_paths=extra_paths, created_by=created_by)
    return {"run_id": run.id, "found": run.found_count, "imported": run.imported_count}


@celery_app.task(name="app.tasks.discovery.run_network_scan")
@db_task
def run_network_scan(
    db,
    targets: list[str],
    ports: list[int] | None = None,
    concurrency: int | None = None,
    timeout_seconds: float | None = None,
    created_by: int | None = None,
) -> dict:
    from app.services.discovery_service import run_network_scan as _run

    run = _run(db, targets=targets, ports=ports, concurrency=concurrency,
              timeout_seconds=timeout_seconds, created_by=created_by)
    return {"run_id": run.id, "found": run.found_count, "imported": run.imported_count}


@celery_app.task(name="app.tasks.discovery.run_scheduled_network_scan")
@db_task
def run_scheduled_network_scan(db) -> dict:
    """Celery beat entry point — unlike the API-triggered task above, beat
    can't pass per-run targets, so this reads the admin-configured
    tls_scan.scheduled_targets setting instead. No-ops (does not even
    create a DiscoveryRun row) until that setting is non-empty, since an
    empty target list isn't "scan nothing successfully", it's "nobody has
    opted in yet"."""
    from app.services.discovery_service import run_network_scan as _run
    from app.services.settings_service import get_setting

    raw_targets = get_setting(db, "tls_scan.scheduled_targets") or ""
    targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
    if not targets:
        logger.info("Scheduled network scan skipped — tls_scan.scheduled_targets is not configured")
        return {"skipped": True, "reason": "no targets configured"}

    run = _run(db, targets=targets)
    return {"run_id": run.id, "found": run.found_count, "imported": run.imported_count}
