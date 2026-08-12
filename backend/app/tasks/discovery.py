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
