"""Shared task helpers: DB sessions, maintenance guard, audit integration."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from app.core.database import session_scope
from app.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


def db_task(fn: Callable[..., T]) -> Callable[..., T]:
    """Wrap a Celery task body with a DB session and maintenance guard.

    The wrapped function receives `db` as its first argument.
    """
    def wrapper(*args, **kwargs):
        from app.services.maintenance_service import ensure_not_maintenance

        with session_scope() as db:
            ensure_not_maintenance(db)
            return fn(db, *args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper
