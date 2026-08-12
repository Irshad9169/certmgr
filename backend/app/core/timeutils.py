"""Time helpers: UTC-aware datetimes that survive SQLite's naive storage."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def days_until(dt: datetime) -> int:
    if dt is None:
        return 0
    diff = ensure_aware(dt) - utcnow()
    return diff.days
