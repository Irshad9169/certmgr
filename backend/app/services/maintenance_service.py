"""Maintenance mode: pause renewals / deployments / notifications / imports /
background jobs. Implemented as an app_settings flag row + optional end time."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import MaintenanceModeError
from app.core.timeutils import utcnow
from app.models.settings import AppSetting, MaintenanceWindow

_KEY = "maintenance.mode"


def is_maintenance(db: Session) -> bool:
    row = db.query(AppSetting).filter(AppSetting.key == _KEY).first()
    if row is None or not row.value:
        return False
    if row.value == "true":
        # check for scheduled end
        window = db.query(MaintenanceWindow).order_by(MaintenanceWindow.id.desc()).first()
        if window and window.scheduled_end and window.scheduled_end < utcnow():
            row.value = "false"
            db.commit()
            return False
        return True
    return False


def get_status(db: Session) -> dict[str, Any]:
    row = db.query(AppSetting).filter(AppSetting.key == _KEY).first()
    window = db.query(MaintenanceWindow).order_by(MaintenanceWindow.id.desc()).first()
    active = bool(row and row.value == "true")
    return {
        "active": active,
        "reason": window.reason if window else None,
        "scheduled_end": window.scheduled_end.isoformat() if window and window.scheduled_end else None,
        "pauses": {
            "renewals": window.pause_renewals if window else active,
            "deployments": window.pause_deployments if window else active,
            "notifications": window.pause_notifications if window else active,
            "imports": window.pause_imports if window else active,
            "background_jobs": window.pause_background_jobs if window else active,
        },
    }


def set_maintenance(db: Session, *, active: bool, reason: str | None = None,
                    scheduled_end: datetime | None = None,
                    pauses: dict[str, bool] | None = None,
                    created_by: int | None = None) -> dict[str, Any]:
    row = db.query(AppSetting).filter(AppSetting.key == _KEY).first()
    if row is None:
        row = AppSetting(key=_KEY, description="Global maintenance mode")
        db.add(row)
    row.value = "true" if active else "false"
    row.updated_by = created_by
    if active:
        window = MaintenanceWindow(
            reason=reason or "Scheduled maintenance",
            scheduled_end=scheduled_end,
            created_by=created_by,
        )
        for key in ("pause_renewals", "pause_deployments", "pause_notifications",
                    "pause_imports", "pause_background_jobs"):
            setattr(window, key, bool((pauses or {}).get(key, True)))
        db.add(window)
    db.commit()
    return get_status(db)


def ensure_not_maintenance(db: Session, *, operation: str = "background job") -> None:
    """Raise MaintenanceModeError when maintenance is active."""
    if is_maintenance(db):
        raise MaintenanceModeError(f"Platform is in maintenance mode — {operation} paused")
