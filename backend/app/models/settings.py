"""Key/value application settings (admin-configurable, secrets encrypted)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutils import utcnow
from app.models.base import Base, IntPkMixin, TimestampMixin


class AppSetting(Base, IntPkMixin):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[int | None] = mapped_column(nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MaintenanceWindow(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "maintenance_windows"

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    pause_renewals: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pause_deployments: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pause_notifications: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pause_imports: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    pause_background_jobs: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scheduled_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int | None] = mapped_column(nullable=True)
