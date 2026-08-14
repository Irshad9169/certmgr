"""Job executions, discovery runs, scheduled jobs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutils import utcnow
from app.models.base import LONGTEXT, Base, IntPkMixin, TimestampMixin


class JobExecution(Base, IntPkMixin, TimestampMixin):
    """Every certificate/command operation records an execution here.

    stdout/stderr may be large for long certbot runs — we keep a bounded copy in
    the DB plus the full log on disk under CERTMGR_LOG_ROOT.
    """

    __tablename__ = "job_executions"
    __table_args__ = (
        Index("ix_job_cert", "certificate_id"),
        Index("ix_job_status", "status"),
        Index("ix_job_created", "created_at"),
    )

    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    certificate_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True
    )
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
    task_id: Mapped[str | None] = mapped_column(String(128), nullable=True)  # Celery task id
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str | None] = mapped_column(LONGTEXT, nullable=True)
    stderr: Mapped[str | None] = mapped_column(LONGTEXT, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    job_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)

    certificate: Mapped[Certificate | None] = relationship(back_populates="executions")  # noqa: F821
    server: Mapped[Server | None] = relationship()  # noqa: F821


class DiscoveryRun(Base, IntPkMixin):
    __tablename__ = "discovery_runs"

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    scan_paths: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    found_count: Mapped[int] = mapped_column(Integer, default=0)
    imported_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    log: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DiscoveryIgnore(Base, IntPkMixin, TimestampMixin):
    """Fingerprints of certificates deliberately removed from tracking.

    run_discovery() computes its "already seen" set fresh from the current
    certificates table on every run, so deleting a discovered certificate's
    row alone doesn't stop it from being re-imported the next scan finds the
    same file on disk (e.g. an OS-default self-signed cert under a default
    scan path). Deleting an imported certificate records its fingerprint
    here so future runs skip it too.
    """

    __tablename__ = "discovery_ignores"

    fingerprint_sha256: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    ignored_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ScheduledJob(Base, IntPkMixin, TimestampMixin):
    """User-configurable scheduled jobs (discovery, renewal, compliance…)."""

    __tablename__ = "scheduled_jobs"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(16), default="cron")
    cron_expression: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
