"""Security findings — the first lifecycle-bearing "issue" model in CertMgr.

Compliance reports and health checks are both point-in-time logs with no
acknowledge/resolve capability; a CTFinding is a real, investigable record an
analyst works through over time (open -> acknowledged/investigating ->
false_positive/resolved), matching the pattern security tools use.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutils import utcnow
from app.models.base import Base, IntPkMixin, TimestampMixin
from app.models.enums import FindingSeverity, FindingStatus


class CTFinding(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "ct_findings"
    __table_args__ = (
        Index("ix_ct_finding_cert", "certificate_id"),
        Index("ix_ct_finding_status", "status"),
        Index("ix_ct_finding_severity", "severity"),
        Index("ix_ct_finding_domain", "domain"),
    )

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    match_type: Mapped[str] = mapped_column(String(16), nullable=False)  # exact/subdomain/wildcard
    # [{"code": "UNKNOWN_CA", "weight": 25, "reason": "Issuer not in expected list: ..."}]
    detections: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default=FindingSeverity.INFORMATIONAL.value, index=True)
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN.value, index=True)
    resolution_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ct_monitor_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
