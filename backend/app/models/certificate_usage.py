"""Wildcard certificate usage discovery.

Answers a different question than CT monitoring or the network scanner:
given a specific wildcard certificate already in CertMgr, which real
endpoints are actually presenting *that exact* certificate over TLS right
now? Coverage by the wildcard (CN/SAN match) is only ever a candidate
signal here — the authoritative result is always an exact SHA-256
fingerprint match against the live handshake.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutils import utcnow
from app.models.base import Base, IntPkMixin
from app.models.enums import CertUsageResultStatus, CertUsageScanStatus


class CertificateUsageScan(Base, IntPkMixin):
    """One usage-discovery run against a single certificate."""

    __tablename__ = "certificate_usage_scans"
    __table_args__ = (
        Index("ix_cert_usage_scan_cert", "certificate_id"),
        Index("ix_cert_usage_scan_status", "status"),
    )

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), default=CertUsageScanStatus.QUEUED.value, index=True)
    sources: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    candidate_count: Mapped[int] = mapped_column(Integer, default=0)
    scanned_count: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_count: Mapped[int] = mapped_column(Integer, default=0)
    different_certificate_count: Mapped[int] = mapped_column(Integer, default=0)
    unreachable_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    log: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


class CertificateUsageResult(Base, IntPkMixin):
    """One (certificate, hostname, ip, port) endpoint observation.

    Upserted in place (not append-only like NetworkCertificateSighting):
    first_seen_at is preserved across rescans, last_seen_at/last_checked_at
    always advance, and status/presented_* reflect only the most recent
    probe — a certificate rotation history isn't the point of this feature,
    "what does this endpoint present right now" is.
    """

    __tablename__ = "certificate_usage_results"
    __table_args__ = (
        UniqueConstraint("certificate_id", "hostname", "ip_address", "port",
                         name="uq_cert_usage_result_endpoint"),
        Index("ix_cert_usage_result_cert", "certificate_id"),
        Index("ix_cert_usage_result_status", "status"),
        Index("ix_cert_usage_result_hostname", "hostname"),
    )

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="tls")

    status: Mapped[str] = mapped_column(String(32), default=CertUsageResultStatus.UNREACHABLE.value, index=True)

    expected_fingerprint: Mapped[str | None] = mapped_column(String(96), nullable=True)
    presented_fingerprint: Mapped[str | None] = mapped_column(String(96), nullable=True)

    presented_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    presented_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    presented_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Set only when status is "different_certificate" AND the presented
    # fingerprint matches another certificate CertMgr already tracks — lets
    # the UI say "actually serving Certificate #47 (*.otherapp.com)" instead
    # of just raw subject/issuer text for an unrecognized cert.
    presented_certificate_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True
    )

    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    discovery_source: Mapped[str] = mapped_column(String(16), default="manual")  # inventory / manual

    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificate_usage_scans.id", ondelete="SET NULL"), nullable=True
    )
