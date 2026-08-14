"""Certificates, domains, providers, tags, hooks, backups, compliance, health."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutils import utcnow
from app.models.base import Base, IntPkMixin, TimestampMixin
from app.models.enums import (
    CertificateStatus,
    CertificateType,
    ComplianceStatus,
    HealthStatus,
    HookType,
    RenewalStatus,
    ValidationMethod,
)

# ── Association tables ──────────────────────────────────────────────────────
certificate_tags = Table(
    "certificate_tags",
    Base.metadata,
    Column("certificate_id", Integer, ForeignKey("certificates.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

server_tags = Table(
    "server_tags",
    Base.metadata,
    Column("server_id", Integer, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "tags"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    color: Mapped[str] = mapped_column(String(16), default="#3f51b5")


class Provider(Base, IntPkMixin, TimestampMixin):
    """Certificate authority integration. Config stored encrypted."""

    __tablename__ = "providers"
    __table_args__ = (UniqueConstraint("name", name="uq_provider_name"),)

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)  # registry key
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Certificate(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "certificates"
    __table_args__ = (
        Index("ix_cert_domain", "domain"),
        Index("ix_cert_expiry", "valid_until"),
        Index("ix_cert_status", "status"),
        Index("ix_cert_fingerprint", "fingerprint_sha256"),
        Index("ix_cert_issuer", "issuer"),
        Index("ix_cert_owner", "owner_id"),
        Index("ix_cert_env", "environment"),
    )

    # Identity
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    cert_name: Mapped[str | None] = mapped_column(String(255), nullable=True)  # certbot --cert-name
    sans: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cert_type: Mapped[str] = mapped_column(String(32), default=CertificateType.SINGLE.value)

    # Certificate material (x.509 metadata — NEVER private key content)
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(96), nullable=True)
    public_key_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_type: Mapped[str] = mapped_column(String(16), default="rsa")
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Lifecycle
    status: Mapped[str] = mapped_column(String(32), default=CertificateStatus.ACTIVE.value, index=True)
    environment: Mapped[str] = mapped_column(String(32), default="production", index=True)
    provider_name: Mapped[str] = mapped_column(String(64), default="letsencrypt")
    validation_method: Mapped[str] = mapped_column(
        String(32), default=ValidationMethod.HTTP_01.value
    )
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    renewal_status: Mapped[str] = mapped_column(
        String(32), default=RenewalStatus.NONE.value, index=True
    )
    renewal_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Origin / lifecycle flags
    imported: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    staging: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    managed_by_platform: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Ownership / organization
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    favorite: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Issuance configuration — persisted so async/queued issuance (which only
    # has the certificate row to work from, not the original request) and a
    # future renewal can reconstruct the exact same certbot invocation. Hook
    # paths are stored already-resolved (not a Hook.id) so a later edit/
    # deletion of the Hook row doesn't change what an in-flight or historical
    # issuance actually used — same principle certbot's own renewal config
    # uses for hooks baked in at issuance time.
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webroot_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    standalone_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    auth_hook_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    cleanup_hook_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    hook_env: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    hook_execution_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hook_working_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    hook_timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Storage — ENCRYPTED file paths only. Private key content NEVER in the DB.
    cert_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    fullchain_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    pfx_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    backup_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Secrets used by the provider (e.g. DNS plugin credentials) — encrypted JSON
    provider_secrets_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Health / compliance
    health_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    health_status: Mapped[str] = mapped_column(String(16), default=HealthStatus.UNKNOWN.value)
    compliance_status: Mapped[str] = mapped_column(
        String(16), default=ComplianceStatus.UNKNOWN.value
    )
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relations
    owner: Mapped[User | None] = relationship()  # noqa: F821
    domains: Mapped[list[CertificateDomain]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )
    tags: Mapped[list[Tag]] = relationship(secondary=certificate_tags, lazy="selectin")
    executions: Mapped[list[JobExecution]] = relationship(  # noqa: F821
        back_populates="certificate", cascade="all, delete-orphan"
    )
    deployments: Mapped[list[Deployment]] = relationship(  # noqa: F821
        back_populates="certificate", cascade="all, delete-orphan"
    )
    backups: Mapped[list[Backup]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )
    health_checks: Mapped[list[CertificateHealthCheck]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )

    @property
    def days_remaining(self) -> int | None:
        from app.core.timeutils import days_until

        return days_until(self.valid_until) if self.valid_until else None


class CertificateDomain(Base, IntPkMixin):
    __tablename__ = "certificate_domains"
    __table_args__ = (UniqueConstraint("certificate_id", "domain", name="uq_certdomain"),)

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), index=True
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    validation_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    certificate: Mapped[Certificate] = relationship(back_populates="domains")


class Hook(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "hooks"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hook_type: Mapped[str] = mapped_column(String(32), default=HookType.AUTH.value)
    script_path: Mapped[str] = mapped_column(Text, nullable=False)
    env_vars: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    execution_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    working_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Backup(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "backups"

    certificate_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), default="certificate")
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    checksum_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    backup_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    restored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    certificate: Mapped[Certificate | None] = relationship(back_populates="backups")


class CertificateHealthCheck(Base, IntPkMixin):
    __tablename__ = "certificate_health_checks"

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), index=True
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default=HealthStatus.UNKNOWN.value)
    score: Mapped[float] = mapped_column(Float, default=100.0)
    checks: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    certificate: Mapped[Certificate] = relationship(back_populates="health_checks")


class ComplianceReport(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "compliance_reports"

    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="generated")
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    generated_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CertificateRelationship(Base, IntPkMixin, TimestampMixin):
    """Explicit relationship graph: cert → key/chain/server/application."""

    __tablename__ = "certificate_relationships"

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), index=True
    )
    related_certificate_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True
    )
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)  # shares_key, deployed_to…
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
