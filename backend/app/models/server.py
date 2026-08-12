"""Servers, deployment templates, deployments."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IntPkMixin, TimestampMixin
from app.models.certificate import server_tags


class Server(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "servers"
    __table_args__ = (
        Index("ix_server_hostname", "hostname"),
        Index("ix_server_env", "environment"),
    )

    hostname: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="production")
    os_type: Mapped[str] = mapped_column(String(64), default="linux")
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    auth_method: Mapped[str] = mapped_column(String(16), default="ssh_key")
    ssh_user: Mapped[str] = mapped_column(String(64), default="root")
    # Credentials stored ENCRYPTED (Fernet) — never plaintext.
    ssh_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_key_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_key_passphrase_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    proxy_jump: Mapped[str | None] = mapped_column(Text, nullable=True)  # user@host[:port]
    jump_host: Mapped[str | None] = mapped_column(Text, nullable=True)

    certificate_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    web_server_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    tags: Mapped[list[Tag]] = relationship(secondary=server_tags, lazy="selectin")  # noqa: F821
    connection_status: Mapped[str] = mapped_column(String(16), default="unknown")
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class DeploymentTemplate(Base, IntPkMixin, TimestampMixin):
    """Reusable, parameterized deployment scripts (Jinja2-rendered)."""

    __tablename__ = "deployment_templates"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    pre_deploy_script: Mapped[str] = mapped_column(Text, default="")
    backup_script: Mapped[str] = mapped_column(Text, default="")
    deploy_script: Mapped[str] = mapped_column(Text, default="")
    post_deploy_script: Mapped[str] = mapped_column(Text, default="")
    reload_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    verify_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rollback_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    variables: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)  # defaults for {{vars}}
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Deployment(Base, IntPkMixin, TimestampMixin):
    __tablename__ = "deployments"
    __table_args__ = (
        Index("ix_deploy_cert", "certificate_id"),
        Index("ix_deploy_server", "server_id"),
        Index("ix_deploy_status", "status"),
    )

    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False
    )
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )
    template_id: Mapped[int | None] = mapped_column(
        ForeignKey("deployment_templates.id", ondelete="SET NULL"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(16), default="sftp")
    target_service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_cert_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_key_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    remote_chain_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), default="pending")
    backup_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)

    certificate: Mapped[Certificate] = relationship(back_populates="deployments")  # noqa: F821
    server: Mapped[Server] = relationship()
    template: Mapped[DeploymentTemplate | None] = relationship()
