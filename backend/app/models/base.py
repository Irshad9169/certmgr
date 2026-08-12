"""Declarative base and shared mixins."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, Text, func
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.timeutils import utcnow

# Long text that may exceed MySQL/MariaDB TEXT's 64 KB limit (e.g. captured
# certbot/deploy stdout). MEDIUMTEXT holds up to 16 MB; PostgreSQL ignores the
# variant and keeps TEXT. SQLAlchemy reports the MariaDB dialect as "mysql".
LONGTEXT = Text().with_variant(MEDIUMTEXT(), "mysql").with_variant(MEDIUMTEXT(), "mariadb")


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class IntPkMixin:
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)


def utc_timestamp() -> datetime:
    return utcnow()
