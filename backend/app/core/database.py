"""Database engine / session management.

Uses SQLAlchemy 2.0 synchronous sessions (shared safely by FastAPI threadpool
handlers and Celery workers). PostgreSQL in production; SQLite in-memory for
tests/CI. All JSON columns and enums are stored in a PostgreSQL-compatible way.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

_CONNECT_ARGS: dict = {}


def _make_engine() -> Engine:
    url = settings.database_url

    if url.startswith("sqlite"):
        # In-memory DBs require a shared pool so every session sees the same data.
        if ":memory:" in url:
            from sqlalchemy.pool import StaticPool

            return create_engine(
                url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=settings.sql_echo,
            )
        # Ensure parent dir exists for file-based sqlite
        if url.startswith("sqlite:///"):
            db_path = url.replace("sqlite:///", "", 1)
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False}, echo=settings.sql_echo)

    kwargs: dict = {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "echo": settings.sql_echo,
    }
    if url.startswith("postgresql"):
        kwargs["connect_args"] = {"connect_timeout": 10}
    elif url.startswith(("mysql", "mariadb")):
        # MariaDB/MySQL — explicit utf8mb4, pymysql driver.
        kwargs["connect_args"] = {"charset": "utf8mb4"}
    return create_engine(url, **kwargs)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:  # pragma: no cover
    """Enable foreign keys + WAL on SQLite (tests/local dev only)."""
    if engine.url.get_backend_name() == "sqlite":
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def get_db() -> Generator[Session]:
    """FastAPI dependency — yields a session with automatic commit/rollback."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def session_scope() -> Generator[Session]:
    """Context-manager style session for services/tasks (commits on success)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
