"""Dialect compatibility tests — PostgreSQL is primary; MariaDB/MySQL is a
fully supported fallback. These tests verify the SQL we emit compiles for each
dialect without requiring a live server."""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.dialects import mysql, postgresql, sqlite

from app.models.certificate import Certificate
from app.services.certificate_service import _sort_expression


def _compile(expr, dialect_module) -> str:
    return str(
        select(Certificate.id)
        .order_by(expr)
        .compile(dialect=dialect_module.dialect())
    )


def test_order_by_mysql_has_no_nulls_last():
    sql = _compile(_sort_expression(Certificate.valid_until, "asc", "mysql"), mysql)
    assert "NULLS LAST" not in sql.upper()
    assert "ORDER BY certificates.valid_until ASC" in sql


def test_order_by_mysql_desc():
    sql = _compile(_sort_expression(Certificate.created_at, "desc", "mysql"), mysql)
    assert "NULLS LAST" not in sql.upper()
    assert "ORDER BY certificates.created_at DESC" in sql


def test_order_by_mariadb_name_also_safe():
    # SQLAlchemy reports MariaDB connections with dialect name "mysql"
    sql = _compile(_sort_expression(Certificate.valid_until, "asc", "mariadb"), mysql)
    assert "NULLS LAST" not in sql.upper()


def test_order_by_postgres_keeps_nulls_last():
    sql = _compile(_sort_expression(Certificate.valid_until, "asc", "postgresql"), postgresql)
    assert "NULLS LAST" in sql.upper()


def test_order_by_sqlite_keeps_nulls_last():
    sql = _compile(_sort_expression(Certificate.valid_until, "asc", "sqlite"), sqlite)
    assert "NULLS LAST" in sql.upper()


def test_mysql_engine_url_builds_without_connecting():
    engine = create_engine("mysql+pymysql://certmgr:secret@127.0.0.1:3306/certmgr")
    assert engine.url.get_backend_name() == "mysql"
    assert engine.url.username == "certmgr"
    assert engine.url.database == "certmgr"


def test_mariadb_engine_url_builds_without_connecting():
    engine = create_engine("mariadb+pymysql://certmgr:secret@db.internal:3307/certmgr")
    assert engine.url.get_backend_name() in ("mysql", "mariadb")
    assert engine.url.port == 3307


def test_certificate_inventory_query_compiles_for_mysql():
    """The inventory listing (with its filters/joins) must compile on MySQL."""
    from sqlalchemy import or_

    from app.models.certificate import Tag

    q = (
        select(Certificate)
        .join(Certificate.tags)
        .where(
            or_(
                Certificate.domain.ilike("%demo%"),
                Certificate.issuer.ilike("%Let%"),
            ),
            Tag.name.in_(["web", "prod"]),
            Certificate.status == "active",
        )
        .order_by(_sort_expression(Certificate.valid_until, "asc", "mysql"))
        .limit(25)
    )
    sql = str(q.compile(dialect=mysql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "NULLS LAST" not in sql.upper()
    assert "LIKE" in sql.upper()
    assert "LIMIT" in sql.upper()


def test_log_columns_are_mediumtext_on_mysql():
    """stdout/stderr/notification body must be MEDIUMTEXT (TEXT caps at 64 KB
    on MySQL/MariaDB, but the app stores up to 100 KB of logs)."""
    from sqlalchemy.schema import CreateTable

    from app.models.job import JobExecution
    from app.models.notification import Notification

    job_sql = str(CreateTable(JobExecution.__table__).compile(dialect=mysql.dialect()))
    notif_sql = str(CreateTable(Notification.__table__).compile(dialect=mysql.dialect()))
    assert "MEDIUMTEXT" in job_sql
    assert "MEDIUMTEXT" in notif_sql
    # and that the big columns specifically are MEDIUMTEXT (not plain TEXT)
    assert "stdout MEDIUMTEXT" in job_sql
    assert "stderr MEDIUMTEXT" in job_sql
    assert "body MEDIUMTEXT" in notif_sql


def test_log_columns_stay_text_on_postgres():
    """On PostgreSQL the variant is ignored — TEXT is unbounded there."""
    from sqlalchemy.dialects import postgresql as pg
    from sqlalchemy.schema import CreateTable

    from app.models.job import JobExecution

    sql = str(CreateTable(JobExecution.__table__).compile(dialect=pg.dialect()))
    assert "MEDIUMTEXT" not in sql.upper()
    assert "TEXT" in sql.upper()
