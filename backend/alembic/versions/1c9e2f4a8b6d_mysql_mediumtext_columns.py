"""MySQL/MariaDB: widen log columns to MEDIUMTEXT.

MySQL TEXT holds at most 64 KB, but certbot/deploy stdout can exceed that
(logs are capped at 100 KB per field in the service layer). On PostgreSQL and
SQLite this is a no-op (TEXT is unbounded there).

Revision ID: 1c9e2f4a8b6d
Revises: 2fd8527c809e
Create Date: 2026-08-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "1c9e2f4a8b6d"
down_revision: Union[str, None] = "2fd8527c809e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = [
    ("job_executions", "stdout"),
    ("job_executions", "stderr"),
    ("notifications", "body"),
]


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name not in ("mysql", "mariadb"):
        # PostgreSQL TEXT and SQLite are unbounded — nothing to do.
        return
    from sqlalchemy.dialects.mysql import MEDIUMTEXT

    for table, column in _COLUMNS:
        op.alter_column(
            table, column,
            type_=MEDIUMTEXT(),
            existing_type=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name not in ("mysql", "mariadb"):
        return
    for table, column in _COLUMNS:
        op.alter_column(
            table, column,
            type_=sa.Text(),
            existing_type=sa.Text(),
            existing_nullable=True,
        )
