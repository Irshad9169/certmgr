"""Persist issuance config (hooks/webroot/standalone/email) on Certificate.

Async/queued issuance only ever had the certificate row to reconstruct a
request from (certificate_id is all a Celery task receives) — it had no
columns to recover auth/cleanup hook paths, webroot_path, standalone_port,
hook_env, or a caller-supplied email, so that configuration was silently
dropped for every non-eager (worker-dispatched) issuance. All new columns
are nullable — existing rows are unaffected.

Revision ID: 3f7a9c2e5b1d
Revises: 1c9e2f4a8b6d
Create Date: 2026-08-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "3f7a9c2e5b1d"
down_revision: Union[str, None] = "1c9e2f4a8b6d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("certificates", sa.Column("email", sa.String(length=255), nullable=True))
    op.add_column("certificates", sa.Column("webroot_path", sa.String(length=1024), nullable=True))
    op.add_column("certificates", sa.Column("standalone_port", sa.Integer(), nullable=True))
    op.add_column("certificates", sa.Column("auth_hook_path", sa.Text(), nullable=True))
    op.add_column("certificates", sa.Column("cleanup_hook_path", sa.Text(), nullable=True))
    op.add_column("certificates", sa.Column("hook_env", sa.JSON(), nullable=True))
    op.add_column("certificates", sa.Column("hook_execution_user", sa.String(length=64), nullable=True))
    op.add_column("certificates", sa.Column("hook_working_directory", sa.Text(), nullable=True))
    op.add_column("certificates", sa.Column("hook_timeout", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("certificates", "hook_timeout")
    op.drop_column("certificates", "hook_working_directory")
    op.drop_column("certificates", "hook_execution_user")
    op.drop_column("certificates", "hook_env")
    op.drop_column("certificates", "cleanup_hook_path")
    op.drop_column("certificates", "auth_hook_path")
    op.drop_column("certificates", "standalone_port")
    op.drop_column("certificates", "webroot_path")
    op.drop_column("certificates", "email")
