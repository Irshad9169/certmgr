"""Add discovery_ignores table.

run_discovery() only knows about "already seen" fingerprints by querying
the current certificates table — deleting a discovered certificate's row
doesn't stop the next scan from re-importing the same file on disk (e.g.
an OS-default self-signed cert under a default scan path like
/etc/pki/tls/certs). This table lets delete_certificate() record a
deleted, discovery-imported certificate's fingerprint so future runs
skip it too.

Revision ID: 9d4b6e1a3c8f
Revises: 7c1e4a9d2f6b
Create Date: 2026-08-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "9d4b6e1a3c8f"
down_revision: Union[str, None] = "7c1e4a9d2f6b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "discovery_ignores",
        sa.Column("fingerprint_sha256", sa.String(length=96), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("source_path", sa.Text(), nullable=True),
        sa.Column("ignored_by", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint_sha256"),
    )
    op.create_index(
        "ix_discovery_ignores_fingerprint_sha256", "discovery_ignores", ["fingerprint_sha256"], unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_discovery_ignores_fingerprint_sha256", table_name="discovery_ignores")
    op.drop_table("discovery_ignores")
