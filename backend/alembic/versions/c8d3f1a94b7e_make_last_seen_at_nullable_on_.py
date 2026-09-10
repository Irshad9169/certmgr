"""Make certificate_usage_results.last_seen_at nullable.

A candidate that has never once been confirmed/different_certificate (e.g.
unreachable on every scan since it was first added) has genuinely never
been "seen" serving anything. The column previously had a Python-side
default of utcnow(), which meant a brand-new row for an unreachable
candidate silently got stamped with the scan's own timestamp — an
independent audit caught this as a real correctness bug (the UI/API could
show "last seen: just now" for an endpoint that has never actually
answered). NULL now means exactly what it should: never confirmed
reachable.

Revision ID: c8d3f1a94b7e
Revises: f2a7c94e6b1d
Create Date: 2026-09-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c8d3f1a94b7e'
down_revision: Union[str, None] = 'f2a7c94e6b1d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("certificate_usage_results") as batch_op:
        batch_op.alter_column("last_seen_at", existing_type=sa.DateTime(timezone=True), nullable=True)


def downgrade() -> None:
    # Backfill any NULLs before restoring NOT NULL, so the downgrade itself
    # doesn't fail against real data.
    op.execute(
        "UPDATE certificate_usage_results SET last_seen_at = last_checked_at WHERE last_seen_at IS NULL"
    )
    with op.batch_alter_table("certificate_usage_results") as batch_op:
        batch_op.alter_column("last_seen_at", existing_type=sa.DateTime(timezone=True), nullable=False)
