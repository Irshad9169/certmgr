"""Add presented_certificate_id to certificate_usage_results.

When a usage-discovery probe finds a different_certificate result, and the
presented fingerprint matches another certificate CertMgr already tracks,
this links to it directly — so the UI can say "actually serving Certificate
#47 (*.otherapp.com)" instead of just showing raw, unattributed subject/
issuer text for a certificate CertMgr happens to already know about.

Revision ID: f2a7c94e6b1d
Revises: e91a4c6f8b2d
Create Date: 2026-09-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f2a7c94e6b1d'
down_revision: Union[str, None] = 'e91a4c6f8b2d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("certificate_usage_results") as batch_op:
        batch_op.add_column(sa.Column("presented_certificate_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_cert_usage_result_presented_cert", "certificates",
            ["presented_certificate_id"], ["id"], ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("certificate_usage_results") as batch_op:
        batch_op.drop_constraint("fk_cert_usage_result_presented_cert", type_="foreignkey")
        batch_op.drop_column("presented_certificate_id")
