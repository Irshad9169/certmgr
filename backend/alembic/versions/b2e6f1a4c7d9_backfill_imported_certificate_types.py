"""Backfill cert_type for previously-imported certificates.

import_certificate() hardcoded cert_type="imported" for every imported
certificate regardless of its actual structure, even though is_wildcard and
sans were already parsed correctly from the certificate. This meant the
Certificates page's Type column (and the dashboard's certificates-by-type
breakdown) showed "Imported" instead of Wildcard/SAN/Single for every
imported certificate. The app code now derives cert_type from structure on
import just like it already did for issued certificates; this backfills
existing rows written before that fix. The `imported` boolean column already
tracks provenance separately, so no information is lost.

Revision ID: b2e6f1a4c7d9
Revises: 9d4b6e1a3c8f
Create Date: 2026-08-27
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b2e6f1a4c7d9"
down_revision: Union[str, None] = "9d4b6e1a3c8f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

certificates = sa.table(
    "certificates",
    sa.column("id", sa.Integer),
    sa.column("cert_type", sa.String),
    sa.column("is_wildcard", sa.Boolean),
    sa.column("imported", sa.Boolean),
    sa.column("sans", sa.JSON),
)


def _cert_type_for(is_wildcard: bool, sans: list) -> str:
    if is_wildcard:
        return "wildcard"
    if len(sans or []) > 1:
        return "multi"
    return "single"


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.select(certificates.c.id, certificates.c.is_wildcard, certificates.c.sans)
        .where(certificates.c.cert_type == "imported")
    ).fetchall()
    for row in rows:
        bind.execute(
            certificates.update()
            .where(certificates.c.id == row.id)
            .values(cert_type=_cert_type_for(row.is_wildcard, row.sans))
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(certificates.update().where(certificates.c.imported.is_(True)).values(cert_type="imported"))
