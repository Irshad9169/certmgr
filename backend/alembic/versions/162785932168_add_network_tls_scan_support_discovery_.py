"""Add network TLS scan support: discovery_runs columns + sightings table.

Network scanning (scan IP ranges/hosts across a port list, TLS-handshake
each live endpoint, record whatever cert is presented) is a different mode
from the existing filesystem-path discovery, so DiscoveryRun gains a
scan_type discriminator plus scan_targets/scan_ports (parallel to the
existing scan_paths, unused by filesystem runs and vice versa).

network_certificate_sightings records where a certificate was seen
(host:port); it's append-only rather than upserted-in-place so an
endpoint's certificate rotating over time (e.g. self-signed -> CA-issued)
is preserved as history instead of silently overwritten.

Revision ID: 162785932168
Revises: b2e6f1a4c7d9
Create Date: 2026-09-03
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '162785932168'
down_revision: Union[str, None] = 'b2e6f1a4c7d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("discovery_runs", sa.Column("scan_type", sa.String(length=16), nullable=False,
                                               server_default="filesystem"))
    op.add_column("discovery_runs", sa.Column("scan_targets", sa.JSON(), nullable=True))
    op.add_column("discovery_runs", sa.Column("scan_ports", sa.JSON(), nullable=True))

    op.create_table(
        "network_certificate_sightings",
        sa.Column("fingerprint_sha256", sa.String(length=96), nullable=False),
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("sni_hostname", sa.String(length=255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("discovery_run_id", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovery_run_id"], ["discovery_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_certificate_sightings_fingerprint_sha256",
                    "network_certificate_sightings", ["fingerprint_sha256"])
    op.create_index("ix_sighting_host_port", "network_certificate_sightings", ["host", "port"])
    op.create_index("ix_sighting_cert", "network_certificate_sightings", ["certificate_id"])


def downgrade() -> None:
    op.drop_index("ix_sighting_cert", table_name="network_certificate_sightings")
    op.drop_index("ix_sighting_host_port", table_name="network_certificate_sightings")
    op.drop_index("ix_network_certificate_sightings_fingerprint_sha256", table_name="network_certificate_sightings")
    op.drop_table("network_certificate_sightings")
    op.drop_column("discovery_runs", "scan_ports")
    op.drop_column("discovery_runs", "scan_targets")
    op.drop_column("discovery_runs", "scan_type")
