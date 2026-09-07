"""Add CT monitoring support: ct_observations, ct_findings, discovery_runs.scan_domains.

Certificate Transparency monitoring queries crt.sh for admin-configured
domains — a third DiscoveryRun.scan_type ("ct_log", alongside "filesystem"
and "network"), so it gets its own optional target-shape column
(scan_domains) the same way "network" got scan_targets/scan_ports.

ct_observations is the CT analogue of network_certificate_sightings, but
NOT append-only: a crt.sh entry (crt_sh_id) is an immutable historical
record, not a live endpoint that can start serving a different certificate,
so a rescan just bumps last_seen_at in place (unique on crt_sh_id).

ct_findings is the first lifecycle-bearing "finding" model in CertMgr —
compliance reports and health checks are both point-in-time logs with no
acknowledge/resolve capability; this one has a real status workflow
(open -> acknowledged/investigating -> false_positive/resolved).

Revision ID: 83caf2fc7394
Revises: 162785932168
Create Date: 2026-09-07
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '83caf2fc7394'
down_revision: Union[str, None] = '162785932168'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("discovery_runs", sa.Column("scan_domains", sa.JSON(), nullable=True))

    op.create_table(
        "ct_observations",
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("crt_sh_id", sa.Integer(), nullable=False),
        sa.Column("matched_domain", sa.String(length=253), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("ct_monitor_run_id", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ct_monitor_run_id"], ["discovery_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("crt_sh_id"),
    )
    op.create_index("ix_ct_observations_crt_sh_id", "ct_observations", ["crt_sh_id"], unique=True)
    op.create_index("ix_ct_observation_cert", "ct_observations", ["certificate_id"])

    op.create_table(
        "ct_findings",
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("match_type", sa.String(length=16), nullable=False),
        sa.Column("detections", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("resolution_reason", sa.Text(), nullable=True),
        sa.Column("assigned_to", sa.Integer(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("ct_monitor_run_id", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ct_monitor_run_id"], ["discovery_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ct_finding_cert", "ct_findings", ["certificate_id"])
    op.create_index("ix_ct_finding_status", "ct_findings", ["status"])
    op.create_index("ix_ct_finding_severity", "ct_findings", ["severity"])
    op.create_index("ix_ct_finding_domain", "ct_findings", ["domain"])


def downgrade() -> None:
    op.drop_index("ix_ct_finding_domain", table_name="ct_findings")
    op.drop_index("ix_ct_finding_severity", table_name="ct_findings")
    op.drop_index("ix_ct_finding_status", table_name="ct_findings")
    op.drop_index("ix_ct_finding_cert", table_name="ct_findings")
    op.drop_table("ct_findings")

    op.drop_index("ix_ct_observation_cert", table_name="ct_observations")
    op.drop_index("ix_ct_observations_crt_sh_id", table_name="ct_observations")
    op.drop_table("ct_observations")

    op.drop_column("discovery_runs", "scan_domains")
