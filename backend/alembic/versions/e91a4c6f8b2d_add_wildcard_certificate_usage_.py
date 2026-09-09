"""Add wildcard certificate usage discovery: certificate_usage_scans, certificate_usage_results.

Answers a different question from CT monitoring or the network scanner:
given a specific wildcard certificate already in CertMgr, which real
endpoints are actually presenting *that exact* certificate right now, based
on an exact SHA-256 fingerprint match against a live TLS/SNI handshake —
never CN/SAN/wildcard coverage alone.

certificate_usage_results is upserted in place per (certificate, hostname,
ip, port) — unlike network_certificate_sightings, a certificate rotation
history isn't the point here, "what does this endpoint present right now"
is, so first_seen_at is preserved across rescans while status/presented_*
always reflect the most recent probe.

Revision ID: e91a4c6f8b2d
Revises: 83caf2fc7394
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e91a4c6f8b2d'
down_revision: Union[str, None] = '83caf2fc7394'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "certificate_usage_scans",
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("candidate_count", sa.Integer(), nullable=False),
        sa.Column("scanned_count", sa.Integer(), nullable=False),
        sa.Column("confirmed_count", sa.Integer(), nullable=False),
        sa.Column("different_certificate_count", sa.Integer(), nullable=False),
        sa.Column("unreachable_count", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("log", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cert_usage_scan_cert", "certificate_usage_scans", ["certificate_id"])
    op.create_index("ix_cert_usage_scan_status", "certificate_usage_scans", ["status"])

    op.create_table(
        "certificate_usage_results",
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expected_fingerprint", sa.String(length=96), nullable=True),
        sa.Column("presented_fingerprint", sa.String(length=96), nullable=True),
        sa.Column("presented_subject", sa.String(length=512), nullable=True),
        sa.Column("presented_issuer", sa.String(length=512), nullable=True),
        sa.Column("presented_serial", sa.String(length=128), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovery_source", sa.String(length=16), nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["certificate_usage_scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("certificate_id", "hostname", "ip_address", "port",
                            name="uq_cert_usage_result_endpoint"),
    )
    op.create_index("ix_cert_usage_result_cert", "certificate_usage_results", ["certificate_id"])
    op.create_index("ix_cert_usage_result_status", "certificate_usage_results", ["status"])
    op.create_index("ix_cert_usage_result_hostname", "certificate_usage_results", ["hostname"])


def downgrade() -> None:
    op.drop_index("ix_cert_usage_result_hostname", table_name="certificate_usage_results")
    op.drop_index("ix_cert_usage_result_status", table_name="certificate_usage_results")
    op.drop_index("ix_cert_usage_result_cert", table_name="certificate_usage_results")
    op.drop_table("certificate_usage_results")

    op.drop_index("ix_cert_usage_scan_status", table_name="certificate_usage_scans")
    op.drop_index("ix_cert_usage_scan_cert", table_name="certificate_usage_scans")
    op.drop_table("certificate_usage_scans")
