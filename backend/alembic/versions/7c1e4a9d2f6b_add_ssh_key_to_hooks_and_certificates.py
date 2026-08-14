"""Add encrypted SSH private key + target host to Hook and Certificate.

Some auth/cleanup hook scripts SSH to a remote host (with no -i flag) to
place/remove an ACME challenge file, relying entirely on whatever identity
the calling process's ssh already trusts — which breaks for headless/
worker-driven issuance since there's no interactively-forwarded agent.
Lets an admin attach an SSH private key to a Hook (like a Jenkins
credential) so CertMgr can stage it as a temporary, host-scoped ssh_config
entry for the duration of a single hook-driven issuance. The key is
Fernet-encrypted at rest (same mechanism already used for provider
configs) and never returned by the API. Certificate gets the same two
columns so async/queued issuance can reconstruct it, mirroring the
hook_* columns added in 3f7a9c2e5b1d. All new columns are nullable —
existing rows are unaffected.

Revision ID: 7c1e4a9d2f6b
Revises: 3f7a9c2e5b1d
Create Date: 2026-08-14
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "7c1e4a9d2f6b"
down_revision: Union[str, None] = "3f7a9c2e5b1d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("hooks", sa.Column("ssh_private_key_encrypted", sa.Text(), nullable=True))
    op.add_column("hooks", sa.Column("ssh_target_host", sa.String(length=255), nullable=True))
    op.add_column("certificates", sa.Column("ssh_private_key_encrypted", sa.Text(), nullable=True))
    op.add_column("certificates", sa.Column("ssh_target_host", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("certificates", "ssh_target_host")
    op.drop_column("certificates", "ssh_private_key_encrypted")
    op.drop_column("hooks", "ssh_target_host")
    op.drop_column("hooks", "ssh_private_key_encrypted")
