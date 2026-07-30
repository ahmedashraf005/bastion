"""Record the active Gate detector manifests used by each campaign.

Revision ID: 0012_gate_manifest_versions
Revises: 0011_blast_radius_stage
"""

import sqlalchemy as sa
from alembic import op


revision = "0012_gate_manifest_versions"
down_revision = "0011_blast_radius_stage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add nullable version provenance without inventing a composite profile ID."""

    op.add_column(
        "campaigns",
        sa.Column("gate_normalization_version_id", sa.Text(), nullable=True),
        schema="strike",
    )
    op.add_column(
        "campaigns",
        sa.Column("gate_pattern_version_id", sa.Text(), nullable=True),
        schema="strike",
    )


def downgrade() -> None:
    """Remove only the two independently recorded manifest IDs."""

    op.drop_column("campaigns", "gate_pattern_version_id", schema="strike")
    op.drop_column("campaigns", "gate_normalization_version_id", schema="strike")
