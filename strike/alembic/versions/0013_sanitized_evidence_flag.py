"""Record when a NUL byte was stripped from persisted evidence.

Revision ID: 0013_sanitized_evidence_flag
Revises: 0012_gate_manifest_versions
"""

import sqlalchemy as sa
from alembic import op


revision = "0013_sanitized_evidence_flag"
down_revision = "0012_gate_manifest_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a non-nullable flag, defaulting false for all existing rows."""

    op.add_column(
        "attempts",
        sa.Column(
            "sanitized", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        schema="strike",
    )
    op.add_column(
        "findings",
        sa.Column(
            "sanitized", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        schema="strike",
    )


def downgrade() -> None:
    """Remove the flag without touching any other persisted evidence."""

    op.drop_column("findings", "sanitized", schema="strike")
    op.drop_column("attempts", "sanitized", schema="strike")
