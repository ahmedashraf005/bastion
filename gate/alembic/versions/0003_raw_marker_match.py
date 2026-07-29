"""Persist only pre-redaction value-anchored marker-match evidence."""

import sqlalchemy as sa
from alembic import op


revision = "0003_raw_marker_match"
down_revision = "0002_add_policy_audit_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a nullable boolean; NULL means no configured value was evaluated."""

    op.add_column(
        "requests",
        sa.Column("raw_exact_marker_match", sa.Boolean(), nullable=True),
        schema="gate",
    )


def downgrade() -> None:
    """Remove the boolean without touching redacted request audit data."""

    op.drop_column("requests", "raw_exact_marker_match", schema="gate")
