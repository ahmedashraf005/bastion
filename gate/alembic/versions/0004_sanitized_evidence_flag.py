"""Record when a NUL byte was stripped from a persisted request/response.

Revision ID: 0004_sanitized_evidence_flag
Revises: 0003_raw_marker_match
"""

import sqlalchemy as sa
from alembic import op


revision = "0004_sanitized_evidence_flag"
down_revision = "0003_raw_marker_match"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a non-nullable flag, defaulting false for all existing rows."""

    op.add_column(
        "requests",
        sa.Column(
            "sanitized", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        schema="gate",
    )


def downgrade() -> None:
    """Remove the flag without touching any other persisted audit data."""

    op.drop_column("requests", "sanitized", schema="gate")
