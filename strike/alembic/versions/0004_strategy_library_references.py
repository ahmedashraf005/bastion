"""Record strategy-library context and successful promotion references.

Revision ID: 0004_strategy_library_references
Revises: 0003_branching_attempt_metadata
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0004_strategy_library_references"
down_revision: str | None = "0003_branching_attempt_metadata"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add nullable references; historical rows predate strategy-library context."""

    op.add_column(
        "attempts",
        sa.Column("retrieved_strategy_ids", postgresql.JSONB(), nullable=True),
        schema="strike",
    )
    op.add_column(
        "findings",
        sa.Column("promoted_strategy_id", sa.Text(), nullable=True),
        schema="strike",
    )


def downgrade() -> None:
    """Remove only the optional strategy-library references."""

    op.drop_column("findings", "promoted_strategy_id", schema="strike")
    op.drop_column("attempts", "retrieved_strategy_ids", schema="strike")
