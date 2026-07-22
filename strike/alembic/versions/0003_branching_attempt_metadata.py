"""Record branching-round and prune metadata for Strike attempts.

Revision ID: 0003_branching_attempt_metadata
Revises: 0002_strike_attempts
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0003_branching_attempt_metadata"
down_revision: str | None = "0002_strike_attempts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add auditable pruning fields and backfill legacy single-item rounds."""

    op.alter_column(
        "attempts",
        "target_status",
        existing_type=sa.Integer(),
        nullable=True,
        schema="strike",
    )
    op.add_column(
        "attempts",
        sa.Column(
            "round_number", sa.Integer(), server_default=sa.text("1"), nullable=False
        ),
        schema="strike",
    )
    op.add_column(
        "attempts",
        sa.Column(
            "pruned",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        schema="strike",
    )
    op.add_column(
        "attempts", sa.Column("prune_reason", sa.Text(), nullable=True), schema="strike"
    )
    op.add_column(
        "attempts",
        sa.Column("prune_score", sa.Double(), nullable=True),
        schema="strike",
    )
    # Legacy static and linear-planner attempts were one-candidate rounds.
    op.execute("UPDATE strike.attempts SET round_number = sequence_number")
    op.alter_column(
        "attempts",
        "round_number",
        existing_type=sa.Integer(),
        server_default=None,
        schema="strike",
    )
    op.alter_column(
        "attempts",
        "pruned",
        existing_type=sa.Boolean(),
        server_default=None,
        schema="strike",
    )


def downgrade() -> None:
    """Remove only the metadata introduced for branching campaign rounds."""

    # A downgrade must restore target_status to NOT NULL; preserve the existing
    # network-failure convention for rows that were intentionally never queried.
    # This deliberately collapses pruned/never-queried and network-failure meanings
    # into sentinel 0; that lossy downgrade is accepted rather than overlooked.
    op.execute("UPDATE strike.attempts SET target_status = 0 WHERE target_status IS NULL")
    op.drop_column("attempts", "prune_score", schema="strike")
    op.drop_column("attempts", "prune_reason", schema="strike")
    op.drop_column("attempts", "pruned", schema="strike")
    op.drop_column("attempts", "round_number", schema="strike")
    op.alter_column(
        "attempts",
        "target_status",
        existing_type=sa.Integer(),
        nullable=False,
        schema="strike",
    )
