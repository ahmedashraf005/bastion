"""Persist every Strike campaign attempt.

Revision ID: 0002_strike_attempts
Revises: 0001_strike_initial
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0002_strike_attempts"
down_revision: str | None = "0001_strike_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create complete, ordered attempt records owned by Bastion.Strike."""

    op.create_table(
        "attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("planner_reasoning", sa.Text(), nullable=True),
        sa.Column("attack_turns", postgresql.JSONB(), nullable=False),
        # 0 denotes no HTTP response; target_error holds the network failure.
        sa.Column("target_status", sa.Integer(), nullable=False),
        sa.Column("target_error", sa.Text(), nullable=True),
        sa.Column("target_reply", sa.Text(), nullable=True),
        sa.Column("matched", sa.Boolean(), nullable=False),
        sa.Column("gate_request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["strike.campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema="strike",
    )


def downgrade() -> None:
    """Remove only Strike's complete attempt-record storage."""

    op.drop_table("attempts", schema="strike")
