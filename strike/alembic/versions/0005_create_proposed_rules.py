"""Create the Strike-owned human-review queue for synthesized Gate rules.

Revision ID: 0005_create_proposed_rules
Revises: 0004_strategy_library_references
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0005_create_proposed_rules"
down_revision: str | None = "0004_strategy_library_references"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create only the reviewed-proposal queue owned by Strike."""

    op.create_table(
        "proposed_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("strike.findings.id"),
            nullable=False,
        ),
        sa.Column("proposed_id", sa.Text(), nullable=False),
        sa.Column("proposed_pattern", sa.Text(), nullable=False),
        sa.Column("proposed_pattern_type", sa.Text(), nullable=False),
        sa.Column("proposed_normalize", sa.Text(), nullable=False),
        sa.Column("proposed_description", sa.Text(), nullable=False),
        sa.Column("verification_passed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reviewer_note", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'applied')",
            name="proposed_rules_status_check",
        ),
        schema="strike",
    )


def downgrade() -> None:
    """Remove the proposal queue without changing findings or Gate state."""

    op.drop_table("proposed_rules", schema="strike")
