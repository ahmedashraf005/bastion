"""Persist versioned normalization proposals, sign-off, and deployment state.

Revision ID: 0008_norm_promotion
Revises: 0007_campaign_leases
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0008_norm_promotion"
down_revision: str | None = "0007_campaign_leases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create Strike's auditable, reversible normalization-promotion record."""

    op.create_table(
        "normalization_proposals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("strike.findings.id"),
            nullable=False,
        ),
        sa.Column("proposal", postgresql.JSONB(), nullable=False),
        sa.Column("verification_passed", sa.Boolean(), nullable=False),
        sa.Column("verification_mode", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("approver", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_evidence", postgresql.JSONB(), nullable=True),
        sa.Column("version_id", sa.Text(), nullable=False, unique=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reverted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revert_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'approved', 'applied', 'reverted')",
            name="normalization_proposals_status_check",
        ),
        schema="strike",
    )


def downgrade() -> None:
    """Remove the promotion record without mutating Gate's deployed config."""

    op.drop_table("normalization_proposals", schema="strike")
