"""Add policy-evaluation audit fields to Gate requests.

Revision ID: 0002_add_policy_audit_fields
Revises: 0001_create_gate_requests
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0002_add_policy_audit_fields"
down_revision: str | None = "0001_create_gate_requests"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the policy evaluation details to the Gate-owned audit table."""

    op.add_column("requests", sa.Column("policy_action", sa.Text(), nullable=True), schema="gate")
    op.add_column(
        "requests",
        sa.Column("matched_rules", postgresql.JSONB(), nullable=True),
        schema="gate",
    )
    op.add_column(
        "requests",
        sa.Column("detector_signals", postgresql.JSONB(), nullable=True),
        schema="gate",
    )


def downgrade() -> None:
    """Remove only the policy evaluation audit fields from Gate requests."""

    op.drop_column("requests", "detector_signals", schema="gate")
    op.drop_column("requests", "matched_rules", schema="gate")
    op.drop_column("requests", "policy_action", schema="gate")
