"""Persist terminal campaign exceptions and distinguish partial execution.

Revision ID: 0010_campaign_errors
Revises: 0009_inference_provenance
"""

import sqlalchemy as sa
from alembic import op


revision = "0010_campaign_errors"
down_revision = "0009_inference_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add diagnostics and a terminal state for exceptions after persisted attempts."""

    op.add_column("campaigns", sa.Column("error_type", sa.Text(), nullable=True), schema="strike")
    op.add_column("campaigns", sa.Column("error_detail", sa.Text(), nullable=True), schema="strike")
    op.drop_constraint("campaigns_status_valid", "campaigns", schema="strike")
    op.create_check_constraint(
        "campaigns_status_valid",
        "campaigns",
        "status IN ('running', 'bypass_found', 'completed_no_bypass', "
        "'query_limit_reached', 'timed_out', 'error', 'interrupted', "
        "'failed_after_progress')",
        schema="strike",
    )


def downgrade() -> None:
    """Collapse the newer terminal state before removing its diagnostic fields."""

    op.execute(
        "UPDATE strike.campaigns SET status = 'error' "
        "WHERE status = 'failed_after_progress'"
    )
    op.drop_constraint("campaigns_status_valid", "campaigns", schema="strike")
    op.create_check_constraint(
        "campaigns_status_valid",
        "campaigns",
        "status IN ('running', 'bypass_found', 'completed_no_bypass', "
        "'query_limit_reached', 'timed_out', 'error', 'interrupted')",
        schema="strike",
    )
    op.drop_column("campaigns", "error_detail", schema="strike")
    op.drop_column("campaigns", "error_type", schema="strike")
