"""Add owner leases and explicit interrupted recovery state to campaigns."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0007_campaign_leases"
down_revision = "0006_success_outcomes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Store renewable ownership metadata without inferring meaning for NULL leases."""

    op.add_column(
        "campaigns",
        sa.Column("runner_owner_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="strike",
    )
    op.add_column(
        "campaigns",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        schema="strike",
    )
    op.add_column(
        "campaigns",
        sa.Column("recovery_reason", sa.Text(), nullable=True),
        schema="strike",
    )
    op.drop_constraint("campaigns_status_valid", "campaigns", schema="strike")
    op.create_check_constraint(
        "campaigns_status_valid",
        "campaigns",
        "status IN ('running', 'bypass_found', 'completed_no_bypass', "
        "'query_limit_reached', 'timed_out', 'error', 'interrupted')",
        schema="strike",
    )


def downgrade() -> None:
    """Drop lease metadata after rejecting an irreversible interrupted-state downgrade."""

    op.execute(
        "UPDATE strike.campaigns SET status = 'error' "
        "WHERE status = 'interrupted'"
    )
    op.drop_constraint("campaigns_status_valid", "campaigns", schema="strike")
    op.create_check_constraint(
        "campaigns_status_valid",
        "campaigns",
        "status IN ('running', 'bypass_found', 'completed_no_bypass', "
        "'query_limit_reached', 'timed_out', 'error')",
        schema="strike",
    )
    op.drop_column("campaigns", "recovery_reason", schema="strike")
    op.drop_column("campaigns", "lease_expires_at", schema="strike")
    op.drop_column("campaigns", "runner_owner_id", schema="strike")
