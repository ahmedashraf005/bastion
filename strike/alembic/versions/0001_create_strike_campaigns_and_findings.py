"""Create Strike campaign and finding storage.

Revision ID: 0001_strike_initial
Revises:
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0001_strike_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


CAMPAIGN_STATUSES = (
    "running",
    "bypass_found",
    "completed_no_bypass",
    "query_limit_reached",
    "timed_out",
    "error",
)


def upgrade() -> None:
    """Create the schema and tables exclusively owned by Bastion.Strike."""

    op.execute("CREATE SCHEMA IF NOT EXISTS strike")
    op.create_table(
        "campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("owasp_id", sa.Text(), nullable=False),
        sa.Column("target_key", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_queries", sa.Integer(), nullable=False),
        sa.Column(
            "queries_used", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("max_wall_clock_seconds", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN (" + ", ".join(f"'{status}'" for status in CAMPAIGN_STATUSES) + ")",
            name="campaigns_status_valid",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="strike",
    )
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owasp_id", sa.Text(), nullable=False),
        sa.Column("attack_turns", postgresql.JSONB(), nullable=False),
        sa.Column("target_reply", sa.Text(), nullable=False),
        sa.Column("matched_pattern", sa.Text(), nullable=False),
        sa.Column("gate_request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "found_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["strike.campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema="strike",
    )


def downgrade() -> None:
    """Remove only the objects owned by this Strike migration."""

    op.drop_table("findings", schema="strike")
    op.drop_table("campaigns", schema="strike")
    op.execute("DROP SCHEMA IF EXISTS strike")
