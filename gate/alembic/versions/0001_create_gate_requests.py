"""Create Gate request audit storage.

Revision ID: 0001_create_gate_requests
Revises:
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0001_create_gate_requests"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the schema and table exclusively owned by Bastion.Gate."""

    op.execute("CREATE SCHEMA IF NOT EXISTS gate")
    op.create_table(
        "requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("stream_requested", sa.Boolean(), nullable=False),
        sa.Column("request_body", postgresql.JSONB(), nullable=False),
        sa.Column("response_body", postgresql.JSONB(), nullable=True),
        sa.Column("upstream_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", postgresql.DOUBLE_PRECISION(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema="gate",
    )


def downgrade() -> None:
    """Remove only the objects owned by this Gate migration."""

    op.drop_table("requests", schema="gate")
    op.execute("DROP SCHEMA IF EXISTS gate")
