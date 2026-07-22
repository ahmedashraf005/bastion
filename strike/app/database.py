"""Strike-owned SQLAlchemy table definitions for the shared Postgres instance."""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


metadata = sa.MetaData(schema="strike")

campaigns = sa.Table(
    "campaigns",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
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
)

findings = sa.Table(
    "findings",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
    sa.Column(
        "campaign_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("strike.campaigns.id"),
        nullable=False,
    ),
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
)

attempts = sa.Table(
    "attempts",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
    sa.Column(
        "campaign_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("strike.campaigns.id"),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("source", sa.Text(), nullable=False),
    sa.Column("planner_reasoning", sa.Text(), nullable=True),
    sa.Column("attack_turns", postgresql.JSONB(), nullable=False),
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
)


def new_campaign_id() -> uuid.UUID:
    """Create a campaign identifier before the initial insert."""

    return uuid.uuid4()


def new_finding_id() -> uuid.UUID:
    """Create a finding identifier before its insert."""

    return uuid.uuid4()


def new_attempt_id() -> uuid.UUID:
    """Create an attempt identifier before its insert."""

    return uuid.uuid4()
