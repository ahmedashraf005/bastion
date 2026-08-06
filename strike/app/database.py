"""Strike-owned SQLAlchemy table definitions for the shared Postgres instance."""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


metadata = sa.MetaData(schema="strike")

attempt_outcome = postgresql.ENUM(
    "confirmed_bypass",
    "near_marker_miss",
    "marker_shaped_nonmatch",
    "gate_redacted_pattern",
    "clean_no_marker_evidence",
    "no_response",
    "transport",
    "pruned",
    name="attempt_outcome",
    schema="strike",
    create_type=False,
)

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
    sa.Column("runner_owner_id", postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("recovery_reason", sa.Text(), nullable=True),
    sa.Column("inference_base_url", sa.Text(), nullable=True),
    sa.Column("inference_route", sa.Text(), nullable=True),
    sa.Column("inference_model", sa.Text(), nullable=True),
    sa.Column("inference_parameters", postgresql.JSONB(), nullable=True),
    sa.Column("gate_normalization_version_id", sa.Text(), nullable=True),
    sa.Column("gate_pattern_version_id", sa.Text(), nullable=True),
    # Local-only diagnostics. They can include payload text from an exception
    # and must never be copied into campaign export/report code.
    sa.Column("error_type", sa.Text(), nullable=True),
    sa.Column("error_detail", sa.Text(), nullable=True),
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
    sa.Column("promoted_strategy_id", sa.Text(), nullable=True),
    sa.Column(
        "found_at",
        sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    ),
    # True if attack_turns or target_reply had a NUL byte (U+0000) or a
    # lone UTF-16 surrogate (U+D800-U+DFFF) stripped before this row was
    # written — Postgres cannot store either at all. Never silent: this is
    # the trace that evidence was altered at the persistence boundary. See
    # gate/app/text_sanitization.py.
    sa.Column(
        "sanitized", sa.Boolean(), server_default=sa.text("false"), nullable=False
    ),
)

proposed_rules = sa.Table(
    "proposed_rules",
    metadata,
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
)

normalization_proposals = sa.Table(
    "normalization_proposals",
    metadata,
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
    sa.Column("version_id", sa.Text(), nullable=False),
    sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("reverted_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("revert_reason", sa.Text(), nullable=True),
    sa.Column(
        "created_at",
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
    sa.Column("target_status", sa.Integer(), nullable=True),
    sa.Column("target_error", sa.Text(), nullable=True),
    sa.Column("target_reply", sa.Text(), nullable=True),
    sa.Column("matched", sa.Boolean(), nullable=False),
    sa.Column("outcome", attempt_outcome, nullable=True),
    sa.Column("normalization_evidence", postgresql.JSONB(), nullable=True),
    sa.Column("parent_node_id", postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column("gate_request_id", postgresql.UUID(as_uuid=True), nullable=True),
    sa.Column("round_number", sa.Integer(), nullable=False),
    sa.Column(
        "pruned", sa.Boolean(), server_default=sa.text("false"), nullable=False
    ),
    sa.Column("prune_reason", sa.Text(), nullable=True),
    sa.Column("prune_score", sa.Double(), nullable=True),
    sa.Column("retrieved_strategy_ids", postgresql.JSONB(), nullable=True),
    # True if any planner- or target-generated text field on this row had a
    # NUL byte (U+0000) or a lone UTF-16 surrogate (U+D800-U+DFFF) stripped
    # before the write — Postgres cannot store either at all. Never silent:
    # this is the trace that evidence was altered at the persistence
    # boundary. See gate/app/text_sanitization.py.
    sa.Column(
        "sanitized", sa.Boolean(), server_default=sa.text("false"), nullable=False
    ),
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


def new_proposed_rule_id() -> uuid.UUID:
    """Create an identifier for a human-reviewable synthesized rule."""

    return uuid.uuid4()


def new_normalization_proposal_id() -> uuid.UUID:
    """Create an identifier for a versioned detector-normalization proposal."""

    return uuid.uuid4()
