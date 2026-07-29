"""Persist value-anchored success outcomes and TAP parent links."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006_success_outcomes"
down_revision = "0005_create_proposed_rules"
branch_labels = None
depends_on = None


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
)


def upgrade() -> None:
    """Add nullable fields without rewriting historical attempt evidence."""

    attempt_outcome.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "attempts",
        sa.Column("outcome", attempt_outcome, nullable=True),
        schema="strike",
    )
    op.add_column(
        "attempts",
        sa.Column("normalization_evidence", postgresql.JSONB(), nullable=True),
        schema="strike",
    )
    op.add_column(
        "attempts",
        sa.Column("parent_node_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="strike",
    )


def downgrade() -> None:
    """Revert the three independent attempt-evidence additions."""

    op.drop_column("attempts", "parent_node_id", schema="strike")
    op.drop_column("attempts", "normalization_evidence", schema="strike")
    op.drop_column("attempts", "outcome", schema="strike")
    attempt_outcome.drop(op.get_bind(), checkfirst=True)
