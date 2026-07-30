"""Store the resolved inference route and configuration for every campaign.

Revision ID: 0009_inference_provenance
Revises: 0008_norm_promotion
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0009_inference_provenance"
down_revision = "0008_norm_promotion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add nullable, backfill-safe provenance; existing campaigns remain historical."""

    op.add_column("campaigns", sa.Column("inference_base_url", sa.Text(), nullable=True), schema="strike")
    op.add_column("campaigns", sa.Column("inference_route", sa.Text(), nullable=True), schema="strike")
    op.add_column("campaigns", sa.Column("inference_model", sa.Text(), nullable=True), schema="strike")
    op.add_column(
        "campaigns", sa.Column("inference_parameters", postgresql.JSONB(), nullable=True), schema="strike"
    )
    op.create_check_constraint(
        "campaigns_inference_route_valid",
        "campaigns",
        "inference_route IS NULL OR inference_route IN "
        "('host_native', 'compose_container', 'other')",
        schema="strike",
    )


def downgrade() -> None:
    """Remove only the provenance fields added by this migration."""

    op.drop_constraint("campaigns_inference_route_valid", "campaigns", schema="strike")
    op.drop_column("campaigns", "inference_parameters", schema="strike")
    op.drop_column("campaigns", "inference_model", schema="strike")
    op.drop_column("campaigns", "inference_route", schema="strike")
    op.drop_column("campaigns", "inference_base_url", schema="strike")
