"""Replace directionally ambiguous blast-radius JSON fields.

Revision ID: 0011_blast_radius_stage
Revises: 0010_campaign_errors
"""

from alembic import op


revision = "0011_blast_radius_stage"
down_revision = "0010_campaign_errors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Record the output stage without laundering the model's legacy class claim.

    Structural invariant: ``normalization_proposals`` can only be written by
    ``NormalizationProposal``, whose detector is the output-only
    ``system_prompt_leak`` detector. Input-stage normalization proposals are
    rejected before persistence.
    """

    op.execute(
        """
        UPDATE strike.normalization_proposals
        SET proposal = jsonb_set(
            proposal,
            ARRAY['blast_radius']::text[],
            (
                ((proposal->'blast_radius'::text) - 'affected_input_classes'::text)
                || jsonb_build_object(
                    'affected_stage', 'output',
                    'affected_classes', 'null'::jsonb,
                    'affected_classes_unverified', true,
                    'legacy_affected_input_classes',
                        proposal->'blast_radius'::text->'affected_input_classes'::text
                )
            )
        )
        WHERE proposal ? 'blast_radius'
          AND proposal->'blast_radius' ? 'affected_input_classes';
        """
    )


def downgrade() -> None:
    """Restore pre-0011 rows exactly; post-0011 rows lose stage metadata.

    Rows created after 0011 have no legacy class claim to restore. Their
    downgrade therefore records JSON null rather than an empty array, making
    the missing provenance explicit. A populated ``affected_classes`` value
    is deliberately discarded rather than mapped to
    ``affected_input_classes``: the legacy name asserts an input-stage
    direction that stage-agnostic data does not carry. Mapping it would
    reintroduce the directional ambiguity this migration removes. As with
    0010, that branch is lossy.
    """

    op.execute(
        """
        UPDATE strike.normalization_proposals
        SET proposal = jsonb_set(
            proposal,
            ARRAY['blast_radius']::text[],
            (
                (
                    (proposal->'blast_radius'::text)
                    - ARRAY[
                        'affected_stage',
                        'affected_classes',
                        'affected_classes_unverified',
                        'legacy_affected_input_classes'
                    ]::text[]
                )
                || jsonb_build_object(
                    'affected_input_classes', COALESCE(
                        proposal->'blast_radius'::text->'legacy_affected_input_classes'::text,
                        'null'::jsonb
                    )
                )
            )
        )
        WHERE proposal ? 'blast_radius'
          AND proposal->'blast_radius' ? 'affected_stage';
        """
    )
