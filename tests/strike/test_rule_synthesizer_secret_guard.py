"""Secret-retention guard tests for synthesized, reviewable rules."""

import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from strike.synthesizer.rule_synthesizer import (
    AdditiveNormalization,
    BlastRadiusReport,
    FindingEvidence,
    MARKER_PLACEHOLDER,
    NormalizationProposal,
    PROPOSAL_ADAPTER,
    RuleSynthesizer,
)


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return {
            "message": {
                "content": json.dumps(
                    {
                        "proposal_type": "signature",
                        "proposal_schema_version": 1,
                        "signature": {
                            "marker_ref": "sample-bank.internal_configuration_marker",
                            "pattern": MARKER_PLACEHOLDER,
                            "pattern_type": "literal",
                            "normalize": "none",
                        },
                        "description": "Contains BASTION-CANARY-7K2M9QX4",
                        "blast_radius": {
                            "affected_stage": "output",
                            "affected_classes": ["marker output"],
                            "expected_false_positive_risk": "low",
                            "rationale": "test",
                            "benign_corpus_required": False,
                        },
                    }
                )
            }
        }


class _FakeClient:
    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def post(self, *args: object, **kwargs: object) -> _FakeResponse:
        return _FakeResponse()


class _ProposalResponse:
    def __init__(self, proposal: dict[str, object]) -> None:
        self._proposal = proposal

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return {"message": {"content": json.dumps(self._proposal)}}


class _ProposalClient:
    def __init__(self, proposal: dict[str, object]) -> None:
        self._proposal = proposal

    async def __aenter__(self) -> "_ProposalClient":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def post(self, *args: object, **kwargs: object) -> _ProposalResponse:
        return _ProposalResponse(self._proposal)


class RuleSynthesizerSecretGuardTests(unittest.TestCase):
    def test_marker_value_is_rejected_before_mechanical_verification(self) -> None:
        async def exercise() -> None:
            synthesizer = RuleSynthesizer(
                ollama_base_url="http://example.invalid",
                model="test-model",
                max_parse_retries=1,
                forbidden_marker_values={"BASTION-CANARY-7K2M9QX4"},
            )
            with (
                patch(
                    "strike.synthesizer.rule_synthesizer.httpx.AsyncClient",
                    return_value=_FakeClient(),
                ),
                patch.object(
                    RuleSynthesizer,
                    "mechanical_verification",
                    new_callable=AsyncMock,
                ) as verifier,
            ):
                proposal = await synthesizer.propose(
                    FindingEvidence(
                        finding_id="finding",
                        attack_turns=[],
                        target_reply="evidence",
                    )
                )

            self.assertIsNone(proposal)
            verifier.assert_not_awaited()
            self.assertEqual(
                synthesizer.last_retry_trace[0]["rejection_reason"],
                "contains_configured_marker_value",
            )

        asyncio.run(exercise())

    def test_marker_value_never_appears_in_built_prompt(self) -> None:
        marker = "BASTION-CANARY-7K2M9QX4"
        formatted_marker = "\u200b".join(marker)
        messages = RuleSynthesizer.build_messages(
            FindingEvidence(
                finding_id="finding",
                attack_turns=[{"role": "user", "content": marker}],
                target_reply=f"reply: {formatted_marker}",
                normalization_evidence={"steps_fired": ["Cf"]},
            ),
            frozenset({marker}),
        )
        self.assertNotIn(marker, "\n".join(message["content"] for message in messages))
        self.assertIn(MARKER_PLACEHOLDER, messages[1]["content"])

    def test_prompt_exposes_detector_delta_for_nbsp_and_zero_width_space(self) -> None:
        messages = RuleSynthesizer.build_messages(
            FindingEvidence(
                finding_id="finding",
                attack_turns=[],
                target_reply="\u00a0\u200b",
            )
        )
        prompt = messages[1]["content"]
        self.assertIn("U+00A0 | Zs | NO-BREAK SPACE | isspace=True | ALREADY stripped", prompt)
        self.assertIn("U+200B | Cf | ZERO WIDTH SPACE | isspace=False | NOT stripped (gap)", prompt)
        self.assertIn("redundant no-op", prompt)

    def test_literal_regex_syntax_has_a_distinct_validation_reason(self) -> None:
        with self.assertRaisesRegex(ValidationError, "literal_contains_regex_syntax"):
            PROPOSAL_ADAPTER.validate_python(
                {
                    "proposal_type": "signature",
                    "proposal_schema_version": 1,
                    "signature": {
                        "marker_ref": "sample-bank.internal_configuration_marker",
                        "pattern": MARKER_PLACEHOLDER + r"\\s+",
                        "pattern_type": "literal",
                        "normalize": "none",
                    },
                    "description": "test",
                    "blast_radius": {
                        "affected_stage": "output",
                        "affected_classes": ["test"],
                        "expected_false_positive_risk": "low",
                        "rationale": "test",
                        "benign_corpus_required": False,
                    },
                }
            )

    def test_noncompiling_regex_has_a_distinct_validation_reason(self) -> None:
        with self.assertRaisesRegex(ValidationError, "regex_does_not_compile"):
            PROPOSAL_ADAPTER.validate_python(
                {
                    "proposal_type": "signature",
                    "proposal_schema_version": 1,
                    "signature": {
                        "marker_ref": "sample-bank.internal_configuration_marker",
                        "pattern": "(" + MARKER_PLACEHOLDER,
                        "pattern_type": "regex",
                        "normalize": "none",
                    },
                    "description": "test",
                    "blast_radius": {
                        "affected_stage": "output",
                        "affected_classes": ["test"],
                        "expected_false_positive_risk": "low",
                        "rationale": "test",
                        "benign_corpus_required": False,
                    },
                }
            )

    def test_normalization_is_blocked_without_a_benign_corpus(self) -> None:
        proposal = NormalizationProposal(
            proposal_type="normalization",
            proposal_schema_version=1,
            detector="system_prompt_leak",
            normalization=AdditiveNormalization(operation="add", unicode_categories=["Cf"]),
            description="test",
            blast_radius=BlastRadiusReport(
                affected_stage="output",
                affected_classes=["format characters"],
                expected_false_positive_risk="medium",
                rationale="test",
                benign_corpus_required=True,
            ),
        )
        with patch(
            "strike.synthesizer.rule_synthesizer.BENIGN_CORPUS_PATH",
            Path("/nonexistent/benign.yaml"),
        ):
            self.assertEqual(
                RuleSynthesizer.promotion_tier(proposal),
                ("tier_3_normalization", "blocked_missing_benign_corpus"),
            )

    def test_fully_covered_normalization_is_rejected_before_verification(self) -> None:
        proposal = {
            "proposal_type": "normalization",
            "proposal_schema_version": 1,
            "detector": "system_prompt_leak",
            "normalization": {
                "operation": "add",
                "named_classes": ["unicode_whitespace"],
                "codepoints": ["U+00A0"],
            },
            "description": "no-op",
            "blast_radius": {
                "affected_stage": "output",
                "affected_classes": ["whitespace"],
                "expected_false_positive_risk": "low",
                "rationale": "test",
                "benign_corpus_required": True,
            },
        }

        async def exercise() -> None:
            synthesizer = RuleSynthesizer(
                ollama_base_url="http://example.invalid", model="test", max_parse_retries=1
            )
            with (
                patch(
                    "strike.synthesizer.rule_synthesizer.httpx.AsyncClient",
                    return_value=_ProposalClient(proposal),
                ),
                patch.object(
                    RuleSynthesizer,
                    "mechanical_verification",
                    new_callable=AsyncMock,
                ) as verifier,
            ):
                result = await synthesizer.propose(
                    FindingEvidence(finding_id="finding", attack_turns=[], target_reply="evidence")
                )
            self.assertIsNone(result)
            verifier.assert_not_awaited()
            self.assertEqual(
                synthesizer.last_retry_trace[0]["rejection_reason"], "redundant_no_op"
            )

        asyncio.run(exercise())

    def test_partial_overlap_is_reported_not_rejected(self) -> None:
        proposal = NormalizationProposal(
            proposal_type="normalization",
            proposal_schema_version=1,
            detector="system_prompt_leak",
            normalization=AdditiveNormalization(
                operation="add", unicode_categories=["Cf"], codepoints=["U+00A0"]
            ),
            description="partial",
            blast_radius=BlastRadiusReport(
                affected_stage="output",
                affected_classes=["format characters"],
                expected_false_positive_risk="medium",
                rationale="test",
                benign_corpus_required=True,
            ),
        )
        redundant_no_op, overlap = RuleSynthesizer._normalization_overlap(proposal)
        self.assertFalse(redundant_no_op)
        self.assertEqual(overlap, ["codepoint:U+00A0"])
        proposal.blast_radius.existing_normalization_overlap = overlap
        self.assertEqual(
            proposal.blast_radius.existing_normalization_overlap, ["codepoint:U+00A0"]
        )

    def test_output_stage_proposal_rejects_input_only_classes(self) -> None:
        with self.assertRaisesRegex(
            ValidationError, "output_stage_cannot_report_input_only_classes"
        ):
            PROPOSAL_ADAPTER.validate_python(
                {
                    "proposal_type": "normalization",
                    "proposal_schema_version": 1,
                    "detector": "system_prompt_leak",
                    "normalization": {"operation": "add", "unicode_categories": ["Cf"]},
                    "description": "incorrect direction",
                    "blast_radius": {
                        "affected_stage": "output",
                        "affected_classes": ["user_input"],
                        "expected_false_positive_risk": "high",
                        "rationale": "test",
                        "benign_corpus_required": True,
                    },
                }
            )
