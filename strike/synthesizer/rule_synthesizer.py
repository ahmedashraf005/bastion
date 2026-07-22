"""Narrow, evidence-verified leak-pattern proposals from confirmed findings."""

from __future__ import annotations

import json
import re
from typing import Literal

import httpx
from pydantic import BaseModel

from gate.detectors.system_prompt_leak import LeakPattern, SystemPromptLeakDetector


class ProposedRule(BaseModel):
    """A candidate leak-pattern entry awaiting mechanical verification and review."""

    pattern: str
    pattern_type: Literal["literal", "regex"]
    normalize: Literal["none", "strip_separators"]
    description: str


class FindingEvidence(BaseModel):
    """Only the already-persisted evidence needed to propose a narrow signature."""

    finding_id: str
    attack_turns: list[dict[str, str]]
    target_reply: str


class RuleSynthesizer:
    """Best-effort proposal generation that never surfaces unverified candidates."""

    def __init__(
        self,
        ollama_base_url: str,
        model: str,
        max_parse_retries: int = 3,
        request_timeout_seconds: float = 60,
    ) -> None:
        self._ollama_base_url = ollama_base_url.rstrip("/")
        self._model = model
        self._max_parse_retries = max_parse_retries
        self._request_timeout_seconds = request_timeout_seconds
        self.last_raw_output: str | None = None
        self.last_retry_trace: list[dict[str, object]] = []

    @staticmethod
    def build_messages(
        finding: FindingEvidence, verification_feedback: str | None = None
    ) -> list[dict[str, str]]:
        """Build a bounded, evidence-specific proposal prompt without generalization claims."""

        system_prompt = """You propose one narrow output-leak detection signature from confirmed black-box evidence. Given an attack's turns and the target reply, propose a pattern that catches that exact reply if it appears again. Do not claim to solve the root cause and do not generalize beyond the supplied evidence. Return only a JSON object matching the supplied schema, with a short human-readable description."""
        sections = [
            f"Finding ID: {finding.finding_id}",
            f"Attack turns:\n{json.dumps(finding.attack_turns)}",
            f"Target reply evidence:\n{finding.target_reply}",
            "Choose pattern_type literal or regex, and normalize none or strip_separators.",
        ]
        if verification_feedback is not None:
            sections.append(verification_feedback)
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "\n\n".join(sections)},
        ]

    @staticmethod
    async def _matches_evidence(candidate: ProposedRule, evidence: str) -> bool:
        """Verify through Gate's actual normalization, regex, and span-mapping implementation."""

        detector = SystemPromptLeakDetector.from_definitions(
            [
                LeakPattern(
                    id="synthesizer-verification",
                    description=candidate.description,
                    pattern=candidate.pattern,
                    pattern_type=candidate.pattern_type,
                    normalize=candidate.normalize,
                )
            ]
        )
        signal = await detector.scan(evidence)
        return signal.matched is True

    @staticmethod
    def _nonmatching_feedback(candidate: ProposedRule, evidence: str) -> str:
        """Explain a failed check using Gate's real normalization behavior."""

        if candidate.normalize == "strip_separators":
            normalized_evidence, _ = (
                SystemPromptLeakDetector._strip_separators_with_index_map(evidence)
            )
            return (
                "Your last candidate did not match the target reply evidence under "
                "Gate's real matching logic. With normalize='strip_separators', "
                f"the evidence becomes {normalized_evidence!r} before regex matching, "
                f"but your pattern was {candidate.pattern!r}. Characters such as spaces, "
                "tabs, newlines, hyphens, underscores, and periods are removed before "
                "matching, so a pattern that depends on them cannot match normalized text. "
                "Either adjust the pattern not to depend on characters this normalization "
                "removes, or choose normalize='none' when the pattern needs them."
            )
        return (
            "Your last candidate did not match the target reply evidence under Gate's "
            f"real matching logic. With normalize='none', the evidence remains {evidence!r}; "
            f"your pattern was {candidate.pattern!r}. Choose a valid pattern that matches "
            "that exact evidence."
        )

    async def propose(self, finding: FindingEvidence) -> ProposedRule | None:
        """Return only a candidate proven to match the persisted target reply."""

        feedback: str | None = None
        failures: list[str] = []
        self.last_retry_trace = []
        async with httpx.AsyncClient(timeout=self._request_timeout_seconds) as client:
            for attempt in range(1, self._max_parse_retries + 1):
                try:
                    response = await client.post(
                        f"{self._ollama_base_url}/api/chat",
                        json={
                            "model": self._model,
                            "messages": self.build_messages(finding, feedback),
                            "stream": False,
                            "format": ProposedRule.model_json_schema(),
                        },
                    )
                    response.raise_for_status()
                    raw_output = response.json()["message"]["content"]
                    if not isinstance(raw_output, str):
                        raise ValueError("Ollama proposal content was not a string")
                    self.last_raw_output = raw_output
                    candidate = ProposedRule.model_validate_json(raw_output)
                    verified = await self._matches_evidence(candidate, finding.target_reply)
                    self.last_retry_trace.append(
                        {
                            "attempt": attempt,
                            "raw_output": raw_output,
                            "verified": verified,
                        }
                    )
                    if verified:
                        return candidate
                    feedback = self._nonmatching_feedback(candidate, finding.target_reply)
                    failures.append(f"attempt {attempt}: candidate did not match evidence")
                except (httpx.HTTPError, KeyError, TypeError, ValueError, re.error) as exc:
                    feedback = (
                        "Your last candidate could not be parsed or verified. Try again with "
                        "a valid pattern that matches the target reply evidence."
                    )
                    failures.append(f"attempt {attempt}: {type(exc).__name__}: {exc}")

        print("rule_synthesizer_proposal_failed " + "; ".join(failures))
        return None
