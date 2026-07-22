"""Pluggable static, linear-planner, and branching-planner attempt sources."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Callable, Literal, Protocol

import httpx
from pydantic import BaseModel, Field

from strike.planner.attacker import AttackerPlanner, PlannerAttempt
from strike.planner.prune_gate import PruneGate


class AttemptTurn(BaseModel):
    """One caller-visible target message."""

    role: Literal["user", "assistant"]
    content: str


class StaticAttempt(BaseModel):
    """The existing YAML shape for a static, potentially multi-turn attempt."""

    turns: list[AttemptTurn] = Field(min_length=1)


class AttemptSpec(BaseModel):
    """One source-produced attempt plus metadata retained in strike.attempts."""

    turns: list[AttemptTurn] = Field(min_length=1)
    source: Literal["static", "planner"]
    planner_reasoning: str | None = None


class AttemptRecord(BaseModel):
    """Persisted outcome view supplied to an adaptive planner."""

    sequence_number: int
    user_message: str
    target_status: int
    target_reply: str | None
    matched: bool


class AttemptSource(Protocol):
    """Supply one next attempt or signal finite static-source exhaustion."""

    async def next_attempt(self, history: list[AttemptRecord]) -> AttemptSpec | None:
        """Return the next candidate, or None only after a finite source ends."""


class StaticAttemptSource:
    """Replay the current static attempts list unchanged and in file order."""

    def __init__(self, static_attempts: list[StaticAttempt]) -> None:
        self._static_attempts = static_attempts
        self._next_index = 0

    async def next_attempt(self, history: list[AttemptRecord]) -> AttemptSpec | None:
        """Return one configured attempt until the finite list is exhausted."""

        del history
        if self._next_index >= len(self._static_attempts):
            return None
        static_attempt = self._static_attempts[self._next_index]
        self._next_index += 1
        return AttemptSpec(turns=static_attempt.turns, source="static")


class PlannerAttemptSource:
    """Use the attacker's own Ollama reasoning to produce one user turn."""

    def __init__(self, planner: AttackerPlanner, objective: str) -> None:
        self._planner = planner
        self._objective = objective

    async def next_attempt(self, history: list[AttemptRecord]) -> AttemptSpec:
        """Generate one new planner attempt; planner sources never exhaust."""

        planner_attempt = await self._planner.generate_next_attempt(
            self._objective, history
        )
        return AttemptSpec(
            turns=[AttemptTurn(role="user", content=planner_attempt.user_message)],
            source="planner",
            planner_reasoning=planner_attempt.reasoning,
        )


@dataclass(frozen=True)
class RoundCandidateOutcome:
    """One generated candidate's prune or target outcome for runner persistence."""

    planner_attempt: PlannerAttempt
    pruned: bool
    prune_reason: Literal["off_topic", "below_top_w_cutoff"] | None
    prune_score: float
    target_status: int | None
    target_error: str | None
    target_reply: str | None
    matched: bool
    gate_request_id: uuid.UUID | None


@dataclass(frozen=True)
class RoundResult:
    """All resolved outcomes from one branching round and its query cost."""

    outcomes: list[RoundCandidateOutcome]
    queries_consumed: int
    match_outcome: RoundCandidateOutcome | None


class BranchingAttemptSource:
    """Generate, score, prune, and query a bounded beam of candidate attempts."""

    def __init__(
        self,
        planner: AttackerPlanner,
        prune_gate: PruneGate,
        objective: str,
        branching_factor: int,
        beam_width: int,
        success_regex: re.Pattern[str],
        normalize_reply: Callable[[str], str],
    ) -> None:
        if branching_factor <= 0:
            raise ValueError("branching_factor must be greater than zero")
        if beam_width <= 0:
            raise ValueError("beam_width must be greater than zero")
        self._planner = planner
        self._prune_gate = prune_gate
        self._objective = objective
        self._branching_factor = branching_factor
        self._beam_width = beam_width
        self._success_regex = success_regex
        self._normalize_reply = normalize_reply

    @staticmethod
    def _parse_gate_request_id(response_body: object) -> uuid.UUID | None:
        if not isinstance(response_body, dict):
            return None
        raw_request_id = response_body.get("gate_request_id")
        if not isinstance(raw_request_id, str):
            return None
        try:
            return uuid.UUID(raw_request_id)
        except ValueError:
            return None

    async def run_round(
        self,
        round_number: int,
        history: list[AttemptRecord],
        target_url: str,
        http_client: httpx.AsyncClient,
        queries_remaining: int,
    ) -> RoundResult:
        """Run one generate-evaluate-query round without querying pruned candidates."""

        if queries_remaining <= 0:
            return RoundResult(outcomes=[], queries_consumed=0, match_outcome=None)

        batch = await self._planner.generate_candidate_batch(
            self._objective, history, self._branching_factor
        )
        evaluation = await self._prune_gate.evaluate(self._objective, batch.candidates)

        indexed = list(enumerate(zip(batch.candidates, evaluation.evaluations)))
        survivor_indexes = {
            index
            for index, (_, candidate_evaluation) in sorted(
                (
                    pair for pair in indexed if pair[1][1].on_topic
                ),
                key=lambda pair: pair[1][1].score,
                reverse=True,
            )[: self._beam_width]
        }
        outcomes: list[RoundCandidateOutcome | None] = [None] * len(batch.candidates)
        for index, (candidate, candidate_evaluation) in indexed:
            if not candidate_evaluation.on_topic:
                outcomes[index] = RoundCandidateOutcome(
                    planner_attempt=candidate,
                    pruned=True,
                    prune_reason="off_topic",
                    prune_score=candidate_evaluation.score,
                    target_status=None,
                    target_error=None,
                    target_reply=None,
                    matched=False,
                    gate_request_id=None,
                )
            elif index not in survivor_indexes:
                outcomes[index] = RoundCandidateOutcome(
                    planner_attempt=candidate,
                    pruned=True,
                    prune_reason="below_top_w_cutoff",
                    prune_score=candidate_evaluation.score,
                    target_status=None,
                    target_error=None,
                    target_reply=None,
                    matched=False,
                    gate_request_id=None,
                )

        queries_consumed = 0
        match_outcome: RoundCandidateOutcome | None = None
        for index, (candidate, candidate_evaluation) in sorted(
            (
                pair for pair in indexed if pair[0] in survivor_indexes
            ),
            key=lambda pair: pair[1][1].score,
            reverse=True,
        ):
            if queries_consumed >= queries_remaining:
                # The runner will begin no further round when the campaign hits
                # its hard query limit. These generated-but-unqueried survivors
                # have no permitted prune reason, so are not persisted as attempts.
                break
            try:
                response = await http_client.post(
                    target_url,
                    json={
                        "messages": [
                            {"role": "user", "content": candidate.user_message}
                        ]
                    },
                )
            except httpx.HTTPError as exc:
                queries_consumed += 1
                outcomes[index] = RoundCandidateOutcome(
                    planner_attempt=candidate,
                    pruned=False,
                    prune_reason=None,
                    prune_score=candidate_evaluation.score,
                    target_status=0,
                    target_error=f"{type(exc).__name__}: {exc}",
                    target_reply=None,
                    matched=False,
                    gate_request_id=None,
                )
                continue

            queries_consumed += 1
            try:
                response_body: object = response.json()
            except ValueError:
                response_body = response.text
            reply = response_body.get("reply") if isinstance(response_body, dict) else None
            target_reply = reply if isinstance(reply, str) else None
            normalized = (
                self._normalize_reply(target_reply)
                if target_reply is not None
                else None
            )
            matched = (
                isinstance(normalized, str)
                and self._success_regex.search(normalized) is not None
            )
            outcome = RoundCandidateOutcome(
                planner_attempt=candidate,
                pruned=False,
                prune_reason=None,
                prune_score=candidate_evaluation.score,
                target_status=response.status_code,
                target_error=None,
                target_reply=target_reply if response.status_code == 200 else None,
                matched=matched,
                gate_request_id=self._parse_gate_request_id(response_body),
            )
            outcomes[index] = outcome
            if matched:
                match_outcome = outcome
                break

        return RoundResult(
            outcomes=[outcome for outcome in outcomes if outcome is not None],
            queries_consumed=queries_consumed,
            match_outcome=match_outcome,
        )
