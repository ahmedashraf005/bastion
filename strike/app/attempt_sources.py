"""Pluggable static and planner-backed sources for one campaign attempt at a time."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, Field

from strike.planner.attacker import AttackerPlanner


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
