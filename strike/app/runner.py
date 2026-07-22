"""Safety-limited execution shared by static and adaptive Strike campaigns."""

import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
import sqlalchemy as sa
import yaml
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from .config import ALLOWED_TARGETS, settings
from .attempt_sources import (
    AttemptRecord,
    AttemptSource,
    BranchingAttemptSource,
    PlannerAttemptSource,
    RoundCandidateOutcome,
    StaticAttempt,
    StaticAttemptSource,
)
from .database import (
    attempts,
    campaigns,
    findings,
    new_attempt_id,
    new_campaign_id,
    new_finding_id,
)
from strike.planner.attacker import AttackerPlanner, PlannerGenerationError


class AttemptsFile(BaseModel):
    """Campaign metadata plus either a static list or an adaptive source."""

    objective: str
    owasp_id: str
    success_pattern: str
    success_normalization: Literal["none", "strip_separators"] = "none"
    attempt_source: Literal["static", "planner", "branching"] = "static"
    attempts: list[StaticAttempt] | None = None
    branching_factor: int | None = None
    beam_width: int | None = None

    @model_validator(mode="after")
    def validate_source_configuration(self) -> "AttemptsFile":
        """Reject ambiguous or incomplete attempt-source declarations early."""

        if self.attempt_source in {"planner", "branching"} and self.attempts is not None:
            raise ValueError(
                f"{self.attempt_source} attempt_source must not define an attempts list"
            )
        if self.attempt_source == "static" and not self.attempts:
            raise ValueError("static attempt_source requires a non-empty attempts list")
        if self.attempt_source == "branching":
            if self.branching_factor is None or self.branching_factor <= 0:
                raise ValueError("branching attempt_source requires branching_factor > 0")
            if self.beam_width is None or self.beam_width <= 0:
                raise ValueError("branching attempt_source requires beam_width > 0")
        return self


@dataclass(frozen=True)
class CampaignOutcome:
    """Final persisted state returned to the CLI after execution."""

    campaign_id: uuid.UUID
    status: str
    queries_used: int
    elapsed_seconds: float


def load_attempts(path: Path) -> AttemptsFile:
    """Load the reviewed static attempt contract from YAML."""

    with path.open(encoding="utf-8") as attempts_file:
        return AttemptsFile.model_validate(yaml.safe_load(attempts_file))


def utc_now() -> datetime:
    """Return a timezone-aware timestamp for a terminal campaign update."""

    return datetime.now(timezone.utc)


def normalize_success_reply(reply: str, normalization: str) -> str:
    """Apply the attempts file's narrowly defined success-match normalization."""

    if normalization == "none":
        return reply
    if normalization == "strip_separators":
        return re.sub(r"[ \t\n\r\-_.]", "", reply)
    raise ValueError(f"unsupported success normalization: {normalization}")


def create_attempt_source(
    attempts_file: AttemptsFile, success_regex: re.Pattern[str]
) -> AttemptSource | BranchingAttemptSource:
    """Choose the source while retaining one shared campaign execution loop."""

    if attempts_file.attempt_source == "static":
        return StaticAttemptSource(attempts_file.attempts or [])
    planner = AttackerPlanner(
        ollama_base_url=settings.ollama_base_url,
        model="llama3.1:8b",
        request_timeout_seconds=settings.request_timeout_seconds,
    )
    if attempts_file.attempt_source == "planner":
        return PlannerAttemptSource(planner, attempts_file.objective)

    from strike.planner.prune_gate import PruneGate

    return BranchingAttemptSource(
        planner=planner,
        prune_gate=PruneGate(
            ollama_base_url=settings.ollama_base_url,
            model="llama3.1:8b",
            request_timeout_seconds=settings.request_timeout_seconds,
        ),
        objective=attempts_file.objective,
        branching_factor=attempts_file.branching_factor or 0,
        beam_width=attempts_file.beam_width or 0,
        success_regex=success_regex,
        normalize_reply=lambda reply: normalize_success_reply(
            reply, attempts_file.success_normalization
        ),
    )


async def update_campaign(
    connection: AsyncConnection,
    campaign_id: uuid.UUID,
    **values: object,
) -> None:
    """Persist an immediate campaign-state transition."""

    await connection.execute(
        sa.update(campaigns).where(campaigns.c.id == campaign_id).values(**values)
    )
    await connection.commit()


def parse_gate_request_id(response_body: object) -> uuid.UUID | None:
    """Accept only a valid optional Gate request identifier from the target."""

    if not isinstance(response_body, dict):
        return None
    raw_request_id = response_body.get("gate_request_id")
    if not isinstance(raw_request_id, str):
        return None
    try:
        return uuid.UUID(raw_request_id)
    except ValueError:
        return None


async def persist_attempt(
    connection: AsyncConnection,
    *,
    campaign_id: uuid.UUID,
    sequence_number: int,
    attack_turns: list[dict[str, str]],
    source: str,
    planner_reasoning: str | None,
    target_status: int | None,
    target_error: str | None,
    target_reply: str | None,
    matched: bool,
    gate_request_id: uuid.UUID | None,
    round_number: int,
    pruned: bool,
    prune_reason: str | None,
    prune_score: float | None,
) -> None:
    """Persist one executed attempt before campaign execution continues."""

    await connection.execute(
        sa.insert(attempts).values(
            id=new_attempt_id(),
            campaign_id=campaign_id,
            sequence_number=sequence_number,
            source=source,
            planner_reasoning=planner_reasoning,
            attack_turns=attack_turns,
            target_status=target_status,
            target_error=target_error,
            target_reply=target_reply,
            matched=matched,
            gate_request_id=gate_request_id,
            round_number=round_number,
            pruned=pruned,
            prune_reason=prune_reason,
            prune_score=prune_score,
        )
    )


async def run_campaign(
    target_key: str,
    attempts_path: Path,
    max_queries: int,
    max_wall_clock_seconds: int,
) -> CampaignOutcome:
    """Run a bounded static campaign against one reviewed allowlisted target."""

    # This must remain the first operation: no YAML, database, or network work
    # happens until the target key is proven to be in the reviewed allowlist.
    target_url = ALLOWED_TARGETS.get(target_key)
    if target_url is None:
        raise ValueError(
            f"target {target_key!r} is not allowlisted; permitted targets: "
            + ", ".join(ALLOWED_TARGETS)
        )

    if max_queries <= 0:
        raise ValueError("max_queries must be greater than zero")
    if max_wall_clock_seconds <= 0:
        raise ValueError("max_wall_clock_seconds must be greater than zero")

    attempts_file = load_attempts(attempts_path)
    success_regex = re.compile(attempts_file.success_pattern)
    attempt_source = create_attempt_source(attempts_file, success_regex)
    campaign_id = new_campaign_id()
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    start_monotonic = time.monotonic()
    queries_used = 0
    final_status = "error"
    terminal_written = False
    history: list[AttemptRecord] = []
    sequence_number = 0
    round_number = 0

    print(
        "campaign_start"
        f" campaign_id={campaign_id} target={target_key}"
        f" objective={attempts_file.objective!r} max_queries={max_queries}"
        f" max_wall_clock_seconds={max_wall_clock_seconds}"
    )

    try:
        async with engine.connect() as connection:
            # This is the campaign's first database write.
            await connection.execute(
                sa.insert(campaigns).values(
                    id=campaign_id,
                    objective=attempts_file.objective,
                    owasp_id=attempts_file.owasp_id,
                    target_key=target_key,
                    status="running",
                    max_queries=max_queries,
                    queries_used=0,
                    max_wall_clock_seconds=max_wall_clock_seconds,
                )
            )
            await connection.commit()

            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds
            ) as client:
                while True:
                    if queries_used >= max_queries:
                        final_status = "query_limit_reached"
                        break
                    if time.monotonic() - start_monotonic >= max_wall_clock_seconds:
                        final_status = "timed_out"
                        break

                    if isinstance(attempt_source, BranchingAttemptSource):
                        round_number += 1
                        try:
                            round_result = await attempt_source.run_round(
                                round_number=round_number,
                                history=history,
                                target_url=target_url,
                                http_client=client,
                                queries_remaining=max_queries - queries_used,
                            )
                        except PlannerGenerationError as exc:
                            final_status = "error"
                            print(
                                "campaign_planner_error"
                                f" campaign_id={campaign_id} error={exc!s}"
                            )
                            break

                        for outcome in round_result.outcomes:
                            sequence_number += 1
                            if outcome.target_status is not None:
                                queries_used += 1
                                await update_campaign(
                                    connection, campaign_id, queries_used=queries_used
                                )
                            turns = [
                                {
                                    "role": "user",
                                    "content": outcome.planner_attempt.user_message,
                                }
                            ]
                            await persist_attempt(
                                connection,
                                campaign_id=campaign_id,
                                sequence_number=sequence_number,
                                attack_turns=turns,
                                source="planner",
                                planner_reasoning=outcome.planner_attempt.reasoning,
                                target_status=outcome.target_status,
                                target_error=outcome.target_error,
                                target_reply=outcome.target_reply,
                                matched=outcome.matched,
                                gate_request_id=outcome.gate_request_id,
                                round_number=round_number,
                                pruned=outcome.pruned,
                                prune_reason=outcome.prune_reason,
                                prune_score=outcome.prune_score,
                            )
                            await connection.commit()
                            if outcome.target_status is not None:
                                history.append(
                                    AttemptRecord(
                                        sequence_number=sequence_number,
                                        user_message=outcome.planner_attempt.user_message,
                                        target_status=outcome.target_status,
                                        target_reply=outcome.target_reply,
                                        matched=outcome.matched,
                                    )
                                )
                            print(
                                "campaign_branch_candidate"
                                f" campaign_id={campaign_id} round={round_number}"
                                f" index={sequence_number} pruned={str(outcome.pruned).lower()}"
                                f" prune_reason={outcome.prune_reason}"
                                f" prune_score={outcome.prune_score}"
                                f" target_status={outcome.target_status}"
                                f" match={str(outcome.matched).lower()}"
                            )

                        if round_result.match_outcome is not None:
                            matched_outcome = round_result.match_outcome
                            await connection.execute(
                                sa.insert(findings).values(
                                    id=new_finding_id(),
                                    campaign_id=campaign_id,
                                    owasp_id=attempts_file.owasp_id,
                                    attack_turns=[
                                        {
                                            "role": "user",
                                            "content": matched_outcome.planner_attempt.user_message,
                                        }
                                    ],
                                    target_reply=matched_outcome.target_reply,
                                    matched_pattern=attempts_file.success_pattern,
                                    gate_request_id=matched_outcome.gate_request_id,
                                )
                            )
                            await connection.commit()
                            final_status = "bypass_found"
                            await update_campaign(
                                connection,
                                campaign_id,
                                status=final_status,
                                ended_at=utc_now(),
                            )
                            terminal_written = True
                            break
                        continue

                    try:
                        attempt_spec = await attempt_source.next_attempt(history)
                    except PlannerGenerationError as exc:
                        final_status = "error"
                        print(
                            "campaign_planner_error"
                            f" campaign_id={campaign_id} error={exc!s}"
                        )
                        break

                    if attempt_spec is None:
                        final_status = "completed_no_bypass"
                        break

                    sequence_number += 1
                    round_number += 1
                    turns = [turn.model_dump() for turn in attempt_spec.turns]
                    try:
                        response = await client.post(target_url, json={"messages": turns})
                    except httpx.HTTPError as exc:
                        queries_used += 1
                        await update_campaign(
                            connection, campaign_id, queries_used=queries_used
                        )
                        # No target response was received: 0 is the no-response
                        # sentinel, with the network failure retained separately.
                        await persist_attempt(
                            connection,
                            campaign_id=campaign_id,
                            sequence_number=sequence_number,
                            attack_turns=turns,
                            source=attempt_spec.source,
                            planner_reasoning=attempt_spec.planner_reasoning,
                            target_status=0,
                            target_error=f"{type(exc).__name__}: {exc}",
                            target_reply=None,
                            matched=False,
                            gate_request_id=None,
                            round_number=round_number,
                            pruned=False,
                            prune_reason=None,
                            prune_score=None,
                        )
                        await connection.commit()
                        history.append(
                            AttemptRecord(
                                sequence_number=sequence_number,
                                user_message=attempt_spec.turns[-1].content,
                                target_status=0,
                                target_reply=None,
                                matched=False,
                            )
                        )
                        print(
                            "campaign_attempt"
                            f" campaign_id={campaign_id} index={sequence_number}"
                            f" target_status=network_error match=false error={exc!s}"
                        )
                        continue

                    queries_used += 1
                    # Persist this count immediately after every attempted call.
                    await update_campaign(
                        connection, campaign_id, queries_used=queries_used
                    )

                    try:
                        response_body: object = response.json()
                    except ValueError:
                        response_body = response.text

                    reply = (
                        response_body.get("reply")
                        if isinstance(response_body, dict)
                        else None
                    )
                    target_reply = reply if isinstance(reply, str) else None
                    match_candidate = (
                        normalize_success_reply(
                            target_reply, attempts_file.success_normalization
                        )
                        if target_reply is not None
                        else None
                    )
                    matched = (
                        isinstance(match_candidate, str)
                        and success_regex.search(match_candidate) is not None
                    )
                    gate_request_id = parse_gate_request_id(response_body)

                    await persist_attempt(
                        connection,
                        campaign_id=campaign_id,
                        sequence_number=sequence_number,
                        attack_turns=turns,
                        source=attempt_spec.source,
                        planner_reasoning=attempt_spec.planner_reasoning,
                        target_status=response.status_code,
                        target_error=None,
                        target_reply=target_reply if response.status_code == 200 else None,
                        matched=matched,
                        gate_request_id=gate_request_id,
                        round_number=round_number,
                        pruned=False,
                        prune_reason=None,
                        prune_score=None,
                    )

                    if response.status_code != 200:
                        await connection.commit()
                        history.append(
                            AttemptRecord(
                                sequence_number=sequence_number,
                                user_message=attempt_spec.turns[-1].content,
                                target_status=response.status_code,
                                target_reply=None,
                                matched=False,
                            )
                        )
                        print(
                            "campaign_attempt"
                            f" campaign_id={campaign_id} index={sequence_number}"
                            f" target_status={response.status_code} match=false"
                            f" response={response_body!r}"
                        )
                        continue

                    print(
                        "campaign_attempt"
                        f" campaign_id={campaign_id} index={sequence_number}"
                        f" target_status={response.status_code} match={str(matched).lower()}"
                        f" reply={reply!r}"
                    )
                    if not matched:
                        await connection.commit()
                        history.append(
                            AttemptRecord(
                                sequence_number=sequence_number,
                                user_message=attempt_spec.turns[-1].content,
                                target_status=response.status_code,
                                target_reply=target_reply,
                                matched=False,
                            )
                        )
                        continue

                    await connection.execute(
                        sa.insert(findings).values(
                            id=new_finding_id(),
                            campaign_id=campaign_id,
                            owasp_id=attempts_file.owasp_id,
                            attack_turns=turns,
                            target_reply=reply,
                            matched_pattern=attempts_file.success_pattern,
                            gate_request_id=parse_gate_request_id(response_body),
                        )
                    )
                    await connection.commit()
                    final_status = "bypass_found"
                    await update_campaign(
                        connection,
                        campaign_id,
                        status=final_status,
                        ended_at=utc_now(),
                    )
                    terminal_written = True
                    break

            if not terminal_written:
                await update_campaign(
                    connection,
                    campaign_id,
                    status=final_status,
                    ended_at=utc_now(),
                )
                terminal_written = True
    except Exception:
        if not terminal_written:
            async with engine.connect() as connection:
                await update_campaign(
                    connection,
                    campaign_id,
                    status="error",
                    ended_at=utc_now(),
                )
        raise
    finally:
        await engine.dispose()

    elapsed_seconds = time.monotonic() - start_monotonic
    print(
        "campaign_end"
        f" campaign_id={campaign_id} status={final_status}"
        f" queries_used={queries_used} elapsed_seconds={elapsed_seconds:.3f}"
    )
    return CampaignOutcome(campaign_id, final_status, queries_used, elapsed_seconds)
