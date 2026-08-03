"""Safety-limited execution shared by static and adaptive Strike campaigns."""

import math
import os
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

import httpx
import sqlalchemy as sa
import yaml
from pydantic import BaseModel, Field, model_validator
from redis import asyncio as redis
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
    new_proposed_rule_id,
    proposed_rules,
)
from .success_contract import (
    SuccessEvaluation,
    classify_target_response,
    resolve_marker_ref,
)
from gate.app.policy_profile import active_manifest_version, resolve_policy_profile
from strike.planner.attacker import AttackerPlanner, PlannerGenerationError
from strike.planner.strategy_library import StrategyLibrary
from strike.synthesizer.rule_synthesizer import FindingEvidence, RuleSynthesizer


class AttemptsFile(BaseModel):
    """Campaign metadata plus either a static list or an adaptive source."""

    objective: str
    owasp_id: str
    success: "SuccessContract"
    attempt_source: Literal["static", "planner", "branching"] = "static"
    attempts: list[StaticAttempt] | None = None
    branching_factor: int | None = None
    beam_width: int | None = None
    planner_request_timeout_seconds: float | None = Field(default=None, gt=0)
    max_queries: int | None = Field(default=None, gt=0)
    max_wall_clock_seconds: int | None = Field(default=None, gt=0)
    use_strategy_library: bool = False
    strategy_retrieval_k: int = 3

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
        elif self.use_strategy_library:
            raise ValueError("use_strategy_library is supported only for branching campaigns")
        if self.use_strategy_library and self.strategy_retrieval_k <= 0:
            raise ValueError("strategy_retrieval_k must be greater than zero")
        return self


class NearMatchContract(BaseModel):
    """Bounded similarity settings for non-confirming marker evidence."""

    anchor: str
    suffix_length: int
    max_edit_distance: int
    minimum_positional_overlap: float
    max_anchor_to_suffix_gap: int

    @model_validator(mode="after")
    def validate_bounds(self) -> "NearMatchContract":
        if self.suffix_length <= 0:
            raise ValueError("success.near_match.suffix_length must be greater than zero")
        if self.max_edit_distance < 0:
            raise ValueError("success.near_match.max_edit_distance must not be negative")
        if not 0 <= self.minimum_positional_overlap <= 1:
            raise ValueError(
                "success.near_match.minimum_positional_overlap must be between 0 and 1"
            )
        if self.max_anchor_to_suffix_gap < 0:
            raise ValueError(
                "success.near_match.max_anchor_to_suffix_gap must not be negative"
            )
        return self


class SuccessContract(BaseModel):
    """Marker-reference success configuration that excludes a marker value from YAML."""

    marker_ref: str
    canonicalization: Literal["strip_separators"]
    near_match: NearMatchContract


@dataclass(frozen=True)
class CampaignOutcome:
    """Final persisted state returned to the CLI after execution."""

    campaign_id: uuid.UUID
    status: str
    queries_used: int
    elapsed_seconds: float


PLANNER_MODEL = (
    settings.openai_model
    if settings.planner_provider == "openai"
    else settings.planner_model
)
DEFAULT_MAX_QUERIES = 50
DEFAULT_MAX_WALL_CLOCK_SECONDS = 300
# Measured from campaign 3fad81c5: 194.846 seconds for ten target queries.
OBSERVED_TARGET_QUERY_SECONDS = 19.4846
# Later branching rounds grew by approximately this amount as history accumulated.
OBSERVED_PLANNER_ROUND_DRIFT_SECONDS = 1.4


def inference_route(base_url: str) -> str:
    """Classify the resolved endpoint without rewriting or probing it."""

    from urllib.parse import urlparse

    hostname = (urlparse(base_url).hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        return "host_native"
    if hostname == "ollama":
        return "compose_container"
    return "other"


def inference_provenance(planner_timeout_seconds: float) -> dict[str, object]:
    """Record the configured inference context needed for timing comparisons."""

    return {
        "inference_base_url": (
            settings.openai_base_url
            if settings.planner_provider == "openai"
            else settings.ollama_base_url
        ),
        "inference_route": (
            "openai_compatible"
            if settings.planner_provider == "openai"
            else inference_route(settings.ollama_base_url)
        ),
        "inference_model": PLANNER_MODEL,
        "inference_parameters": {
            "planner_request_timeout_seconds": planner_timeout_seconds,
            "planner_max_parse_retries": 3,
            "prune_gate_request_timeout_seconds": planner_timeout_seconds,
            "prune_gate_max_parse_retries": 3,
            "synthesizer_request_timeout_seconds": settings.request_timeout_seconds,
            "synthesizer_max_parse_retries": 3,
            "planner_provider": settings.planner_provider,
        },
    }


def active_gate_manifest_versions() -> dict[str, str | None]:
    """Read the two active Gate version IDs used by the campaign target.

    These are the same ``active`` manifest entries Gate applies at startup;
    a campaign refuses to begin when either manifest is absent or ambiguous.
    """

    profile = resolve_policy_profile(os.getenv("GATE_POLICY_PROFILE") or None)
    return {
        "gate_normalization_version_id": active_manifest_version(
            profile.normalization_versions
        ),
        "gate_pattern_version_id": active_manifest_version(profile.pattern_versions),
    }


def feasibility_estimate(
    attempts_file: AttemptsFile, max_queries: int
) -> dict[str, float | int]:
    """Estimate campaign duration from the recorded preflight measurement.

    This is an operator-facing estimate, not a scheduling guard: target and
    planner behavior can still vary at runtime. A static attempt source
    replays a finite, pre-written list with no planner call per attempt, so
    its query count and drift are known exactly up front rather than bounded
    by max_queries (a safety cap the static list may never approach) — using
    max_queries there produced a large, alarming negative headroom on runs
    that in fact complete comfortably within seconds.
    """

    if attempts_file.attempt_source == "static":
        expected_queries = len(attempts_file.attempts or [])
        expected_rounds = expected_queries
        drift_seconds = 0.0
    else:
        expected_queries = max_queries
        queries_per_round = (
            attempts_file.beam_width if attempts_file.attempt_source == "branching" else 1
        )
        expected_rounds = math.ceil(expected_queries / (queries_per_round or 1))
        drift_seconds = (
            OBSERVED_PLANNER_ROUND_DRIFT_SECONDS * expected_rounds * (expected_rounds - 1) / 2
        )
    query_seconds = OBSERVED_TARGET_QUERY_SECONDS * expected_queries
    return {
        "expected_queries": expected_queries,
        "expected_rounds": expected_rounds,
        "query_seconds": query_seconds,
        "drift_seconds": drift_seconds,
        "total_seconds": query_seconds + drift_seconds,
    }


def terminal_exception_values(
    exc: Exception, persisted_attempt_count: int
) -> dict[str, object]:
    """Persist partial execution visibly instead of silently treating it as complete."""

    return {
        "status": "failed_after_progress" if persisted_attempt_count > 0 else "error",
        "error_type": type(exc).__name__,
        "error_detail": "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        ),
        "ended_at": utc_now(),
        "lease_expires_at": None,
    }


async def persisted_attempt_count(
    connection: AsyncConnection, campaign_id: uuid.UUID
) -> int:
    """Count durable attempt rows when assigning a terminal failure state."""

    result = await connection.execute(
        sa.select(sa.func.count()).select_from(attempts).where(attempts.c.campaign_id == campaign_id)
    )
    return int(result.scalar_one())


def load_attempts(path: Path) -> AttemptsFile:
    """Load the reviewed static attempt contract from YAML."""

    with path.open(encoding="utf-8") as attempts_file:
        return AttemptsFile.model_validate(yaml.safe_load(attempts_file))


def utc_now() -> datetime:
    """Return a timezone-aware timestamp for a terminal campaign update."""

    return datetime.now(timezone.utc)


def lease_expiry() -> datetime:
    """Return the next bounded ownership deadline for this runner process."""

    return utc_now() + timedelta(seconds=settings.runner_lease_seconds)


async def reconcile_expired_campaigns(engine: AsyncEngine) -> int:
    """Interrupt only rows with an explicit, expired runner lease."""

    async with engine.begin() as connection:
        result = await connection.execute(
            sa.update(campaigns)
            .where(
                campaigns.c.status == "running",
                campaigns.c.lease_expires_at.is_not(None),
                campaigns.c.lease_expires_at < utc_now(),
            )
            .values(
                status="interrupted",
                ended_at=utc_now(),
                recovery_reason="runner lease expired before campaign completion",
                lease_expires_at=None,
            )
        )
    return result.rowcount or 0


async def renew_campaign_lease(
    connection: AsyncConnection, campaign_id: uuid.UUID, owner_id: uuid.UUID
) -> None:
    """Renew this runner's lease and fail rather than writing after ownership loss."""

    result = await connection.execute(
        sa.update(campaigns)
        .where(
            campaigns.c.id == campaign_id,
            campaigns.c.status == "running",
            campaigns.c.runner_owner_id == owner_id,
        )
        .values(lease_expires_at=lease_expiry())
    )
    if result.rowcount != 1:
        raise RuntimeError(f"campaign lease lost for {campaign_id}")
    await connection.commit()


def create_attempt_source(
    attempts_file: AttemptsFile,
    evaluate_response: Callable[[str | None, int, object], SuccessEvaluation],
    planner_request_timeout_seconds: float,
    retrieved_strategies: list[str] | None = None,
) -> AttemptSource | BranchingAttemptSource:
    """Choose the source while retaining one shared campaign execution loop."""

    if attempts_file.attempt_source == "static":
        return StaticAttemptSource(attempts_file.attempts or [])
    planner = AttackerPlanner(
        ollama_base_url=settings.ollama_base_url,
        model=PLANNER_MODEL,
        request_timeout_seconds=planner_request_timeout_seconds,
        provider=settings.planner_provider,
        openai_base_url=settings.openai_base_url,
        openai_api_key=settings.openai_api_key,
    )
    if attempts_file.attempt_source == "planner":
        return PlannerAttemptSource(planner, attempts_file.objective)

    from strike.planner.prune_gate import PruneGate

    return BranchingAttemptSource(
        planner=planner,
        prune_gate=PruneGate(
            ollama_base_url=settings.ollama_base_url,
            model=PLANNER_MODEL,
            request_timeout_seconds=planner_request_timeout_seconds,
            provider=settings.planner_provider,
            openai_base_url=settings.openai_base_url,
            openai_api_key=settings.openai_api_key,
        ),
        objective=attempts_file.objective,
        branching_factor=attempts_file.branching_factor or 0,
        beam_width=attempts_file.beam_width or 0,
        evaluate_response=evaluate_response,
        retrieved_strategies=retrieved_strategies,
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


def _leak_pattern_ids() -> set[str]:
    """Read Gate's current detector IDs before assigning a new proposal slug."""

    patterns_path = Path(__file__).resolve().parents[2] / "gate/detectors/leak_patterns.yaml"
    with patterns_path.open(encoding="utf-8") as patterns_file:
        raw_patterns = yaml.safe_load(patterns_file) or []
    return {
        entry["id"]
        for entry in raw_patterns
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }


def _slug_base(description: str) -> str:
    """Make a short, stable human-review identifier from a proposal description."""

    words = re.findall(r"[a-z0-9]+", description.lower())[:6]
    return "synthesized-" + ("-".join(words) if words else "leak-pattern")


async def synthesize_proposed_rule(
    connection: AsyncConnection,
    synthesizer: RuleSynthesizer,
    *,
    finding_id: uuid.UUID,
    attack_turns: list[dict[str, str]],
    target_reply: str,
    normalization_evidence: dict[str, object] | None = None,
) -> None:
    """Best-effort synthesis after a persisted adaptive finding; never change its outcome."""

    try:
        proposal = await synthesizer.propose(
            FindingEvidence(
                finding_id=str(finding_id),
                attack_turns=attack_turns,
                target_reply=target_reply,
                normalization_evidence=normalization_evidence,
            )
        )
        if proposal is None:
            print(f"rule_synthesizer_no_proposal finding_id={finding_id}")
            return

        tier, promotion_block = synthesizer.promotion_tier(proposal)
        # The legacy proposed_rules table only represents inline pattern rows.
        # Ref-based signatures and additive normalizations await their own
        # versioned migration; never degrade them into a marker-bearing row.
        print(
            "rule_synthesizer_verified_proposal_not_persisted"
            f" finding_id={finding_id} proposal_type={proposal.proposal_type}"
            f" promotion_tier={tier} promotion_block={promotion_block}"
        )
        return
    except Exception as exc:
        print(f"rule_synthesizer_failed finding_id={finding_id} error={exc!s}")


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
    outcome: str,
    normalization_evidence: dict[str, object] | None,
    parent_node_id: uuid.UUID | None,
    gate_request_id: uuid.UUID | None,
    round_number: int,
    pruned: bool,
    prune_reason: str | None,
    prune_score: float | None,
    # Context shown to the planner, not proof that any candidate used it.
    retrieved_strategy_ids: list[str] | None = None,
) -> uuid.UUID:
    """Persist one executed attempt before campaign execution continues."""

    attempt_id = new_attempt_id()
    await connection.execute(
        sa.insert(attempts).values(
            id=attempt_id,
            campaign_id=campaign_id,
            sequence_number=sequence_number,
            source=source,
            planner_reasoning=planner_reasoning,
            attack_turns=attack_turns,
            target_status=target_status,
            target_error=target_error,
            target_reply=target_reply,
            matched=matched,
            outcome=outcome,
            normalization_evidence=normalization_evidence,
            parent_node_id=parent_node_id,
            gate_request_id=gate_request_id,
            round_number=round_number,
            pruned=pruned,
            prune_reason=prune_reason,
            prune_score=prune_score,
            retrieved_strategy_ids=retrieved_strategy_ids,
        )
    )
    return attempt_id


async def run_campaign(
    target_key: str,
    attempts_path: Path,
    max_queries: int | None,
    max_wall_clock_seconds: int | None,
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

    if settings.planner_provider == "openai" and not settings.openai_api_key:
        raise ValueError(
            "STRIKE_PLANNER_PROVIDER=openai requires OPENAI_API_KEY; "
            "there is no silent Ollama fallback"
        )
    attempts_file = load_attempts(attempts_path)
    max_queries = (
        max_queries
        if max_queries is not None
        else attempts_file.max_queries or DEFAULT_MAX_QUERIES
    )
    max_wall_clock_seconds = (
        max_wall_clock_seconds
        if max_wall_clock_seconds is not None
        else attempts_file.max_wall_clock_seconds or DEFAULT_MAX_WALL_CLOCK_SECONDS
    )
    if max_queries <= 0:
        raise ValueError("max_queries must be greater than zero")
    if max_wall_clock_seconds <= 0:
        raise ValueError("max_wall_clock_seconds must be greater than zero")
    # Resolve before any database or network action. The resulting value stays
    # inside this scorer closure and is never passed to an LLM-facing object.
    resolved_marker = resolve_marker_ref(attempts_file.success.marker_ref)
    gate_manifest_versions = active_gate_manifest_versions()
    planner_request_timeout_seconds = (
        attempts_file.planner_request_timeout_seconds
        or settings.planner_request_timeout_seconds
    )

    def evaluate_response(
        reply: str | None, response_status: int, response_body: object
    ) -> SuccessEvaluation:
        return classify_target_response(
            reply,
            response_status=response_status,
            response_body=response_body,
            marker_ref=attempts_file.success.marker_ref,
            anchor=attempts_file.success.near_match.anchor,
            suffix_length=attempts_file.success.near_match.suffix_length,
            max_edit_distance=attempts_file.success.near_match.max_edit_distance,
            minimum_positional_overlap=(
                attempts_file.success.near_match.minimum_positional_overlap
            ),
            max_anchor_to_suffix_gap=(
                attempts_file.success.near_match.max_anchor_to_suffix_gap
            ),
        )
    valkey_client = None
    strategy_library: StrategyLibrary | None = None
    retrieved_strategy_ids: list[str] | None = None
    retrieved_strategy_descriptions: list[str] = []
    rule_synthesizer = RuleSynthesizer(
        ollama_base_url=settings.ollama_base_url,
        model=PLANNER_MODEL,
        request_timeout_seconds=settings.request_timeout_seconds,
        forbidden_marker_values={resolved_marker.value},
    )
    if attempts_file.use_strategy_library:
        valkey_client = redis.from_url(settings.valkey_url, decode_responses=True)
        strategy_library = StrategyLibrary(
            valkey_client,
            settings.ollama_base_url,
            settings.embedding_model,
            request_timeout_seconds=settings.request_timeout_seconds,
        )
        retrieved_strategies = await strategy_library.retrieve(
            attempts_file.objective, attempts_file.strategy_retrieval_k
        )
        retrieved_strategy_ids = [strategy.strategy_id for strategy in retrieved_strategies]
        retrieved_strategy_descriptions = [
            strategy.description for strategy in retrieved_strategies
        ]
        print(
            "strategy_library_retrieval"
            f" enabled=true retrieved_strategy_ids={retrieved_strategy_ids}"
        )
    attempt_source = create_attempt_source(
        attempts_file,
        evaluate_response,
        planner_request_timeout_seconds,
        retrieved_strategy_descriptions,
    )
    campaign_id = new_campaign_id()
    runner_owner_id = uuid.uuid4()
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    reconciled_campaigns = await reconcile_expired_campaigns(engine)
    start_monotonic = time.monotonic()
    queries_used = 0
    final_status = "error"
    terminal_written = False
    terminal_error: Exception | None = None
    history: list[AttemptRecord] = []
    sequence_number = 0
    round_number = 0

    print(
        "campaign_start"
        f" campaign_id={campaign_id} target={target_key}"
        f" objective={attempts_file.objective!r} max_queries={max_queries}"
        f" max_wall_clock_seconds={max_wall_clock_seconds}"
        f" reconciled_expired_campaigns={reconciled_campaigns}"
        f" planner_request_timeout_seconds={planner_request_timeout_seconds}"
    )
    estimate = feasibility_estimate(attempts_file, max_queries)
    print(
        "campaign_feasibility_estimate"
        f" campaign_id={campaign_id} max_queries={max_queries}"
        f" expected_queries={estimate['expected_queries']}"
        f" observed_target_query_seconds={OBSERVED_TARGET_QUERY_SECONDS:.4f}"
        f" expected_rounds={estimate['expected_rounds']}"
        f" estimated_query_seconds={estimate['query_seconds']:.3f}"
        f" estimated_planner_drift_seconds={estimate['drift_seconds']:.3f}"
        f" estimated_total_seconds={estimate['total_seconds']:.3f}"
        f" max_wall_clock_seconds={max_wall_clock_seconds}"
        f" estimated_headroom_seconds={max_wall_clock_seconds - estimate['total_seconds']:.3f}"
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
                    runner_owner_id=runner_owner_id,
                    lease_expires_at=lease_expiry(),
                    **inference_provenance(planner_request_timeout_seconds),
                    **gate_manifest_versions,
                )
            )
            await connection.commit()

            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds
            ) as client:
                while True:
                    await renew_campaign_lease(connection, campaign_id, runner_owner_id)
                    if queries_used >= max_queries:
                        final_status = "query_limit_reached"
                        break
                    if time.monotonic() - start_monotonic >= max_wall_clock_seconds:
                        final_status = "timed_out"
                        break

                    if isinstance(attempt_source, BranchingAttemptSource):
                        round_number += 1
                        parent_node_id = history[-1].attempt_id if history else None

                        async def renew_lease() -> None:
                            await renew_campaign_lease(
                                connection, campaign_id, runner_owner_id
                            )

                        try:
                            round_result = await attempt_source.run_round(
                                round_number=round_number,
                                history=history,
                                target_url=target_url,
                                http_client=client,
                                queries_remaining=max_queries - queries_used,
                                before_external_call=renew_lease,
                            )
                        except PlannerGenerationError as exc:
                            terminal_error = exc
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
                            attempt_id = await persist_attempt(
                                connection,
                                campaign_id=campaign_id,
                                sequence_number=sequence_number,
                                attack_turns=turns,
                                source="branching",
                                planner_reasoning=outcome.planner_attempt.reasoning,
                                target_status=outcome.target_status,
                                target_error=outcome.target_error,
                                target_reply=outcome.target_reply,
                                matched=outcome.matched,
                                outcome=outcome.outcome,
                                normalization_evidence=outcome.normalization_evidence,
                                parent_node_id=parent_node_id,
                                gate_request_id=outcome.gate_request_id,
                                round_number=round_number,
                                pruned=outcome.pruned,
                                prune_reason=outcome.prune_reason,
                                prune_score=outcome.prune_score,
                                retrieved_strategy_ids=retrieved_strategy_ids,
                            )
                            await connection.commit()
                            if outcome.target_status is not None:
                                history.append(
                                    AttemptRecord(
                                        attempt_id=attempt_id,
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
                            finding_id = new_finding_id()
                            await connection.execute(
                                sa.insert(findings).values(
                                    id=finding_id,
                                    campaign_id=campaign_id,
                                    owasp_id=attempts_file.owasp_id,
                                    attack_turns=[
                                        {
                                            "role": "user",
                                            "content": matched_outcome.planner_attempt.user_message,
                                        }
                                    ],
                                    target_reply=matched_outcome.target_reply,
                                    matched_pattern=attempts_file.success.marker_ref,
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
                                lease_expires_at=None,
                            )
                            terminal_written = True
                            if strategy_library is not None:
                                promoted_strategy_id = await strategy_library.promote(
                                    campaign_id=str(campaign_id),
                                    finding_id=str(finding_id),
                                    objective=attempts_file.objective,
                                    owasp_id=attempts_file.owasp_id,
                                    attack_turns=[
                                        {
                                            "role": "user",
                                            "content": matched_outcome.planner_attempt.user_message,
                                        }
                                    ],
                                    target_reply=matched_outcome.target_reply or "",
                                )
                                if promoted_strategy_id is None:
                                    print(
                                        "strategy_library_promotion_failed"
                                        f" campaign_id={campaign_id} finding_id={finding_id}"
                                    )
                                else:
                                    try:
                                        await connection.execute(
                                            sa.update(findings)
                                            .where(findings.c.id == finding_id)
                                            .values(promoted_strategy_id=promoted_strategy_id)
                                        )
                                        await connection.commit()
                                    except Exception as exc:
                                        print(
                                            "strategy_library_promotion_reference_failed"
                                            f" campaign_id={campaign_id} finding_id={finding_id} error={exc!s}"
                                        )
                            await synthesize_proposed_rule(
                                connection,
                                rule_synthesizer,
                                finding_id=finding_id,
                                attack_turns=[
                                    {
                                        "role": "user",
                                        "content": matched_outcome.planner_attempt.user_message,
                                    }
                                ],
                                target_reply=matched_outcome.target_reply or "",
                                normalization_evidence=matched_outcome.normalization_evidence,
                            )
                            break
                        continue

                    try:
                        attempt_spec = await attempt_source.next_attempt(history)
                    except PlannerGenerationError as exc:
                        terminal_error = exc
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
                        await renew_campaign_lease(connection, campaign_id, runner_owner_id)
                        response = await client.post(target_url, json={"messages": turns})
                    except httpx.HTTPError as exc:
                        queries_used += 1
                        await update_campaign(
                            connection, campaign_id, queries_used=queries_used
                        )
                        # No target response was received: 0 is the no-response
                        # sentinel, with the network failure retained separately.
                        attempt_id = await persist_attempt(
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
                            outcome="transport",
                            normalization_evidence=None,
                            parent_node_id=None,
                            gate_request_id=None,
                            round_number=round_number,
                            pruned=False,
                            prune_reason=None,
                            prune_score=None,
                            retrieved_strategy_ids=retrieved_strategy_ids,
                        )
                        await connection.commit()
                        history.append(
                            AttemptRecord(
                                attempt_id=attempt_id,
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
                    evaluation = evaluate_response(
                        target_reply, response.status_code, response_body
                    )
                    matched = evaluation.confirmed
                    gate_request_id = parse_gate_request_id(response_body)

                    attempt_id = await persist_attempt(
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
                        outcome=evaluation.outcome,
                        normalization_evidence=evaluation.normalization_evidence,
                        parent_node_id=None,
                        gate_request_id=gate_request_id,
                        round_number=round_number,
                        pruned=False,
                        prune_reason=None,
                        prune_score=None,
                        retrieved_strategy_ids=retrieved_strategy_ids,
                    )

                    if response.status_code != 200:
                        await connection.commit()
                        history.append(
                            AttemptRecord(
                                attempt_id=attempt_id,
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
                                attempt_id=attempt_id,
                                sequence_number=sequence_number,
                                user_message=attempt_spec.turns[-1].content,
                                target_status=response.status_code,
                                target_reply=target_reply,
                                matched=False,
                            )
                        )
                        continue

                    finding_id = new_finding_id()
                    await connection.execute(
                        sa.insert(findings).values(
                            id=finding_id,
                            campaign_id=campaign_id,
                            owasp_id=attempts_file.owasp_id,
                            attack_turns=turns,
                            target_reply=reply,
                            normalization_evidence=evaluation.normalization_evidence,
                            matched_pattern=attempts_file.success.marker_ref,
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
                        lease_expires_at=None,
                    )
                    terminal_written = True
                    if attempt_spec.source == "planner":
                        await synthesize_proposed_rule(
                            connection,
                            rule_synthesizer,
                            finding_id=finding_id,
                            attack_turns=turns,
                            target_reply=reply,
                        )
                    break

            if not terminal_written:
                terminal_values: dict[str, object] = {
                    "status": final_status,
                    "ended_at": utc_now(),
                    "lease_expires_at": None,
                }
                if terminal_error is not None:
                    terminal_values.update(
                        terminal_exception_values(
                            terminal_error,
                            await persisted_attempt_count(connection, campaign_id),
                        )
                    )
                    final_status = str(terminal_values["status"])
                await update_campaign(
                    connection,
                    campaign_id,
                    **terminal_values,
                )
                terminal_written = True
    except Exception as exc:
        if not terminal_written:
            async with engine.connect() as connection:
                await update_campaign(
                    connection,
                    campaign_id,
                    **terminal_exception_values(
                        exc,
                        await persisted_attempt_count(connection, campaign_id),
                    ),
                )
        raise
    finally:
        await engine.dispose()
        if valkey_client is not None:
            await valkey_client.aclose()

    elapsed_seconds = time.monotonic() - start_monotonic
    print(
        "campaign_end"
        f" campaign_id={campaign_id} status={final_status}"
        f" queries_used={queries_used} elapsed_seconds={elapsed_seconds:.3f}"
    )
    return CampaignOutcome(campaign_id, final_status, queries_used, elapsed_seconds)
