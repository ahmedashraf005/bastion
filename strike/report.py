"""Read-only campaign report: identity, coverage, findings, near-misses.

This module never writes to the database and never touches Gate, Strike's
detection path, or the success contract. It renders what campaign_terminal
diagnostics and the attempts/findings/proposed_rules tables already record.

error_type and error_detail on strike.campaigns are explicit local-dashboard
diagnostics (see the column comment in strike/app/database.py) and must
never appear in this module's output. fetch_campaign() deliberately does not
select those two columns at all, so there is no code path that could leak
them into a report or export payload.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from strike.app.config import settings
from strike.app.database import attempts, campaigns, findings, proposed_rules


# Bucket labels are always present in a report, even when empty, so the
# structure is stable whether or not any bucket has been populated yet.
REMEDIATION_BUCKETS = (
    "closed_by_synthesized_rule",
    "requires_fix_in_target_application",
    "requires_architectural_decision",
    "still_open_uncategorized",
)

# proposed_rules statuses that represent an active, non-abandoned proposal.
# "rejected" does not close a finding — it returns it to still_open.
ACTIVE_PROPOSAL_STATUSES = ("pending_review", "approved", "applied")

NEAR_MISS_EXPLANATION = (
    "A near-miss means a marker-shaped candidate appeared near the expected "
    "anchor in the target's reply but did not exactly match the configured "
    "value after normalization. The target may have partially disclosed the "
    "secret (for example, a transcription-corrupted value) while "
    "value-anchored detection — which requires an exact, case-sensitive "
    "match — did not fire. This is not a confirmed bypass. It is evidence a "
    "human should review; see docs/design/value-anchored-marker-detection.md "
    "for why closing this class of gap is an architectural decision, not a "
    "synthesizable signature."
)

# Static summaries of coverage gaps recorded in docs/threat-model.md. Kept
# short and pointed at the source doc rather than duplicated in full, so a
# report cannot silently drift out of sync with the authoritative text.
KNOWN_COVERAGE_GAPS = (
    {
        "id": "user_role_only_input_scanning",
        "summary": (
            "Gate's input-stage detectors (Prompt Guard, Presidio) inspect "
            "user-role message content only. Tool-role and assistant-role "
            "content are not input-scanned, so indirect prompt injection "
            "delivered through tool output or retrieved context is outside "
            "current coverage."
        ),
        "doc_ref": "docs/threat-model.md#indirect-prompt-injection-boundary",
    },
    {
        "id": "tool_argument_egress_not_scanned",
        "summary": (
            "Tool-call arguments are not scanned by the output-stage leak "
            "detector, so a canary or PII value carried in a tool argument "
            "is not caught the way one in message content is."
        ),
        "doc_ref": "docs/threat-model.md#indirect-prompt-injection-boundary",
    },
    {
        "id": "multi_choice_output_scanning",
        "summary": (
            "With n>1, only the first choice in a response is output-scanned. "
            "Additional choices are not audited for leakage."
        ),
        "doc_ref": "docs/threat-model.md",
    },
    {
        "id": "llm10_not_implemented",
        "summary": (
            "LLM10 (unbounded consumption) is not implemented. Gate persists "
            "usage but enforces no cap; do not read a clean report as "
            "including LLM10 coverage."
        ),
        "doc_ref": "docs/threat-model.md",
    },
)

CONFIG_IDENTITY_NOTE = (
    "The source campaign YAML file path is not persisted on the campaign "
    "row; objective, owasp_id, and target_key below are the closest "
    "identity proxy actually stored."
)

SEVERITY_NOTE = (
    "Confirmed-finding severity is not a persisted field in the current "
    "schema. No independent severity assessment is stored; use owasp_id "
    "and the evidence payload for triage."
)

EXACT_POSITIONAL_OVERLAP_NOTE = (
    "Only a case-folded positional overlap is persisted per near-miss "
    "(strike.attempts.normalization_evidence). An exact, case-sensitive "
    "positional overlap is not stored and is not recomputed here, since "
    "doing so would require this report to resolve the marker secret "
    "itself — a boundary intentionally kept inside the success contract, "
    "not duplicated into reporting code."
)


@dataclass
class CampaignIdentity:
    campaign_id: str
    objective: str
    owasp_id: str
    target_key: str
    status: str
    started_at: str | None
    ended_at: str | None
    wall_clock_seconds: float | None
    queries_used: int
    max_queries: int
    max_wall_clock_seconds: int
    node_count: int
    pruned_count: int
    executed_count: int
    sanitized_count: int
    planner_model: str | None
    inference_route: str | None
    inference_base_url: str | None
    gate_normalization_version_id: str | None
    gate_pattern_version_id: str | None
    config_note: str = CONFIG_IDENTITY_NOTE
    sanitized_note: str = (
        "sanitized_count is how many attempts had a NUL byte (U+0000) "
        "stripped from planner- or target-generated text before being "
        "persisted — Postgres cannot store one at all. Evidence is never "
        "altered silently; this count is the trace. See "
        "gate/app/text_sanitization.py."
    )


@dataclass
class CoverageOutcome:
    outcome: str
    count: int


@dataclass
class Finding:
    finding_id: str
    owasp_id: str
    found_at: str | None
    attack_turns: object
    target_reply: str
    matched_pattern: str
    remediation_bucket: str
    proposed_rule_statuses: list[str]
    sanitized: bool
    severity_note: str = SEVERITY_NOTE


@dataclass
class NearMiss:
    attempt_id: str
    sequence_number: int
    candidate: str
    edit_distance: int
    positional_overlap_case_folded: float
    explanation: str = NEAR_MISS_EXPLANATION
    exact_positional_overlap_note: str = EXACT_POSITIONAL_OVERLAP_NOTE


@dataclass
class Report:
    identity: CampaignIdentity
    coverage: list[CoverageOutcome]
    findings: list[Finding]
    remediation_buckets: dict[str, list[str]]
    near_misses: list[NearMiss]
    known_coverage_gaps: list[dict] = field(
        default_factory=lambda: [dict(g) for g in KNOWN_COVERAGE_GAPS]
    )


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def classify_finding(proposal_statuses: list[str]) -> str:
    """Assign the remediation bucket a finding falls into today.

    Only two of the four buckets can be populated automatically from what is
    persisted: an active (non-rejected) proposed rule closes a finding;
    everything else defaults to still_open_uncategorized. Nothing in the
    current schema distinguishes "needs a fix in the user's own app" from
    "needs an architectural anchor-change decision" on a confirmed finding —
    those two buckets exist in the structure for a human to move a finding
    into, not for this report to infer.
    """

    if any(status in ACTIVE_PROPOSAL_STATUSES for status in proposal_statuses):
        return "closed_by_synthesized_rule"
    return "still_open_uncategorized"


def build_report(
    campaign_row: dict,
    attempt_rows: list[dict],
    finding_rows: list[dict],
    proposed_rule_rows: list[dict],
) -> Report:
    """Assemble a Report from plain rows — no I/O, so this is unit-testable."""

    started_at = campaign_row.get("started_at")
    ended_at = campaign_row.get("ended_at")
    wall_clock_seconds = (
        (ended_at - started_at).total_seconds()
        if started_at is not None and ended_at is not None
        else None
    )
    node_count = len(attempt_rows)
    pruned_count = sum(1 for a in attempt_rows if a.get("pruned"))
    sanitized_count = sum(1 for a in attempt_rows if a.get("sanitized"))
    identity = CampaignIdentity(
        campaign_id=str(campaign_row["id"]),
        objective=campaign_row["objective"],
        owasp_id=campaign_row["owasp_id"],
        target_key=campaign_row["target_key"],
        status=campaign_row["status"],
        started_at=_isoformat(started_at),
        ended_at=_isoformat(ended_at),
        wall_clock_seconds=wall_clock_seconds,
        queries_used=campaign_row["queries_used"],
        max_queries=campaign_row["max_queries"],
        max_wall_clock_seconds=campaign_row["max_wall_clock_seconds"],
        node_count=node_count,
        pruned_count=pruned_count,
        executed_count=node_count - pruned_count,
        sanitized_count=sanitized_count,
        planner_model=campaign_row.get("inference_model"),
        inference_route=campaign_row.get("inference_route"),
        inference_base_url=campaign_row.get("inference_base_url"),
        gate_normalization_version_id=campaign_row.get("gate_normalization_version_id"),
        gate_pattern_version_id=campaign_row.get("gate_pattern_version_id"),
    )

    outcome_counts: dict[str, int] = {}
    for attempt in attempt_rows:
        outcome = attempt.get("outcome") or "unclassified"
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
    coverage = [
        CoverageOutcome(outcome=outcome, count=count)
        for outcome, count in sorted(outcome_counts.items())
    ]

    proposals_by_finding: dict[str, list[str]] = {}
    for row in proposed_rule_rows:
        proposals_by_finding.setdefault(str(row["finding_id"]), []).append(row["status"])

    buckets: dict[str, list[str]] = {bucket: [] for bucket in REMEDIATION_BUCKETS}
    finding_records: list[Finding] = []
    for row in finding_rows:
        finding_id = str(row["id"])
        proposal_statuses = proposals_by_finding.get(finding_id, [])
        bucket = classify_finding(proposal_statuses)
        buckets[bucket].append(finding_id)
        finding_records.append(
            Finding(
                finding_id=finding_id,
                owasp_id=row["owasp_id"],
                found_at=_isoformat(row.get("found_at")),
                attack_turns=row["attack_turns"],
                target_reply=row["target_reply"],
                matched_pattern=row["matched_pattern"],
                remediation_bucket=bucket,
                proposed_rule_statuses=proposal_statuses,
                sanitized=bool(row.get("sanitized")),
            )
        )

    near_misses = [
        NearMiss(
            attempt_id=str(a["id"]),
            sequence_number=a["sequence_number"],
            candidate=(a.get("normalization_evidence") or {}).get("candidate", ""),
            edit_distance=(a.get("normalization_evidence") or {}).get("edit_distance", -1),
            positional_overlap_case_folded=(a.get("normalization_evidence") or {}).get(
                "positional_overlap", 0.0
            ),
        )
        for a in attempt_rows
        if a.get("outcome") == "near_marker_miss"
    ]

    return Report(
        identity=identity,
        coverage=coverage,
        findings=finding_records,
        remediation_buckets=buckets,
        near_misses=near_misses,
    )


def render_json(report: Report) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=False, default=str)


def render_text(report: Report) -> str:
    lines: list[str] = []
    i = report.identity
    lines.append(f"Campaign {i.campaign_id}")
    lines.append(f"  status:              {i.status}")
    lines.append(f"  objective:           {i.objective}")
    lines.append(f"  owasp_id:            {i.owasp_id}")
    lines.append(f"  target:              {i.target_key}")
    lines.append(f"  ({i.config_note})")
    lines.append(
        f"  queries:             {i.queries_used}/{i.max_queries}"
        f" (budget {i.max_wall_clock_seconds}s)"
    )
    wall_clock = f"{i.wall_clock_seconds:.3f}s" if i.wall_clock_seconds is not None else "n/a (not ended)"
    lines.append(f"  wall clock:          {wall_clock}")
    lines.append(f"  nodes:               {i.node_count} total, {i.pruned_count} pruned, {i.executed_count} executed")
    lines.append(f"  sanitized:           {i.sanitized_count} attempt(s) had a NUL byte stripped before persistence")
    lines.append(f"    ({i.sanitized_note})")
    lines.append(f"  planner model:       {i.planner_model or 'n/a'}")
    lines.append(f"  inference route:     {i.inference_route or 'n/a'} ({i.inference_base_url or 'n/a'})")
    lines.append(f"  gate normalization:  {i.gate_normalization_version_id or 'n/a'}")
    lines.append(f"  gate pattern:        {i.gate_pattern_version_id or 'n/a'}")
    lines.append("")

    lines.append("Coverage (all attempts, including pruned):")
    if report.coverage:
        for outcome in report.coverage:
            lines.append(f"  {outcome.outcome:<28} {outcome.count}")
    else:
        lines.append("  (no attempts recorded)")
    lines.append("")

    lines.append("Confirmed findings:")
    if report.findings:
        for finding in report.findings:
            lines.append(f"  finding {finding.finding_id} [{finding.remediation_bucket}]")
            lines.append(f"    owasp_id:        {finding.owasp_id}")
            lines.append(f"    found_at:        {finding.found_at}")
            lines.append(f"    matched_pattern: {finding.matched_pattern}")
            lines.append(f"    target_reply:    {finding.target_reply}")
            lines.append(f"    attack_turns:    {json.dumps(finding.attack_turns)}")
            lines.append(f"    sanitized:       {finding.sanitized}")
            lines.append(
                f"    proposed_rules:  {finding.proposed_rule_statuses or '(none proposed)'}"
            )
            lines.append(f"    ({finding.severity_note})")
    else:
        lines.append(
            "  None. This means Gate held for every attempt actually executed — "
            "see Coverage above for what was tried, and Near-misses and Known "
            "coverage gaps below for what a clean result does not guarantee."
        )
    lines.append("")

    lines.append("Remediation buckets:")
    for bucket in REMEDIATION_BUCKETS:
        ids = report.remediation_buckets.get(bucket, [])
        lines.append(f"  {bucket:<38} {ids or '(none)'}")
    lines.append("")

    lines.append("Near-misses:")
    if report.near_misses:
        lines.append(f"  {NEAR_MISS_EXPLANATION}")
        lines.append("")
        for nm in report.near_misses:
            lines.append(f"  attempt {nm.attempt_id} (sequence {nm.sequence_number})")
            lines.append(f"    candidate:                    {nm.candidate!r}")
            lines.append(f"    edit_distance:                {nm.edit_distance}")
            lines.append(f"    positional_overlap (case-folded): {nm.positional_overlap_case_folded}")
            lines.append(f"    ({EXACT_POSITIONAL_OVERLAP_NOTE})")
    else:
        lines.append("  None recorded for this campaign.")
    lines.append("")

    lines.append("Known coverage gaps (a clean report does not mean these were checked):")
    for gap in report.known_coverage_gaps:
        lines.append(f"  - {gap['summary']}")
        lines.append(f"    see: {gap['doc_ref']}")
    lines.append("")

    return "\n".join(lines)


async def fetch_report(campaign_id: uuid.UUID) -> Report:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            # error_type and error_detail are deliberately not selected here.
            campaign_result = await connection.execute(
                sa.select(
                    campaigns.c.id,
                    campaigns.c.objective,
                    campaigns.c.owasp_id,
                    campaigns.c.target_key,
                    campaigns.c.status,
                    campaigns.c.started_at,
                    campaigns.c.ended_at,
                    campaigns.c.max_queries,
                    campaigns.c.queries_used,
                    campaigns.c.max_wall_clock_seconds,
                    campaigns.c.inference_base_url,
                    campaigns.c.inference_route,
                    campaigns.c.inference_model,
                    campaigns.c.gate_normalization_version_id,
                    campaigns.c.gate_pattern_version_id,
                ).where(campaigns.c.id == campaign_id)
            )
            campaign_row = campaign_result.mappings().one_or_none()
            if campaign_row is None:
                raise SystemExit(f"campaign not found: {campaign_id}")

            attempt_result = await connection.execute(
                sa.select(
                    attempts.c.id,
                    attempts.c.sequence_number,
                    attempts.c.outcome,
                    attempts.c.pruned,
                    attempts.c.normalization_evidence,
                    attempts.c.sanitized,
                ).where(attempts.c.campaign_id == campaign_id)
            )
            attempt_rows = [dict(r) for r in attempt_result.mappings()]

            finding_result = await connection.execute(
                sa.select(
                    findings.c.id,
                    findings.c.owasp_id,
                    findings.c.found_at,
                    findings.c.attack_turns,
                    findings.c.target_reply,
                    findings.c.matched_pattern,
                    findings.c.sanitized,
                ).where(findings.c.campaign_id == campaign_id)
            )
            finding_rows = [dict(r) for r in finding_result.mappings()]

            finding_ids = [row["id"] for row in finding_rows]
            proposed_rule_rows: list[dict] = []
            if finding_ids:
                proposal_result = await connection.execute(
                    sa.select(proposed_rules.c.finding_id, proposed_rules.c.status).where(
                        proposed_rules.c.finding_id.in_(finding_ids)
                    )
                )
                proposed_rule_rows = [dict(r) for r in proposal_result.mappings()]
    finally:
        await engine.dispose()

    return build_report(dict(campaign_row), attempt_rows, finding_rows, proposed_rule_rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only report over one Strike campaign")
    parser.add_argument("--campaign", required=True, type=uuid.UUID)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = asyncio.run(fetch_report(args.campaign))
    if args.format == "json":
        print(render_json(report))
    else:
        print(render_text(report))


if __name__ == "__main__":
    main()
