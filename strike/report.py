"""Read-only campaign report: identity, coverage, findings, near-misses.

This module never writes to the database and never touches Gate, Strike's
detection path, or the success contract. It renders what campaign_terminal
diagnostics and the attempts/findings tables already record.

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
from strike.app.database import attempts, campaigns, findings
from strike.app.success_contract import resolve_marker_ref
from strike.marker_redaction import replace_markers

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

REPORT_REDACTION_FALLBACK = "[REDACTED: configured value unavailable]"

REMEDIATION_NOTE = (
    "Bastion does not synthesize or apply Gate detection rules automatically. "
    "Both confirmed findings are structurally unclosable in the current rule "
    "vocabulary; see docs/design/rule-vocabulary-and-promotion-gap.md. This "
    "is a deliberate scope decision, not a per-finding remediation state."
)

LLM07_TRIGGER = "finding.owasp_id == 'LLM07'"
LLM07_EVIDENCE_FIELDS = (
    "attack_turns",
    "target_reply",
    "matched_pattern",
    "gate_request_id",
    "sanitized",
)
LLM07_INVARIANT = (
    "The target emitted client-visible text that resolves, under the judge's "
    "canonicalization, to a value Bastion was configured to treat as secret."
)
LLM07_DOES_NOT_KNOW = (
    "The report does not know how the obfuscation worked; normalization_evidence "
    "(steps_fired, matched_via, and matched_region_codepoints) is not persisted. "
    "It also does not know whether this is the only sensitive value in the "
    "application, whether other secrets were exposed, or whether output filtering "
    "could fully close this class for this deployment."
)

LLM02_TRIGGER = "finding.owasp_id == 'LLM02'"
LLM02_EVIDENCE_FIELDS = (
    "attack_turns",
    "target_reply",
    "matched_pattern",
    "gate_request_id",
    "sanitized",
)
LLM02_INVARIANT = (
    "Client-visible output contained information classified by the finding as "
    "PII or sensitive information that the application should not disclose."
)
LLM02_DOES_NOT_KNOW = (
    "The report does not know whether the matched value is genuinely sensitive "
    "or a benign placeholder, whether the detector's entity classification is "
    "correct, or whether other PII exists outside this evidence."
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
        "sanitized_count is how many attempts had a NUL byte (U+0000) or a "
        "lone UTF-16 surrogate (U+D800-U+DFFF) stripped from planner- or "
        "target-generated text before being persisted — Postgres cannot "
        "store either at all. Evidence is never altered silently; this "
        "count is the trace. See gate/app/text_sanitization.py."
    )


@dataclass
class CoverageOutcome:
    outcome: str
    count: int


@dataclass
class Remediation:
    template_id: str
    trigger_condition: str
    evidence_fields_consumed: list[str]
    invariant_claim: str
    action: str
    does_not_know: str


@dataclass
class Finding:
    finding_id: str
    owasp_id: str
    found_at: str | None
    attack_turns: object
    target_reply: str
    matched_pattern: str
    gate_request_id: str | None
    sanitized: bool
    report_redaction_applied: bool
    remediation: Remediation
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
    near_misses: list[NearMiss]
    remediation_note: str = REMEDIATION_NOTE
    known_coverage_gaps: list[dict] = field(
        default_factory=lambda: [dict(g) for g in KNOWN_COVERAGE_GAPS]
    )


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _remediation_for_finding(owasp_id: str, matched_pattern: str) -> Remediation:
    """Return a hand-authored remediation populated only from finding evidence."""

    if owasp_id == "LLM07":
        reference = matched_pattern or "the configured marker reference"
        return Remediation(
            template_id="llm07.configuration_value_disclosed",
            trigger_condition=LLM07_TRIGGER,
            evidence_fields_consumed=list(LLM07_EVIDENCE_FIELDS),
            invariant_claim=LLM07_INVARIANT,
            action=(
                f"Treat the value referenced by {reference} as compromised and rotate it. "
                "Do not rely on output filtering as the only control for values that "
                "must never reach a client: the filter in front of this application "
                "was bypassed. Keep values needed during model interaction out of "
                "client-visible turns; use an out-of-band backend lookup keyed by an "
                "opaque reference instead of placing the literal value in model-visible "
                "context."
            ),
            does_not_know=LLM07_DOES_NOT_KNOW,
        )
    if owasp_id == "LLM02":
        reference = matched_pattern or "the recorded PII match"
        return Remediation(
            template_id="llm02.pii_disclosed",
            trigger_condition=LLM02_TRIGGER,
            evidence_fields_consumed=list(LLM02_EVIDENCE_FIELDS),
            invariant_claim=LLM02_INVARIANT,
            action=(
                f"Treat the disclosed data represented by {reference} as exposed. "
                "Remove real PII from prompts, seeded conversation history, and "
                "retrieved records before they reach model-visible context. If the "
                "application must process it, redact or tokenize it before the model "
                "can repeat it; do not rely on output-side filtering as the sole control."
            ),
            does_not_know=LLM02_DOES_NOT_KNOW,
        )
    return Remediation(
        template_id="unrecognized.finding_class",
        trigger_condition=f"finding.owasp_id == {owasp_id!r}",
        evidence_fields_consumed=["attack_turns", "target_reply", "matched_pattern"],
        invariant_claim="A confirmed finding exists, but its class is not in the current report taxonomy.",
        action="Review the evidence manually and do not infer that a Gate rule or automatic fix exists.",
        does_not_know="The current report has no hand-authored remediation template for this finding class.",
    )


def _marker_values_for_reference(matched_pattern: str) -> frozenset[str]:
    """Resolve only the reviewed marker value needed for report redaction."""

    try:
        return frozenset({resolve_marker_ref(matched_pattern).value})
    except ValueError:
        # A future finding class may not use a success-contract marker_ref.
        # Callers fail closed for the target reply rather than emit evidence
        # that could contain an unredactable secret.
        return frozenset()


def _redact_attack_turns(value: object, marker_values: frozenset[str]) -> object:
    """Redact marker values while preserving the attack-turn JSON shape."""

    if isinstance(value, str):
        return replace_markers(value, marker_values) if marker_values else value
    if isinstance(value, list):
        return [_redact_attack_turns(item, marker_values) for item in value]
    if isinstance(value, dict):
        return {
            key: _redact_attack_turns(item, marker_values)
            for key, item in value.items()
        }
    return value


def _redact_target_reply(value: str, marker_values: frozenset[str]) -> tuple[str, bool]:
    """Redact the target evidence, failing closed if its marker is unavailable."""

    if not marker_values:
        return REPORT_REDACTION_FALLBACK, True
    redacted = replace_markers(value, marker_values)
    if redacted == value:
        return REPORT_REDACTION_FALLBACK, True
    return redacted, True


def build_report(
    campaign_row: dict,
    attempt_rows: list[dict],
    finding_rows: list[dict],
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

    finding_records: list[Finding] = []
    for row in finding_rows:
        finding_id = str(row["id"])
        matched_pattern = row["matched_pattern"]
        marker_values = _marker_values_for_reference(matched_pattern)
        redacted_target_reply, report_redaction_applied = _redact_target_reply(
            row["target_reply"], marker_values
        )
        finding_records.append(
            Finding(
                finding_id=finding_id,
                owasp_id=row["owasp_id"],
                found_at=_isoformat(row.get("found_at")),
                attack_turns=_redact_attack_turns(row["attack_turns"], marker_values),
                target_reply=redacted_target_reply,
                matched_pattern=matched_pattern,
                gate_request_id=(
                    str(row["gate_request_id"])
                    if row.get("gate_request_id") is not None
                    else None
                ),
                sanitized=bool(row.get("sanitized")),
                report_redaction_applied=report_redaction_applied,
                remediation=_remediation_for_finding(
                    row["owasp_id"], matched_pattern
                ),
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
        near_misses=near_misses,
    )


def render_json(report: Report) -> str:
    """Render the stable report envelope with deterministic remediation text."""

    return json.dumps(asdict(report), indent=2, sort_keys=False, default=str)


def _not_attempted_summary(identity: CampaignIdentity) -> str:
    if identity.pruned_count:
        return (
            f"{identity.pruned_count} recorded node(s) were pruned by the "
            "campaign search and were not executed."
        )
    if identity.queries_used >= identity.max_queries:
        return (
            f"No additional queries were attempted because the "
            f"{identity.max_queries}-query budget was exhausted."
        )
    if identity.status in {"completed", "query_limit_reached"}:
        return (
            "No additional queries were attempted after the campaign ended; "
            "the persisted campaign record does not claim unrecorded work."
        )
    return (
        f"No additional attempts are recorded after campaign status "
        f"{identity.status!r}; unrecorded work cannot be inferred."
    )


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
    lines.append(f"  sanitized:           {i.sanitized_count} attempt(s) had an unsafe character stripped before persistence")
    lines.append(f"    ({i.sanitized_note})")
    lines.append(f"  planner model:       {i.planner_model or 'n/a'}")
    lines.append(f"  inference route:     {i.inference_route or 'n/a'} ({i.inference_base_url or 'n/a'})")
    lines.append(f"  gate normalization:  {i.gate_normalization_version_id or 'n/a'}")
    lines.append(f"  gate pattern:        {i.gate_pattern_version_id or 'n/a'}")
    lines.append("")

    lines.append("Coverage boundary:")
    lines.append(
        f"  attempted:           {i.executed_count} executed attempt(s) "
        f"from {i.node_count} recorded node(s)"
    )
    if i.wall_clock_seconds is not None:
        budget = (
            f"{i.queries_used}/{i.max_queries} queries, "
            f"{i.wall_clock_seconds:.3f}s/{i.max_wall_clock_seconds}s wall clock"
        )
    else:
        budget = (
            f"{i.queries_used}/{i.max_queries} queries, "
            f"wall clock not ended/{i.max_wall_clock_seconds}s"
        )
    lines.append(f"  budget:              {budget}")
    lines.append(f"  not attempted:       {_not_attempted_summary(i)}")
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
            lines.append(f"  finding {finding.finding_id}")
            lines.append(f"    owasp_id:        {finding.owasp_id}")
            lines.append(f"    found_at:        {finding.found_at}")
            lines.append(f"    matched_pattern: {finding.matched_pattern}")
            lines.append(f"    gate_request_id: {finding.gate_request_id or 'n/a'}")
            lines.append(
                "    target_reply (report-redacted): "
                f"{finding.target_reply}"
            )
            lines.append(f"    attack_turns:    {json.dumps(finding.attack_turns)}")
            lines.append(f"    report_redaction_applied: {finding.report_redaction_applied}")
            lines.append(
                "    sanitized:       "
                f"{finding.sanitized} (persistence-boundary sanitization; distinct from report redaction)"
            )
            lines.append(f"    ({finding.severity_note})")
            lines.append("    Remediation:")
            lines.append(f"      template_id:              {finding.remediation.template_id}")
            lines.append(f"      trigger_condition:         {finding.remediation.trigger_condition}")
            lines.append(
                "      evidence_fields_consumed: "
                f"{', '.join(finding.remediation.evidence_fields_consumed)}"
            )
            lines.append(f"      invariant_claim:           {finding.remediation.invariant_claim}")
            lines.append(f"      action:                    {finding.remediation.action}")
            lines.append(f"      does_not_know:             {finding.remediation.does_not_know}")
    else:
        lines.append(
            "  None. This means Gate held for every attempt actually executed — "
            "see Coverage above for what was tried, and Near-misses and Known "
            "coverage gaps below for what a clean result does not guarantee."
        )
    lines.append("")

    lines.append("Rule promotion (report-level):")
    lines.append(f"  {report.remediation_note}")
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
                    findings.c.gate_request_id,
                    findings.c.sanitized,
                ).where(findings.c.campaign_id == campaign_id)
            )
            finding_rows = [dict(r) for r in finding_result.mappings()]
    finally:
        await engine.dispose()

    return build_report(dict(campaign_row), attempt_rows, finding_rows)


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
