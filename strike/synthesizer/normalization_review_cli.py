"""Persist and approve versioned, data-only detector normalization proposals."""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from strike.app.config import settings
from strike.app.database import (
    findings,
    new_normalization_proposal_id,
    normalization_proposals,
)
from strike.synthesizer.rule_synthesizer import (
    NormalizationProposal,
    PROPOSAL_ADAPTER,
    RuleSynthesizer,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_uuid(raw: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise SystemExit(f"invalid {field}: {raw}") from exc


async def record(finding_id: uuid.UUID, proposal_path: Path) -> uuid.UUID:
    """Record a normalization proposal only after re-verifying stored evidence."""

    candidate = PROPOSAL_ADAPTER.validate_json(proposal_path.read_text(encoding="utf-8"))
    if not isinstance(candidate, NormalizationProposal):
        raise SystemExit("record refused: proposal_type must be normalization")

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            finding = (
                await connection.execute(
                    sa.select(findings.c.target_reply).where(findings.c.id == finding_id)
                )
            ).scalar_one_or_none()
            if finding is None:
                raise SystemExit(f"record refused: finding not found: {finding_id}")
            synthesizer = RuleSynthesizer(
                ollama_base_url=settings.ollama_base_url,
                model="mechanical-verification-only",
            )
            passed, mode = await synthesizer.mechanical_verification(candidate, finding)
            if not passed:
                raise SystemExit("record refused: mechanical verification failed")
            proposal_id = new_normalization_proposal_id()
            version_id = f"normalization-{proposal_id}"
            await connection.execute(
                sa.insert(normalization_proposals).values(
                    id=proposal_id,
                    finding_id=finding_id,
                    proposal=candidate.model_dump(mode="json"),
                    verification_passed=True,
                    verification_mode=mode,
                    status="pending_review",
                    version_id=version_id,
                )
            )
            print(
                "normalization_proposal_recorded"
                f" proposal_id={proposal_id} version_id={version_id}"
                f" verification_mode={mode}"
            )
            return proposal_id
    finally:
        await engine.dispose()


async def approve(proposal_id: uuid.UUID, approver: str, evidence_path: Path) -> None:
    """Bind one human decision to the immutable evidence snapshot supplied."""

    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid approval evidence: {exc}") from exc
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            updated = await connection.execute(
                sa.update(normalization_proposals)
                .where(
                    normalization_proposals.c.id == proposal_id,
                    normalization_proposals.c.status == "pending_review",
                    normalization_proposals.c.verification_passed.is_(True),
                )
                .values(
                    status="approved",
                    approver=approver,
                    approved_at=_utc_now(),
                    approval_evidence=evidence,
                )
                .returning(normalization_proposals.c.version_id)
            )
            version_id = updated.scalar_one_or_none()
            if version_id is None:
                raise SystemExit("approval refused: proposal is not a verified pending review")
            print(
                "normalization_proposal_approved"
                f" proposal_id={proposal_id} version_id={version_id} approver={approver}"
            )
    finally:
        await engine.dispose()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review Bastion normalization proposals")
    commands = parser.add_subparsers(dest="command", required=True)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--finding-id", required=True)
    record_parser.add_argument("--proposal", required=True, type=Path)
    approve_parser = commands.add_parser("approve")
    approve_parser.add_argument("--proposal-id", required=True)
    approve_parser.add_argument("--approver", required=True)
    approve_parser.add_argument("--evidence", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "record":
        asyncio.run(record(_parse_uuid(args.finding_id, "finding id"), args.proposal))
    else:
        asyncio.run(
            approve(
                _parse_uuid(args.proposal_id, "proposal id"), args.approver, args.evidence
            )
        )


if __name__ == "__main__":
    main()
