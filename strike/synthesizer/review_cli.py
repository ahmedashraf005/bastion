"""Human review commands for Strike's evidence-verified proposed-rule queue."""

from __future__ import annotations

import argparse
import asyncio
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from strike.app.config import settings
from strike.app.database import findings, proposed_rules


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_id(raw_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw_id)
    except ValueError as exc:
        raise SystemExit(f"invalid proposed-rule id: {raw_id}") from exc


def _print_table(rows: list[dict[str, object]]) -> None:
    if not rows:
        print("No pending proposed rules.")
        return
    headers = ["id", "proposed_id", "proposed_pattern", "finding_id", "created_at"]
    widths = {
        header: max(len(header), *(len(str(row[header])) for row in rows))
        for header in headers
    }
    print("  ".join(header.ljust(widths[header]) for header in headers))
    for row in rows:
        print("  ".join(str(row[header]).ljust(widths[header]) for header in headers))


async def list_pending() -> None:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                sa.select(
                    proposed_rules.c.id,
                    proposed_rules.c.proposed_id,
                    proposed_rules.c.proposed_pattern,
                    proposed_rules.c.finding_id,
                    proposed_rules.c.created_at,
                )
                .where(proposed_rules.c.status == "pending_review")
                .order_by(proposed_rules.c.created_at)
            )
            _print_table([dict(row) for row in result.mappings()])
    finally:
        await engine.dispose()


async def show(proposed_rule_id: uuid.UUID) -> None:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                sa.select(
                    proposed_rules,
                    findings.c.attack_turns.label("finding_attack_turns"),
                    findings.c.target_reply.label("finding_target_reply"),
                )
                .join(findings, findings.c.id == proposed_rules.c.finding_id)
                .where(proposed_rules.c.id == proposed_rule_id)
            )
            row = result.mappings().one_or_none()
            if row is None:
                raise SystemExit(f"proposed rule not found: {proposed_rule_id}")
            print(f"id: {row['id']}")
            print(f"status: {row['status']}")
            print(f"finding_id: {row['finding_id']}")
            print(f"attack_turns: {row['finding_attack_turns']}")
            print(f"target_reply: {row['finding_target_reply']}")
            print(f"proposed_id: {row['proposed_id']}")
            print(f"pattern: {row['proposed_pattern']}")
            print(f"pattern_type: {row['proposed_pattern_type']}")
            print(f"normalize: {row['proposed_normalize']}")
            print(f"description: {row['proposed_description']}")
            print(f"verification_passed: {row['verification_passed']}")
            print(f"reviewer_note: {row['reviewer_note']}")
            print(f"reviewed_at: {row['reviewed_at']}")
    finally:
        await engine.dispose()


async def review(proposed_rule_id: uuid.UUID, status: str, note: str) -> None:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                sa.update(proposed_rules)
                .where(
                    proposed_rules.c.id == proposed_rule_id,
                    proposed_rules.c.status == "pending_review",
                )
                .values(status=status, reviewer_note=note, reviewed_at=_utc_now())
                .returning(proposed_rules.c.id)
            )
            if result.scalar_one_or_none() is None:
                await connection.rollback()
                raise SystemExit(
                    "review refused: proposed rule does not exist or is no longer pending_review"
                )
            await connection.commit()
            print(f"proposed_rule_reviewed id={proposed_rule_id} status={status}")
    finally:
        await engine.dispose()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review Bastion synthesized rules")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("list")
    show_parser = subcommands.add_parser("show")
    show_parser.add_argument("id")
    for command in ("approve", "reject"):
        review_parser = subcommands.add_parser(command)
        review_parser.add_argument("id")
        review_parser.add_argument("--note", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "list":
        asyncio.run(list_pending())
    elif args.command == "show":
        asyncio.run(show(_parse_id(args.id)))
    else:
        asyncio.run(review(_parse_id(args.id), args.command + "ed", args.note))


if __name__ == "__main__":
    main()
