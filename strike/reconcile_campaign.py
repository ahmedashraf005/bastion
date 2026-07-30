"""Explicit operator reconciliation for legacy campaigns that predate diagnostics."""

from __future__ import annotations

import argparse
import asyncio
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from strike.app.config import settings
from strike.app.database import attempts, campaigns
from strike.app.runner import utc_now


async def reconcile(campaign_id: uuid.UUID, reason: str, terminal_status: str) -> None:
    """Apply one explicit terminal reconciliation without discarding attempts."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            if terminal_status == "interrupted":
                where_clause = (
                    campaigns.c.id == campaign_id,
                    campaigns.c.status == "running",
                    campaigns.c.lease_expires_at.is_(None),
                )
            else:
                where_clause = (
                    campaigns.c.id == campaign_id,
                    campaigns.c.status == "error",
                    campaigns.c.error_type.is_(None),
                    campaigns.c.error_detail.is_(None),
                    sa.exists(
                        sa.select(sa.literal(1)).where(attempts.c.campaign_id == campaigns.c.id)
                    ),
                )
            result = await connection.execute(
                sa.update(campaigns)
                .where(*where_clause)
                .values(
                    status=terminal_status,
                    ended_at=utc_now(),
                    recovery_reason=reason,
                )
                .returning(campaigns.c.id)
            )
            if result.scalar_one_or_none() is None:
                raise SystemExit(
                    "reconciliation refused: campaign does not match the selected legacy state"
                )
    finally:
        await engine.dispose()
    print(f"campaign_reconciled campaign_id={campaign_id} status={terminal_status}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", required=True, type=uuid.UUID)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--terminal-status",
        choices=("interrupted", "failed_after_progress"),
        default="interrupted",
        help="explicit legacy terminal state (default: interrupted)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(reconcile(args.campaign_id, args.reason, args.terminal_status))


if __name__ == "__main__":
    main()
