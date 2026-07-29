"""Explicit operator reconciliation for legacy campaigns that predate leases."""

from __future__ import annotations

import argparse
import asyncio
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from strike.app.config import settings
from strike.app.database import campaigns
from strike.app.runner import utc_now


async def reconcile(campaign_id: uuid.UUID, reason: str) -> None:
    """Interrupt one named, lease-less legacy campaign with an operator-provided reason."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                sa.update(campaigns)
                .where(
                    campaigns.c.id == campaign_id,
                    campaigns.c.status == "running",
                    campaigns.c.lease_expires_at.is_(None),
                )
                .values(
                    status="interrupted",
                    ended_at=utc_now(),
                    recovery_reason=reason,
                )
                .returning(campaigns.c.id)
            )
            if result.scalar_one_or_none() is None:
                raise SystemExit(
                    "reconciliation refused: campaign is not a lease-less running campaign"
                )
    finally:
        await engine.dispose()
    print(f"campaign_reconciled campaign_id={campaign_id} status=interrupted")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", required=True, type=uuid.UUID)
    parser.add_argument("--reason", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(reconcile(args.campaign_id, args.reason))


if __name__ == "__main__":
    main()
