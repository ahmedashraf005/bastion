"""Apply or reverse one approved, versioned marker-reference detector pattern."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
import yaml
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine

try:
    from app.config import settings
except ModuleNotFoundError:
    from gate.app.config import settings


VERSIONS_PATH = Path(__file__).resolve().parent / "detectors/pattern_versions.yaml"
metadata = sa.MetaData(schema="strike")
normalization_proposals = sa.Table(
    "normalization_proposals",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
    sa.Column("proposal", postgresql.JSONB(), nullable=False),
    sa.Column("verification_passed", sa.Boolean(), nullable=False),
    sa.Column("status", sa.Text(), nullable=False),
    sa.Column("version_id", sa.Text(), nullable=False),
    sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("reverted_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("revert_reason", sa.Text(), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load_versions() -> list[dict[str, object]]:
    loaded = yaml.safe_load(VERSIONS_PATH.read_text(encoding="utf-8")) or []
    if not isinstance(loaded, list):
        raise ValueError("pattern_versions.yaml must contain a list")
    return loaded


def _write_versions(versions: list[dict[str, object]]) -> None:
    VERSIONS_PATH.write_text(
        yaml.safe_dump(versions, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )


def _set_active(versions: list[dict[str, object]], version_id: str, active: bool) -> None:
    entry = next((item for item in versions if item.get("version_id") == version_id), None)
    if entry is None:
        raise SystemExit("pattern-version operation refused: manifest entry is missing")
    entry["active"] = active


async def apply() -> None:
    """Enable all reviewed marker_ref replacements and mark them applied."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            rows = (
                await connection.execute(
                    sa.select(normalization_proposals).where(
                        normalization_proposals.c.status == "approved",
                        normalization_proposals.c.verification_passed.is_(True),
                    )
                )
            ).mappings().all()
            versions = _load_versions()
            for row in rows:
                proposal = row["proposal"]
                if not isinstance(proposal, dict) or proposal.get("proposal_type") != "marker_ref":
                    continue
                _set_active(versions, row["version_id"], True)
                await connection.execute(
                    sa.update(normalization_proposals)
                    .where(normalization_proposals.c.id == row["id"])
                    .values(status="applied", applied_at=_now(), reverted_at=None, revert_reason=None)
                )
                print(f"pattern_version_applied version_id={row['version_id']}")
            _write_versions(versions)
    finally:
        await engine.dispose()


async def revert(version_id: str, reason: str) -> None:
    """Disable one applied marker_ref replacement while keeping its record."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            row = (
                await connection.execute(
                    sa.select(normalization_proposals).where(
                        normalization_proposals.c.version_id == version_id,
                        normalization_proposals.c.status == "applied",
                    )
                )
            ).mappings().one_or_none()
            if row is None or row["proposal"].get("proposal_type") != "marker_ref":
                raise SystemExit("revert refused: marker_ref version is not applied")
            versions = _load_versions()
            _set_active(versions, version_id, False)
            _write_versions(versions)
            await connection.execute(
                sa.update(normalization_proposals)
                .where(normalization_proposals.c.id == row["id"])
                .values(status="reverted", reverted_at=_now(), revert_reason=reason)
            )
            print(f"pattern_version_reverted version_id={version_id}")
    finally:
        await engine.dispose()


async def reapply(version_id: str) -> None:
    """Re-enable one reverted marker_ref replacement with the same version id."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            row = (
                await connection.execute(
                    sa.select(normalization_proposals).where(
                        normalization_proposals.c.version_id == version_id,
                        normalization_proposals.c.status == "reverted",
                    )
                )
            ).mappings().one_or_none()
            if row is None or row["proposal"].get("proposal_type") != "marker_ref":
                raise SystemExit("reapply refused: marker_ref version is not reverted")
            versions = _load_versions()
            _set_active(versions, version_id, True)
            _write_versions(versions)
            await connection.execute(
                sa.update(normalization_proposals)
                .where(normalization_proposals.c.id == row["id"])
                .values(status="applied", applied_at=_now(), reverted_at=None, revert_reason=None)
            )
            print(f"pattern_version_reapplied version_id={version_id}")
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy reviewed Gate marker_ref versions")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("apply")
    revert_parser = commands.add_parser("revert")
    revert_parser.add_argument("--version-id", required=True)
    revert_parser.add_argument("--reason", required=True)
    reapply_parser = commands.add_parser("reapply")
    reapply_parser.add_argument("--version-id", required=True)
    args = parser.parse_args()
    if args.command == "apply":
        asyncio.run(apply())
    elif args.command == "revert":
        asyncio.run(revert(args.version_id, args.reason))
    else:
        asyncio.run(reapply(args.version_id))


if __name__ == "__main__":
    main()
