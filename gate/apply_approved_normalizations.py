"""Apply or reverse versioned Strike-approved detector normalizations."""

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
    from app.policy_profile import resolve_policy_profile
except ModuleNotFoundError:
    from gate.app.config import settings
    from gate.app.policy_profile import resolve_policy_profile


NORMALIZATIONS_PATH = resolve_policy_profile(
    settings.policy_profile, settings.rules_path
).normalization_versions
metadata = sa.MetaData(schema="strike")
normalization_proposals = sa.Table(
    "normalization_proposals",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
    sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
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
    with NORMALIZATIONS_PATH.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or []
    if not isinstance(loaded, list):
        raise ValueError("normalization_versions.yaml must contain a list")
    return loaded


def _write_versions(versions: list[dict[str, object]]) -> None:
    NORMALIZATIONS_PATH.write_text(
        yaml.safe_dump(versions, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )


def _entry(row: sa.RowMapping) -> dict[str, object]:
    proposal = row["proposal"]
    normalization = proposal["normalization"]
    return {
        "version_id": row["version_id"],
        "proposal_id": str(row["id"]),
        "origin_finding_id": str(row["finding_id"]),
        "detector": proposal["detector"],
        "active": True,
        "operation": normalization["operation"],
        "unicode_categories": normalization.get("unicode_categories", []),
        "named_classes": normalization.get("named_classes", []),
        "codepoints": normalization.get("codepoints", []),
    }


async def apply() -> None:
    """Materialize approved data-only changes, then mark their record applied."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            rows = (
                await connection.execute(
                    sa.select(normalization_proposals)
                    .where(
                        normalization_proposals.c.status == "approved",
                        normalization_proposals.c.verification_passed.is_(True),
                    )
                    .order_by(normalization_proposals.c.created_at)
                )
            ).mappings().all()
            versions = _load_versions()
            by_version = {str(item.get("version_id")): item for item in versions}
            for row in rows:
                entry = _entry(row)
                existing = by_version.get(row["version_id"])
                if existing is None:
                    versions.append(entry)
                    by_version[row["version_id"]] = entry
                else:
                    existing.update(entry)
                await connection.execute(
                    sa.update(normalization_proposals)
                    .where(normalization_proposals.c.id == row["id"])
                    .values(status="applied", applied_at=_now(), reverted_at=None, revert_reason=None)
                )
                print(
                    "normalization_version_applied"
                    f" proposal_id={row['id']} version_id={row['version_id']}"
                )
            if rows:
                _write_versions(versions)
    finally:
        await engine.dispose()


async def revert(version_id: str, reason: str) -> None:
    """Disable exactly one deployed version; its config entry and provenance remain."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            row = (
                await connection.execute(
                    sa.select(normalization_proposals)
                    .where(
                        normalization_proposals.c.version_id == version_id,
                        normalization_proposals.c.status == "applied",
                    )
                )
            ).mappings().one_or_none()
            if row is None:
                raise SystemExit("revert refused: version is not applied")
            versions = _load_versions()
            entry = next((item for item in versions if item.get("version_id") == version_id), None)
            if entry is None:
                raise SystemExit("revert refused: version is missing from Gate manifest")
            entry["active"] = False
            _write_versions(versions)
            await connection.execute(
                sa.update(normalization_proposals)
                .where(normalization_proposals.c.id == row["id"])
                .values(status="reverted", reverted_at=_now(), revert_reason=reason)
            )
            print(f"normalization_version_reverted version_id={version_id}")
    finally:
        await engine.dispose()


async def reapply(version_id: str) -> None:
    """Return one previously approved version to the approved queue for deployment."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            restored = await connection.execute(
                sa.update(normalization_proposals)
                .where(
                    normalization_proposals.c.version_id == version_id,
                    normalization_proposals.c.status == "reverted",
                )
                .values(status="approved")
                .returning(normalization_proposals.c.id)
            )
            if restored.scalar_one_or_none() is None:
                raise SystemExit("reapply refused: version is not reverted")
    finally:
        await engine.dispose()
    await apply()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy reviewed Bastion normalizations")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("apply")
    revert_parser = commands.add_parser("revert")
    revert_parser.add_argument("--version-id", required=True)
    revert_parser.add_argument("--reason", required=True)
    reapply_parser = commands.add_parser("reapply")
    reapply_parser.add_argument("--version-id", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "apply":
        asyncio.run(apply())
    elif args.command == "revert":
        asyncio.run(revert(args.version_id, args.reason))
    else:
        asyncio.run(reapply(args.version_id))


if __name__ == "__main__":
    main()
