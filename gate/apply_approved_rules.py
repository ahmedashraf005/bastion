"""Append human-approved Strike proposals to Gate's leak-pattern configuration.

This is intentionally a local-development bridge: it reaches the shared Strike
schema and filesystem directly. Production handoff belongs behind Bastion.Control.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
import yaml
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine

try:
    from app.config import settings
except ModuleNotFoundError:  # Supports `python gate/apply_approved_rules.py` at repo root.
    from gate.app.config import settings


GATE_ROOT = Path(__file__).resolve().parent
PATTERNS_PATH = GATE_ROOT / "detectors/leak_patterns.yaml"
metadata = sa.MetaData(schema="strike")
proposed_rules = sa.Table(
    "proposed_rules",
    metadata,
    sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
    sa.Column("proposed_id", sa.Text(), nullable=False),
    sa.Column("proposed_pattern", sa.Text(), nullable=False),
    sa.Column("proposed_pattern_type", sa.Text(), nullable=False),
    sa.Column("proposed_normalize", sa.Text(), nullable=False),
    sa.Column("proposed_description", sa.Text(), nullable=False),
    sa.Column("status", sa.Text(), nullable=False),
    sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)


def _current_pattern_ids() -> set[str]:
    with PATTERNS_PATH.open(encoding="utf-8") as patterns_file:
        patterns = yaml.safe_load(patterns_file) or []
    return {
        entry["id"]
        for entry in patterns
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }


def _append_pattern(row: sa.RowMapping) -> None:
    """Append one YAML item without rewriting existing, security-reviewed patterns."""

    entry = {
        "id": row["proposed_id"],
        "description": row["proposed_description"],
        "pattern": row["proposed_pattern"],
        "pattern_type": row["proposed_pattern_type"],
        "normalize": row["proposed_normalize"],
        "enabled": True,
    }
    rendered_entry = yaml.safe_dump(
        [entry], sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    existing = PATTERNS_PATH.read_text(encoding="utf-8")
    PATTERNS_PATH.write_text(
        existing.rstrip("\n") + "\n" + rendered_entry,
        encoding="utf-8",
    )


async def apply_approved_rules() -> None:
    """Append collision-free approved rules, then mark each source proposal applied."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                sa.select(proposed_rules)
                .where(proposed_rules.c.status == "approved")
                .order_by(proposed_rules.c.created_at)
            )
            for row in result.mappings():
                if row["proposed_id"] in _current_pattern_ids():
                    print(
                        "apply_approved_rule_id_collision"
                        f" proposal_id={row['id']} proposed_id={row['proposed_id']}"
                    )
                    continue
                try:
                    _append_pattern(row)
                    await connection.execute(
                        sa.update(proposed_rules)
                        .where(proposed_rules.c.id == row["id"])
                        .values(status="applied", applied_at=datetime.now(timezone.utc))
                    )
                    await connection.commit()
                    print(
                        "apply_approved_rule_applied"
                        f" proposal_id={row['id']} proposed_id={row['proposed_id']}"
                    )
                except Exception as exc:
                    await connection.rollback()
                    print(
                        "apply_approved_rule_failed"
                        f" proposal_id={row['id']} error={exc!s}"
                    )
    finally:
        await engine.dispose()


def main() -> None:
    asyncio.run(apply_approved_rules())


if __name__ == "__main__":
    main()
