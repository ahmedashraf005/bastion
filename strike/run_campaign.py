"""CLI entry point for a safety-limited Bastion.Strike campaign."""

import argparse
import asyncio
from pathlib import Path

from .app.runner import run_campaign


def parse_args() -> argparse.Namespace:
    """Parse explicit, visible operator-selected campaign safety limits."""

    parser = argparse.ArgumentParser(description="Run a reviewed Strike campaign")
    parser.add_argument("--target", required=True, help="reviewed target allowlist key")
    parser.add_argument("--attempts", required=True, type=Path, help="attempts YAML file")
    parser.add_argument("--max-queries", type=int, default=50)
    parser.add_argument("--max-wall-clock-seconds", type=int, default=300)
    return parser.parse_args()


def main() -> None:
    """Run the campaign and present a clear CLI failure for invalid input."""

    args = parse_args()
    try:
        asyncio.run(
            run_campaign(
                target_key=args.target,
                attempts_path=args.attempts,
                max_queries=args.max_queries,
                max_wall_clock_seconds=args.max_wall_clock_seconds,
            )
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"campaign refused: {exc}") from exc


if __name__ == "__main__":
    main()
