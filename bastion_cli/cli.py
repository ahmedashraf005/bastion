"""Compose-backed Bastion CLI with actionable prerequisite failures."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import __version__


class CliError(RuntimeError):
    """A user-actionable local-environment failure."""


def project_root() -> Path:
    """Find the repository from the current directory, never from a package path."""

    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "docker-compose.yml").is_file() and (candidate / "strike").is_dir():
            return candidate
    raise CliError(
        "run bastion from the Bastion repository root (docker-compose.yml was not found)"
    )


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise CliError("Docker is not installed or is not on PATH; install Docker Desktop and retry")
    probe = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False
    )
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise CliError(f"Docker is not running; start Docker Desktop and retry{suffix}")


def compose(root: Path, *args: str, check: bool = True) -> int:
    """Run Compose from the repository root, preserving its operator output."""

    result = subprocess.run(["docker", "compose", *args], cwd=root, check=False)
    if check and result.returncode != 0:
        raise CliError(
            f"Docker Compose failed (exit {result.returncode}); run `docker compose {' '.join(args)}` for full diagnostics"
        )
    return result.returncode


def compose_ready(root: Path) -> None:
    require_docker()
    compose(root, "up", "-d", "--wait")


def command_gate(args: argparse.Namespace) -> int:
    root = project_root()
    require_docker()
    if args.action == "up":
        compose(root, "up", "-d", "--wait")
    elif args.action == "down":
        compose(root, "down")
    else:
        compose(root, "ps")
    return 0


def command_strike_run(args: argparse.Namespace) -> int:
    root = project_root()
    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        raise CliError(f"campaign config does not exist: {config_path}")
    if args.planner == "openai" and not os.getenv("OPENAI_API_KEY"):
        raise CliError(
            "--planner openai requires OPENAI_API_KEY in your environment; "
            "it is never inferred and Ollama will not be used as a fallback"
        )

    compose_ready(root)
    compose_args = [
        "--profile",
        "manual",
        "run",
        "--rm",
        "-e",
        f"STRIKE_PLANNER_PROVIDER={args.planner}",
        "-v",
        f"{config_path}:/tmp/bastion-campaign.yaml:ro",
        "strike",
        "python",
        "-m",
        "strike.run_campaign",
        "--target",
        "sample-bank",
        "--attempts",
        "/tmp/bastion-campaign.yaml",
    ]
    if args.planner == "openai":
        compose_args.extend(["-e", "OPENAI_API_KEY"])
    return compose(root, *compose_args)


def parser() -> argparse.ArgumentParser:
    root_parser = argparse.ArgumentParser(
        prog="bastion", description="Run the Bastion local MVP through Docker Compose"
    )
    root_parser.add_argument("--version", action="version", version=f"bastion {__version__}")
    commands = root_parser.add_subparsers(dest="command", required=True)

    gate = commands.add_parser("gate", help="manage the Compose-backed local stack")
    gate.set_defaults(handler=command_gate)
    gate.add_argument("action", choices=("up", "down", "status"))

    strike = commands.add_parser("strike", help="run a reviewed Strike campaign")
    strike_commands = strike.add_subparsers(dest="strike_command", required=True)
    run = strike_commands.add_parser("run", help="run one campaign from YAML")
    run.add_argument("--config", required=True, help="campaign YAML path")
    run.add_argument(
        "--planner",
        choices=("ollama", "openai"),
        default="ollama",
        help="planner provider (default: ollama; openai uses your paid API key)",
    )
    run.set_defaults(handler=command_strike_run)
    return root_parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        return int(args.handler(args))
    except CliError as exc:
        print(f"bastion: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
