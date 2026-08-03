"""Compose-backed Bastion CLI with actionable prerequisite failures."""

from __future__ import annotations

import argparse
import hashlib
import json
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


def default_project_name(root: Path) -> str:
    """Derive a Compose project name unique to this checkout's absolute path.

    docker-compose.yml has no top-level `name:`, so two independent checkouts
    never collide on the literal "bastion" project unless a user explicitly
    overrides COMPOSE_PROJECT_NAME to force it.
    """

    digest = hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:10]
    return f"bastion-{digest}"


def read_dotenv_value(root: Path, key: str) -> str | None:
    """Read one KEY=value line from .env without a parser dependency.

    docker compose auto-loads .env for its own substitutions, but this CLI
    decides the project name in Python before invoking compose, so it must
    read .env itself to honor a value set there rather than only in the
    shell environment.
    """

    env_path = root / ".env"
    if not env_path.is_file():
        return None
    prefix = f"{key}="
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix):].strip()
    return None


def resolve_project_name(root: Path) -> str:
    """Shell env wins, then .env, then a checkout-derived default."""

    return (
        os.environ.get("COMPOSE_PROJECT_NAME")
        or read_dotenv_value(root, "COMPOSE_PROJECT_NAME")
        or default_project_name(root)
    )


def ensure_project_name_persisted(root: Path) -> None:
    """Write the derived project name into .env the first time, if absent.

    docker compose reads COMPOSE_PROJECT_NAME from a .env file in the
    working directory on its own — this CLI's in-Python resolution is
    invisible to a raw `docker compose` command run in this checkout. Without
    this, `bastion` and a manually-run `docker compose` in the same directory
    can resolve to different project names, and a raw command falls back to
    the directory basename, which collides with any other checkout sharing
    that basename (this is exactly how the live stack's containers and
    volumes were destroyed by a raw `docker compose down` once). Only writes
    when .env has no COMPOSE_PROJECT_NAME line yet; never overwrites an
    operator's or an earlier run's existing value.
    """

    env_path = root / ".env"
    if not env_path.is_file():
        return
    if read_dotenv_value(root, "COMPOSE_PROJECT_NAME") is not None:
        return
    with env_path.open("a") as f:
        f.write(
            "\n# Written by `bastion` on first run so a raw `docker compose`\n"
            "# command in this directory resolves to the same project this\n"
            "# checkout's containers and volumes already use. Changing this\n"
            "# value orphans them — a different project name means new,\n"
            "# empty containers and volumes, not a rename. Only change it if\n"
            "# you understand that and want the reset.\n"
            f"COMPOSE_PROJECT_NAME={default_project_name(root)}\n"
        )


def check_no_project_collision(root: Path, project_name: str) -> None:
    """Refuse to proceed if another checkout already owns this project name.

    Without this, `docker compose up` silently recreates whatever containers
    already hold that name using *this* checkout's .env and image, even if
    they belong to a different clone entirely — including disabling that
    other checkout's HF_TOKEN-gated Prompt Guard if this one's .env lacks it.
    """

    probe = subprocess.run(
        ["docker", "compose", "ls", "--all", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0 or not probe.stdout.strip():
        return
    try:
        projects = json.loads(probe.stdout)
    except json.JSONDecodeError:
        return
    resolved_root = str(root.resolve())
    for project in projects:
        if project.get("Name") != project_name:
            continue
        config_files = project.get("ConfigFiles", "")
        other_dirs = {str(Path(f).resolve().parent) for f in config_files.split(",") if f}
        if other_dirs and resolved_root not in other_dirs:
            raise CliError(
                f"COMPOSE_PROJECT_NAME={project_name!r} is already in use by a checkout at "
                f"{', '.join(sorted(other_dirs))}, not this one ({resolved_root}); "
                "bringing this stack up would silently recreate that checkout's containers "
                "with this checkout's .env. Unset COMPOSE_PROJECT_NAME to use a "
                "checkout-derived default, or set it to something unique to this clone."
            )


def compose(root: Path, *args: str, check: bool = True) -> int:
    """Run Compose from the repository root, preserving its operator output."""

    env = os.environ | {"COMPOSE_PROJECT_NAME": resolve_project_name(root)}
    result = subprocess.run(["docker", "compose", *args], cwd=root, env=env, check=False)
    if check and result.returncode != 0:
        raise CliError(
            f"Docker Compose failed (exit {result.returncode}); run `docker compose {' '.join(args)}` for full diagnostics"
        )
    return result.returncode


def compose_ready(root: Path) -> None:
    require_docker()
    check_no_project_collision(root, resolve_project_name(root))
    ensure_project_name_persisted(root)
    compose(root, "up", "-d", "--build", "--wait")


def command_gate(args: argparse.Namespace) -> int:
    root = project_root()
    require_docker()
    if args.action == "up":
        check_no_project_collision(root, resolve_project_name(root))
        ensure_project_name_persisted(root)
        compose(root, "up", "-d", "--build", "--wait")
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
    # Strike is behind the manual profile, so it is not rebuilt by the
    # default-stack `up --build`. Build it explicitly before the on-demand
    # run; otherwise a stale local image can carry an older migration head.
    compose(root, "--profile", "manual", "build", "strike")
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
