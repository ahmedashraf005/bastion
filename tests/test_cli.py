import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from bastion_cli.cli import (
    CliError,
    check_no_project_collision,
    command_strike_run,
    default_project_name,
    ensure_project_name_persisted,
    parser,
    project_root,
    resolve_project_name,
)


class CliTests(unittest.TestCase):
    def test_version_and_commands_are_exposed(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            parser().parse_args(["--version"])
        self.assertEqual(raised.exception.code, 0)
        args = parser().parse_args(["strike", "run", "--config", "campaign.yaml"])
        self.assertEqual(args.planner, "ollama")

    def test_openai_requires_explicit_user_key(self) -> None:
        with tempfile.NamedTemporaryFile() as config:
            args = parser().parse_args(
                ["strike", "run", "--config", config.name, "--planner", "openai"]
            )
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                CliError, "OPENAI_API_KEY"
            ):
                command_strike_run(args)

    def test_project_root_is_discovered_from_a_subdirectory(self) -> None:
        with patch("bastion_cli.cli.Path.cwd", return_value=Path(__file__).parent):
            self.assertTrue((project_root() / "docker-compose.yml").is_file())

    def test_strike_rebuilds_manual_image_before_run(self) -> None:
        with tempfile.NamedTemporaryFile() as config:
            args = parser().parse_args(["strike", "run", "--config", config.name])
            with patch("bastion_cli.cli.compose_ready"), patch(
                "bastion_cli.cli.compose", return_value=0
            ) as compose_call:
                self.assertEqual(command_strike_run(args), 0)
            self.assertTrue(
                any(
                    call.args[1:5] == ("--profile", "manual", "build", "strike")
                    for call in compose_call.call_args_list
                )
            )

    def test_default_project_name_is_unique_per_checkout_path(self) -> None:
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            name_a = default_project_name(Path(a))
            name_b = default_project_name(Path(b))
            self.assertNotEqual(name_a, name_b)
            self.assertEqual(name_a, default_project_name(Path(a)))
            self.assertTrue(name_a.startswith("bastion-"))

    def test_resolve_project_name_precedence_env_then_dotenv_then_default(self) -> None:
        with tempfile.TemporaryDirectory() as root_str, patch.dict(
            os.environ, {}, clear=False
        ):
            os.environ.pop("COMPOSE_PROJECT_NAME", None)
            root = Path(root_str)
            derived = default_project_name(root)
            self.assertEqual(resolve_project_name(root), derived)

            (root / ".env").write_text("COMPOSE_PROJECT_NAME=from-dotenv\n")
            self.assertEqual(resolve_project_name(root), "from-dotenv")

            os.environ["COMPOSE_PROJECT_NAME"] = "from-shell"
            self.assertEqual(resolve_project_name(root), "from-shell")

    def test_ensure_project_name_persisted_writes_once_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as root_str, patch.dict(
            os.environ, {}, clear=False
        ):
            os.environ.pop("COMPOSE_PROJECT_NAME", None)
            root = Path(root_str)
            (root / ".env").write_text("SOME_OTHER_VAR=1\n")

            ensure_project_name_persisted(root)
            derived = default_project_name(root)
            self.assertEqual(resolve_project_name(root), derived)

            (root / ".env").write_text(
                (root / ".env").read_text() + "\n# operator note\n"
            )
            ensure_project_name_persisted(root)
            self.assertEqual(
                (root / ".env").read_text().count("COMPOSE_PROJECT_NAME="), 1
            )

    def test_ensure_project_name_persisted_does_nothing_without_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as root_str:
            root = Path(root_str)
            ensure_project_name_persisted(root)
            self.assertFalse((root / ".env").exists())

    def test_collision_check_passes_for_same_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as root_str:
            root = Path(root_str)
            payload = json.dumps(
                [{"Name": "bastion-x", "ConfigFiles": str(root / "docker-compose.yml")}]
            )
            with patch(
                "bastion_cli.cli.subprocess.run",
                return_value=Mock(returncode=0, stdout=payload),
            ):
                check_no_project_collision(root, "bastion-x")  # must not raise

    def test_collision_check_raises_for_a_different_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as root_str, tempfile.TemporaryDirectory() as other_str:
            root = Path(root_str)
            other = Path(other_str)
            payload = json.dumps(
                [{"Name": "bastion-x", "ConfigFiles": str(other / "docker-compose.yml")}]
            )
            with patch(
                "bastion_cli.cli.subprocess.run",
                return_value=Mock(returncode=0, stdout=payload),
            ), self.assertRaisesRegex(CliError, "already in use"):
                check_no_project_collision(root, "bastion-x")
