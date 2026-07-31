import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bastion_cli.cli import CliError, command_strike_run, parser, project_root


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
