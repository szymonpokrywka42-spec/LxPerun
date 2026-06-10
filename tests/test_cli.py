import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lxperun.cli import main


class CliHelpTest(unittest.TestCase):
    def test_help_topic_mentions_command(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "hardware"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("LxPerun", output)
        self.assertIn("hardware", output)
        self.assertIn("--raw", output)

    def test_help_network_mentions_watch_mode(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "network"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("network", output)
        self.assertIn("--watch", output)

    def test_help_security_mentions_root_mode(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "security"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("security", output)
        self.assertIn("--root", output)
        self.assertIn("SELinux", output)

    def test_help_firewall_mentions_ruleset(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "firewall"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("firewall", output)
        self.assertIn("iptables", output)

    def test_help_performance_mentions_psi(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "performance"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("performance", output)
        self.assertIn("PSI", output)

    def test_help_containers_mentions_cgroup(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "containers"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("containers", output)
        self.assertIn("cgroup", output)

    def test_root_flag_reexecs_through_sudo(self) -> None:
        calls: list[list[str]] = []

        def fake_call(command: list[str]) -> int:
            calls.append(command)
            return 0

        buffer = io.StringIO()
        with (
            patch.object(sys, "argv", ["lxperun", "clean", "--apply", "--root"]),
            patch.object(os, "geteuid", return_value=1000),
            patch("lxperun.cli.subprocess.call", side_effect=fake_call),
            redirect_stdout(buffer),
        ):
            with self.assertRaises(SystemExit) as caught:
                main()

        self.assertEqual(len(calls), 1)
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(calls[0][:4], ["sudo", "-E", sys.executable, "-m"])
        self.assertIn("lxperun.cli", calls[0])
        self.assertIn("clean", calls[0])
        self.assertIn("--apply", calls[0])
        self.assertNotIn("--root", calls[0])


if __name__ == "__main__":
    unittest.main()
