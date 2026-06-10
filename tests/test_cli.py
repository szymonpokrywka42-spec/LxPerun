import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from lxperun.cli import _print_banner, _render_hardware, main


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

    def test_help_compatibility_mentions_backward_support(self) -> None:
        buffer = io.StringIO()
        with patch.object(sys, "argv", ["lxperun", "help", "compatibility"]), redirect_stdout(buffer):
            main()

        output = buffer.getvalue()
        self.assertIn("compatibility", output)
        self.assertIn("backward", output.lower())

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
        self.assertIn("--raw", output)

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

    def test_render_hardware_uses_usb_fields_without_crashing(self) -> None:
        report = SimpleNamespace(
            pci_count=0,
            usb_count=1,
            sensor_count=0,
            numa_count=1,
            pci_devices=(),
            usb_devices=(
                SimpleNamespace(
                    path="1-1",
                    busnum=1,
                    devnum=2,
                    id_vendor="1234",
                    id_product="abcd",
                    manufacturer="Acme",
                    product="Keyboard",
                ),
            ),
            sensors=(),
            numa_nodes=(SimpleNamespace(name="node0", cpulist="0-3", mem_total_kb=1024, mem_free_kb=512),),
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            _render_hardware(report, limit=12, raw=False, color_enabled=False)

        output = buffer.getvalue()
        self.assertIn("USB:", output)
        self.assertIn("1:2", output)
        self.assertIn("1234:abcd", output)
        self.assertIn("node0", output)

    def test_banner_mentions_name_and_tagline(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            _print_banner(color_enabled=False)

        output = buffer.getvalue()
        self.assertIn("LxPerun", output)
        self.assertIn("Linux diagnostics, made readable.", output)
        self.assertIn("╭", output)
        self.assertIn("╰", output)


if __name__ == "__main__":
    unittest.main()
