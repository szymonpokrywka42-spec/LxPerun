from pathlib import Path
import tempfile
import unittest

from lxperun.crash import crash_report


class CrashTest(unittest.TestCase):
    def test_crash_report_collects_tools_and_coredumps(self) -> None:
        def fake_which(name: str) -> str | None:
            mapping = {
                "coredumpctl": "/usr/bin/coredumpctl",
                "gdb": "/usr/bin/gdb",
                "eu-stack": None,
            }
            return mapping.get(name)

        commands: list[list[str]] = []

        def fake_run_command(command: list[str], timeout: float) -> tuple[int, str, str]:
            commands.append(command)
            if command[1:] == ["--no-pager", "--no-legend", "list"]:
                return (
                    0,
                    "\n".join(
                        [
                            "TIME                            PID   UID  GID SIG     COREFILE EXE",
                            "Fri 2026-06-05 12:00:00 CEST 1234 1000 1000 11      present  /usr/bin/app",
                        ]
                    ),
                    "",
                )
            if command[1:] == ["--no-pager", "info"]:
                return (0, "Coredump info line 1\nCoredump info line 2\n", "")
            raise AssertionError(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            debug_dir = proc / "usr" / "lib" / "debug"
            debug_dir.mkdir(parents=True)

            report = crash_report(
                proc=proc,
                which_fn=fake_which,
                run_command_fn=fake_run_command,
                limit=4,
                include_latest=True,
            )

            self.assertTrue(report.ready)
            self.assertEqual(report.coredump_count, 1)
            self.assertEqual(report.coredump_summaries[0].endswith("/usr/bin/app"), True)
            self.assertEqual(report.latest_info, "Coredump info line 1\nCoredump info line 2")
            self.assertIn("/usr/bin/coredumpctl", commands[0][0])

    def test_crash_report_handles_missing_tools(self) -> None:
        report = crash_report(which_fn=lambda name: None)

        self.assertFalse(report.ready)
        self.assertEqual(report.coredump_count, 0)
        self.assertEqual(report.recommendations[0], "Install debug symbols for native stack traces to be meaningful.")


if __name__ == "__main__":
    unittest.main()
