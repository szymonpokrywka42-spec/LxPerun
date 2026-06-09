from pathlib import Path
import tempfile
import time
import unittest
import os

from lxperun.clean import clean


class CleanTest(unittest.TestCase):
    def test_clean_dry_run_reports_old_coredumps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coredump_dir = Path(tmp)
            old_file = coredump_dir / "core.old"
            new_file = coredump_dir / "core.new"
            old_file.write_bytes(b"old-data")
            new_file.write_bytes(b"new-data")

            old_mtime = time.time() - (10 * 86400)
            new_mtime = time.time() - 60
            os.utime(old_file, (old_mtime, old_mtime))
            os.utime(new_file, (new_mtime, new_mtime))

            report = clean(
                coredump_dir=coredump_dir,
                older_than_days=7,
                dry_run=True,
                which_fn=lambda _: None,
                is_root_fn=lambda: 1000,
            )

            self.assertTrue(report.dry_run)
            self.assertEqual(report.actions[0].state, "planned")
            self.assertEqual(report.actions[0].reclaimed_bytes, len(b"old-data"))
            self.assertIn("Re-run with `--apply`", report.recommendations[0])

    def test_clean_apply_runs_available_tools(self) -> None:
        calls: list[list[str]] = []

        def which_fn(name: str) -> str | None:
            mapping = {
                "flatpak": "/usr/bin/flatpak",
                "dnf": "/usr/bin/dnf",
            }
            return mapping.get(name)

        def run_command_fn(command: list[str], timeout: float) -> tuple[int, str, str]:
            calls.append(command)
            return 0, "ok", ""

        with tempfile.TemporaryDirectory() as tmp:
            coredump_dir = Path(tmp)
            old_file = coredump_dir / "core.old"
            old_file.write_bytes(b"old-data")
            old_mtime = time.time() - (10 * 86400)
            os.utime(old_file, (old_mtime, old_mtime))

            report = clean(
                coredump_dir=coredump_dir,
                older_than_days=7,
                dry_run=False,
                which_fn=which_fn,
                run_command_fn=run_command_fn,
                is_root_fn=lambda: 0,
            )

            self.assertEqual(report.actions[0].state, "done")
            self.assertEqual(report.actions[1].state, "done")
            self.assertEqual(report.actions[2].state, "done")
            self.assertGreaterEqual(len(calls), 2)
            self.assertTrue(any(call[:3] == ["/usr/bin/flatpak", "uninstall", "--system"] for call in calls))
            self.assertTrue(any(call[:2] == ["/usr/bin/dnf", "clean"] for call in calls))


if __name__ == "__main__":
    unittest.main()
