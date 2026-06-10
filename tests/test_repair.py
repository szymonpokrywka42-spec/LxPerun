from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lxperun.clean import CleanAction, CleanReport
from lxperun.doctor import DiagnosticIssue, DoctorReport
from lxperun.repair import repair


class RepairTest(unittest.TestCase):
    def test_repair_dry_run_reports_planned_actions(self) -> None:
        clean_report = CleanReport(
            dry_run=True,
            actions=(CleanAction(name="coredumps", state="planned", detail="Would remove old coredumps."),),
            total_reclaimed_bytes=1024,
            recommendations=("Re-run with `--apply` to execute the cleanup steps.",),
        )
        before = DoctorReport(
            issues=(
                DiagnosticIssue(severity="error", source="systemd", message="Failed unit: demo.service"),
                DiagnosticIssue(severity="warning", source="kernel", message="Kernel is tainted: 512"),
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch("lxperun.repair.clean", return_value=clean_report),
                patch("lxperun.repair.diagnose", return_value=before),
            ):
                report = repair(project_root=root, dry_run=True, which_fn=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None)

        self.assertTrue(report.dry_run)
        self.assertEqual(report.issues_before_count, 2)
        self.assertEqual(report.issues_after_count, 0)
        self.assertEqual(report.reset_failed.state, "planned")
        self.assertIn("Re-run with `--apply`", report.recommendations[0])

    def test_repair_apply_resets_failed_units(self) -> None:
        clean_report = CleanReport(
            dry_run=False,
            actions=(CleanAction(name="coredumps", state="done", detail="Removed old coredumps.", reclaimed_bytes=1024),),
            total_reclaimed_bytes=1024,
            recommendations=(),
        )
        before = DoctorReport(
            issues=(DiagnosticIssue(severity="error", source="systemd", message="Failed unit: demo.service"),)
        )
        after = DoctorReport(issues=())
        calls: list[list[str]] = []

        def run_command_fn(command: list[str], timeout: float) -> tuple[int, str, str]:
            calls.append(command)
            return 0, "reset", ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch("lxperun.repair.clean", return_value=clean_report),
                patch("lxperun.repair.diagnose", side_effect=[before, after]),
            ):
                report = repair(
                    project_root=root,
                    dry_run=False,
                    which_fn=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None,
                    run_command_fn=run_command_fn,
                    is_root_fn=lambda: 0,
                )

        self.assertEqual(report.reset_failed.state, "done")
        self.assertEqual(report.issues_before_count, 1)
        self.assertEqual(report.issues_after_count, 0)
        self.assertEqual(calls[0], ["/usr/bin/systemctl", "reset-failed"])


if __name__ == "__main__":
    unittest.main()
