from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lxperun.compatibility import compatibility_report


class CompatibilityTest(unittest.TestCase):
    def test_compatibility_report_marks_legacy_kernel_as_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os_release = root / "etc" / "os-release"
            os_release.parent.mkdir(parents=True)
            os_release.write_text('NAME="TestOS"\nVERSION="1.0"\n', encoding="utf-8")

            proc = root / "proc"
            (proc / "1").mkdir(parents=True)
            (proc / "1" / "cgroup").write_text("0::/init.scope\n", encoding="utf-8")
            (proc / "net").mkdir(parents=True)

            with patch("lxperun.compatibility.platform.release", return_value="4.14.0-legacy"), patch(
                "lxperun.compatibility.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}" if name in {"systemctl", "journalctl", "nft"} else None,
            ):
                report = compatibility_report(root=root)

        self.assertTrue(report.legacy_mode)
        self.assertEqual(report.kernel_version, (4, 14, 0))
        self.assertEqual(report.distro, "TestOS 1.0")
        self.assertFalse(next(check for check in report.checks if check.name == "psi").available)
        self.assertTrue(any("PSI era" in recommendation for recommendation in report.recommendations))


if __name__ == "__main__":
    unittest.main()
