from pathlib import Path
import tempfile
import unittest

from lxperun.performance import performance_report


class PerformanceTest(unittest.TestCase):
    def test_performance_report_parses_pressure_interrupts_and_slabinfo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            pressure = proc / "pressure"
            pressure.mkdir(parents=True)
            (pressure / "cpu").write_text("some avg10=0.10 avg60=0.20 avg300=0.30 total=11\nfull avg10=0.01 avg60=0.02 avg300=0.03 total=4\n", encoding="utf-8")
            (pressure / "memory").write_text("some avg10=0.00 avg60=0.01 avg300=0.02 total=3\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", encoding="utf-8")
            (pressure / "io").write_text("some avg10=0.20 avg60=0.30 avg300=0.40 total=9\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=5\n", encoding="utf-8")
            (proc / "interrupts").write_text(
                "\n".join(
                    [
                        "           CPU0       CPU1",
                        "  0:          1          2   IO-APIC   2-edge      timer",
                        "  1:          3          4   IO-APIC   1-edge      keyboard",
                    ]
                ),
                encoding="utf-8",
            )
            (proc / "softirqs").write_text(
                "\n".join(
                    [
                        "                    CPU0       CPU1",
                        "          HI:          1          0",
                        "       TIMER:          5          6",
                    ]
                ),
                encoding="utf-8",
            )
            (proc / "slabinfo").write_text(
                "\n".join(
                    [
                        "slabinfo - version: 2.1",
                        "# name <active_objs> <num_objs> <objsize>",
                        "dentry 10 20 192",
                        "inode_cache 3 6 1024",
                    ]
                ),
                encoding="utf-8",
            )

            report = performance_report(root=root, max_slab_caches=1)

            self.assertEqual(len(report.pressure), 3)
            self.assertEqual(report.interrupts[0].cpu, "CPU1")
            self.assertEqual(report.slabinfo[0].name, "inode_cache")
            self.assertFalse(report.recommendations)


if __name__ == "__main__":
    unittest.main()
