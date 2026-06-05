from pathlib import Path
import tempfile
import unittest

from lxperun.capabilities import capability_report


class CapabilitiesTest(unittest.TestCase):
    def test_capability_report_detects_virtual_rootfs_features(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proc" / "self").mkdir(parents=True)
            (root / "proc" / "cpuinfo").write_text("", encoding="utf-8")
            (root / "proc" / "meminfo").write_text("", encoding="utf-8")
            (root / "proc" / "sys" / "kernel").mkdir(parents=True)
            (root / "proc" / "sys" / "kernel" / "perf_event_paranoid").write_text("2\n", encoding="utf-8")
            (root / "sys" / "class").mkdir(parents=True)
            (root / "sys" / "devices").mkdir(parents=True)
            (root / "sys" / "module").mkdir(parents=True)
            (root / "sys" / "firmware" / "efi" / "efivars").mkdir(parents=True)
            (root / "dev").mkdir()
            (root / "dev" / "tpmrm0").write_text("", encoding="utf-8")
            (root / "usr" / "lib" / "debug").mkdir(parents=True)

            report = capability_report(root)
            probes = {probe.name: probe for probe in report.probes}

            self.assertTrue(probes["procfs"].available)
            self.assertTrue(probes["sysfs"].available)
            self.assertTrue(probes["efi"].available)
            self.assertTrue(probes["tpm"].available)
            self.assertTrue(probes["debug-symbols"].available)
            self.assertFalse(probes["root"].available)


if __name__ == "__main__":
    unittest.main()
