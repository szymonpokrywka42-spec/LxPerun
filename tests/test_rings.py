from pathlib import Path
import tempfile
import unittest

from lxperun.rings import access_map


class RingsTest(unittest.TestCase):
    def test_access_map_detects_user_space_and_firmware_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proc" / "self").mkdir(parents=True)
            (root / "proc" / "cpuinfo").write_text("flags : fpu hypervisor\n", encoding="utf-8")
            (root / "proc" / "meminfo").write_text("MemTotal: 1 kB\n", encoding="utf-8")
            (root / "proc" / "modules").write_text("", encoding="utf-8")
            (root / "proc" / "sys" / "kernel").mkdir(parents=True)
            (root / "proc" / "sys" / "kernel" / "tainted").write_text("0\n", encoding="utf-8")
            (root / "sys" / "class" / "net").mkdir(parents=True)
            (root / "sys" / "module").mkdir(parents=True)
            (root / "sys" / "kernel").mkdir(parents=True)
            (root / "sys" / "firmware" / "efi").mkdir(parents=True)
            (root / "sys" / "class" / "dmi" / "id").mkdir(parents=True)

            report = access_map(root)
            layers = {layer.ring: layer for layer in report.layers}

            self.assertTrue(layers["3"].available)
            self.assertTrue(layers["0"].available)
            self.assertTrue(layers["-1"].available)
            self.assertTrue(layers["-2"].available)
            self.assertFalse(layers["-3"].available)


if __name__ == "__main__":
    unittest.main()
