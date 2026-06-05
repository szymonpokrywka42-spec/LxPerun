from pathlib import Path
import tempfile
import unittest

from lxperun.hardware import hardware_report


class HardwareTest(unittest.TestCase):
    def test_hardware_report_reads_sysfs_like_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_pci = root / "sys" / "bus" / "pci" / "devices"
            pci = sys_pci / "0000:00:1f.6"
            pci.mkdir(parents=True)
            (pci / "vendor").write_text("0x8086\n", encoding="utf-8")
            (pci / "device").write_text("0x15be\n", encoding="utf-8")
            (pci / "class").write_text("0x020000\n", encoding="utf-8")
            (pci / "subsystem_vendor").write_text("0x1043\n", encoding="utf-8")
            (pci / "subsystem_device").write_text("0x8694\n", encoding="utf-8")

            sys_usb = root / "sys" / "bus" / "usb" / "devices"
            usb = sys_usb / "1-1"
            usb.mkdir(parents=True)
            (usb / "idVendor").write_text("1234\n", encoding="utf-8")
            (usb / "idProduct").write_text("abcd\n", encoding="utf-8")
            (usb / "manufacturer").write_text("Acme\n", encoding="utf-8")
            (usb / "product").write_text("Keyboard\n", encoding="utf-8")
            (usb / "serial").write_text("SN123\n", encoding="utf-8")

            sys_hwmon = root / "sys" / "class" / "hwmon" / "hwmon0"
            sys_hwmon.mkdir(parents=True)
            (sys_hwmon / "name").write_text("coretemp\n", encoding="utf-8")
            (sys_hwmon / "temp1_input").write_text("42000\n", encoding="utf-8")
            (sys_hwmon / "temp1_label").write_text("Package id 0\n", encoding="utf-8")

            sys_numa = root / "sys" / "devices" / "system" / "node" / "node0"
            sys_numa.mkdir(parents=True)
            (sys_numa / "cpulist").write_text("0-3\n", encoding="utf-8")
            (sys_numa / "meminfo").write_text("Node 0 MemTotal: 1024 kB\nNode 0 MemFree: 512 kB\n", encoding="utf-8")

            report = hardware_report(
                sys_pci=sys_pci,
                sys_usb=sys_usb,
                sys_hwmon=root / "sys" / "class" / "hwmon",
                sys_numa=root / "sys" / "devices" / "system" / "node",
            )

            self.assertEqual(report.pci_count, 1)
            self.assertEqual(report.usb_count, 1)
            self.assertEqual(report.sensor_count, 1)
            self.assertEqual(report.numa_count, 1)
            self.assertEqual(report.pci_devices[0].bdf, "0000:00:1f.6")
            self.assertEqual(report.usb_devices[0].product, "Keyboard")
            self.assertEqual(report.sensors[0].value, 42000)
            self.assertEqual(report.numa_nodes[0].mem_total_kb, 1024)


if __name__ == "__main__":
    unittest.main()
