from pathlib import Path
import tempfile
import unittest

from lxperun.doctor import _unique_lines, python_syntax_errors
from lxperun.linux import (
    block_devices,
    cpu_info,
    cpu_times,
    format_bytes,
    memory_info,
    mount_points,
    network_interfaces,
    uptime_seconds,
)


class LinuxHelpersTest(unittest.TestCase):
    def test_uptime_seconds_reads_first_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "uptime").write_text("123.45 678.90\n", encoding="utf-8")

            self.assertEqual(uptime_seconds(proc), 123.45)

    def test_memory_info_parses_kib_as_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "meminfo").write_text(
                "\n".join(
                    [
                        "MemTotal:       1000 kB",
                        "MemFree:         200 kB",
                        "MemAvailable:    700 kB",
                        "Buffers:          10 kB",
                        "Cached:           90 kB",
                        "SwapTotal:       500 kB",
                        "SwapFree:        250 kB",
                    ]
                ),
                encoding="utf-8",
            )

            info = memory_info(proc)

            self.assertEqual(info.total, 1000 * 1024)
            self.assertEqual(info.available, 700 * 1024)
            self.assertEqual(info.used, 300 * 1024)
            self.assertEqual(info.used_percent, 30.0)

    def test_cpu_times_pads_missing_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "stat").write_text("cpu  1 2 3 4\n", encoding="utf-8")

            times = cpu_times(proc)

            self.assertEqual(times.user, 1)
            self.assertEqual(times.nice, 2)
            self.assertEqual(times.system, 3)
            self.assertEqual(times.idle, 4)
            self.assertEqual(times.total, 10)

    def test_network_interfaces_reads_sysfs_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sys_class_net = Path(tmp)
            iface = sys_class_net / "eth0"
            stats = iface / "statistics"
            stats.mkdir(parents=True)
            (iface / "address").write_text("aa:bb:cc:dd:ee:ff\n", encoding="utf-8")
            (iface / "mtu").write_text("1500\n", encoding="utf-8")
            (iface / "operstate").write_text("up\n", encoding="utf-8")
            (stats / "rx_bytes").write_text("1024\n", encoding="utf-8")
            (stats / "tx_bytes").write_text("2048\n", encoding="utf-8")

            interfaces = network_interfaces(sys_class_net)

            self.assertEqual(len(interfaces), 1)
            self.assertEqual(interfaces[0].name, "eth0")
            self.assertEqual(interfaces[0].mac, "aa:bb:cc:dd:ee:ff")
            self.assertEqual(interfaces[0].mtu, 1500)
            self.assertEqual(interfaces[0].carrier, None)
            self.assertEqual(interfaces[0].operstate, "up")
            self.assertEqual(interfaces[0].rx_bytes, 1024)
            self.assertEqual(interfaces[0].tx_bytes, 2048)

    def test_format_bytes_uses_binary_units(self) -> None:
        self.assertEqual(format_bytes(1536), "1.5 KiB")

    def test_cpu_info_parses_first_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "cpuinfo").write_text(
                "\n".join(
                    [
                        "processor   : 0",
                        "vendor_id   : GenuineTest",
                        "model name  : Test CPU",
                        "cpu MHz     : 3200.000",
                        "flags       : fpu sse",
                        "",
                        "processor   : 1",
                    ]
                ),
                encoding="utf-8",
            )

            info = cpu_info(proc)

            self.assertEqual(info.logical_cpus, 2)
            self.assertEqual(info.vendor_id, "GenuineTest")
            self.assertEqual(info.model_name, "Test CPU")
            self.assertEqual(info.cpu_mhz, 3200.0)
            self.assertEqual(info.flags, ("fpu", "sse"))

    def test_block_devices_reads_sysfs_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sys_block = Path(tmp)
            device = sys_block / "sda"
            queue = device / "queue"
            block_model = device / "device"
            queue.mkdir(parents=True)
            block_model.mkdir()
            (device / "size").write_text("2048\n", encoding="utf-8")
            (device / "removable").write_text("0\n", encoding="utf-8")
            (queue / "rotational").write_text("1\n", encoding="utf-8")
            (block_model / "model").write_text("Disk Model\n", encoding="utf-8")
            (block_model / "vendor").write_text("Vendor\n", encoding="utf-8")

            devices = block_devices(sys_block)

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].name, "sda")
            self.assertEqual(devices[0].size, 2048 * 512)
            self.assertFalse(devices[0].removable)
            self.assertTrue(devices[0].rotational)

    def test_mount_points_parses_mountinfo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            self_dir = proc / "self"
            self_dir.mkdir()
            (self_dir / "mountinfo").write_text(
                "24 22 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
                encoding="utf-8",
            )

            mounts = mount_points(proc)

            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0].mount_point, "/")
            self.assertEqual(mounts[0].filesystem, "ext4")
            self.assertEqual(mounts[0].device, "/dev/sda1")

    def test_python_syntax_errors_reports_invalid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text("def nope(:\n", encoding="utf-8")

            issues = python_syntax_errors(root)

            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0].severity, "error")
            self.assertIsNotNone(issues[0].suggestion)

    def test_unique_lines_removes_duplicates_without_reordering(self) -> None:
        self.assertEqual(_unique_lines(["a", "b", "a", "  ", "c"]), ("a", "b", "c"))


if __name__ == "__main__":
    unittest.main()
