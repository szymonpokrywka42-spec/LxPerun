from pathlib import Path
import tempfile
import unittest

from lxperun.linux import MountPoint
from lxperun.storage import storage_report


class StorageTest(unittest.TestCase):
    def test_storage_report_reads_mounts_and_devices(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount_dir = root / "mnt"
            data_dir = root / "data"
            mount_dir.mkdir()
            data_dir.mkdir()

            sys_block = root / "sys" / "block"
            device = sys_block / "sda"
            queue = device / "queue"
            device_dir = device / "device"
            queue.mkdir(parents=True)
            device_dir.mkdir()
            (device / "size").write_text("2048\n", encoding="utf-8")
            (device / "removable").write_text("0\n", encoding="utf-8")
            (device / "ro").write_text("0\n", encoding="utf-8")
            (queue / "rotational").write_text("1\n", encoding="utf-8")
            (queue / "logical_block_size").write_text("512\n", encoding="utf-8")
            (queue / "physical_block_size").write_text("4096\n", encoding="utf-8")
            (queue / "scheduler").write_text("[mq-deadline] none\n", encoding="utf-8")
            (device_dir / "model").write_text("Disk Model\n", encoding="utf-8")
            (device_dir / "vendor").write_text("Vendor\n", encoding="utf-8")

            diskstats = root / "proc" / "diskstats"
            diskstats.parent.mkdir(parents=True)
            diskstats.write_text(
                "   8       0 sda 1 2 3 4 5 6 7 8 0 9 10\n",
                encoding="utf-8",
            )

            def fake_mount_points() -> tuple[MountPoint, ...]:
                return (
                    MountPoint(device="/dev/sda1", mount_point=str(mount_dir), filesystem="ext4", options=("rw",)),
                    MountPoint(device="/dev/sda2", mount_point=str(data_dir), filesystem="xfs", options=("rw",)),
                )

            report = storage_report(
                proc_mounts=fake_mount_points,
                statvfs_fn=lambda path: self._fake_statvfs(path, mount_dir, data_dir),
                sys_block=sys_block,
                diskstats_path=diskstats,
            )

            self.assertEqual(report.mount_count, 2)
            self.assertEqual(report.device_count, 1)
            self.assertEqual(report.mounts[0].filesystem, "ext4")
            self.assertEqual(report.mounts[0].total, 1000)
            self.assertEqual(report.devices[0].name, "sda")
            self.assertEqual(report.devices[0].model, "Disk Model")
            self.assertFalse(report.devices[0].read_only)
            self.assertEqual(report.devices[0].io.reads_completed, 1)
            self.assertEqual(report.devices[0].io.writes_completed, 5)

    def _fake_statvfs(self, path: str, mount_dir: Path, data_dir: Path):
        target = str(path)
        if target == str(mount_dir):
            return self._statvfs_result(100, 40, 10)
        if target == str(data_dir):
            return self._statvfs_result(200, 50, 10)
        raise FileNotFoundError(target)

    def _statvfs_result(self, blocks: int, bavail: int, frsize: int):
        class Result:
            pass

        result = Result()
        result.f_blocks = blocks
        result.f_bavail = bavail
        result.f_frsize = frsize
        return result


if __name__ == "__main__":
    unittest.main()
