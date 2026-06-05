from pathlib import Path
import tempfile
import unittest

from lxperun.processes import inspect_process, process_report, top_by_memory, zombie_processes


class ProcessesTest(unittest.TestCase):
    def test_inspect_process_reads_proc_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            process = proc / "123"
            fd = process / "fd"
            fd.mkdir(parents=True)
            (fd / "0").touch()
            (fd / "1").touch()
            (process / "status").write_text(
                "\n".join(
                    [
                        "Name:\tpython",
                        "State:\tS (sleeping)",
                        "PPid:\t1",
                        "Uid:\t1000\t1000\t1000\t1000",
                        "Threads:\t4",
                        "VmRSS:\t2048 kB",
                        "VmSize:\t4096 kB",
                        "voluntary_ctxt_switches:\t7",
                        "nonvoluntary_ctxt_switches:\t3",
                    ]
                ),
                encoding="utf-8",
            )
            (process / "cmdline").write_bytes(b"python\0-m\0lxperun.cli\0")

            info = inspect_process(123, proc)

            self.assertTrue(info.readable)
            self.assertEqual(info.pid, 123)
            self.assertEqual(info.ppid, 1)
            self.assertEqual(info.uid, 1000)
            self.assertEqual(info.name, "python")
            self.assertEqual(info.threads, 4)
            self.assertEqual(info.vm_rss, 2048 * 1024)
            self.assertEqual(info.vm_size, 4096 * 1024)
            self.assertEqual(info.fd_count, 2)
            self.assertEqual(info.cmdline, ("python", "-m", "lxperun.cli"))

    def test_process_report_filters_numeric_dirs_and_sorts_top_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "self").mkdir()
            self._write_process(proc, 2, "small", "S (sleeping)", 128)
            self._write_process(proc, 1, "big", "R (running)", 4096)

            report = process_report(proc)
            top = top_by_memory(report, limit=1)

            self.assertEqual(report.total, 2)
            self.assertEqual(report.unreadable, 0)
            self.assertEqual(top[0].pid, 1)

    def test_zombie_processes_detects_state_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            self._write_process(proc, 5, "zombie", "Z (zombie)", 0)

            zombies = zombie_processes(process_report(proc))

            self.assertEqual(len(zombies), 1)
            self.assertEqual(zombies[0].pid, 5)

    def _write_process(self, proc: Path, pid: int, name: str, state: str, rss_kib: int) -> None:
        process = proc / str(pid)
        (process / "fd").mkdir(parents=True)
        (process / "status").write_text(
            "\n".join(
                [
                    f"Name:\t{name}",
                    f"State:\t{state}",
                    "PPid:\t0",
                    "Uid:\t1000\t1000\t1000\t1000",
                    "Threads:\t1",
                    f"VmRSS:\t{rss_kib} kB",
                    f"VmSize:\t{rss_kib * 2} kB",
                ]
            ),
            encoding="utf-8",
        )
        (process / "cmdline").write_bytes(f"{name}\0".encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
