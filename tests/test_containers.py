from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lxperun.containers import container_report


class ContainersTest(unittest.TestCase):
    def test_container_report_filters_security_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            (proc / "1").mkdir(parents=True)
            (proc / "1" / "cgroup").write_text("0::/docker/1234\n", encoding="utf-8")
            ns_dir = proc / "1" / "ns"
            ns_dir.mkdir()
            (ns_dir / "pid").symlink_to("pid:[4026531836]")
            (ns_dir / "net").symlink_to("net:[4026531837]")
            (ns_dir / "mnt").symlink_to("mnt:[4026531838]")
            self_ns_dir = proc / "self" / "ns"
            self_ns_dir.mkdir(parents=True)
            for namespace_name in ("pid", "net", "mnt"):
                (self_ns_dir / namespace_name).symlink_to(f"{namespace_name}:[4026532448]")

            report = container_report(network_report_obj=SimpleNamespace(listening_sockets=()))

            signal_names = {signal.name for signal in report.signals}
            self.assertIn("container", signal_names)
            self.assertIn("namespaces", signal_names)


if __name__ == "__main__":
    unittest.main()
