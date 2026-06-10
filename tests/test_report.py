from types import SimpleNamespace
import unittest

from lxperun.report import PerunReport, report_to_markdown


class ReportTest(unittest.TestCase):
    def test_report_to_markdown_includes_all_sections(self) -> None:
        report = PerunReport(
            generated_at="2026-06-05T12:00:00+00:00",
            snapshot=SimpleNamespace(
                identity=SimpleNamespace(hostname="fedora", kernel="7.0", distribution="Fedora"),
                uptime=123.4,
                load_average=(1.0, 2.0, 3.0),
            ),
            capabilities=SimpleNamespace(
                is_root=False,
                effective_uid=1000,
                probes=(SimpleNamespace(name="procfs", available=True, detail="proc",),),
            ),
            security=SimpleNamespace(
                is_root=False,
                effective_uid=1000,
                signals=(),
                findings=(),
                recommendations=(),
            ),
            containers=SimpleNamespace(
                is_root=False,
                effective_uid=1000,
                signals=(),
                findings=(),
                recommendations=(),
            ),
            firewall=SimpleNamespace(backends=(), mappings=(), recommendations=()),
            performance=SimpleNamespace(pressure=(), interrupts=(), softirqs=(), slabinfo=(), recommendations=()),
            rings=SimpleNamespace(layers=(SimpleNamespace(ring="3", name="user space", available=True),)),
            doctor=SimpleNamespace(issues=()),
            processes=SimpleNamespace(
                total=1,
                unreadable=0,
                processes=(SimpleNamespace(pid=1, user="root", cmdline=("init",), name="init", state="S"),),
            ),
            services=SimpleNamespace(total_units=1, failed_count=0, failed_units=(), raw_failed_units=()),
            storage=SimpleNamespace(mount_count=1, device_count=1, mounts=(SimpleNamespace(mount_point="/", filesystem="btrfs", used_percent=80.0),)),
            hardware=SimpleNamespace(pci_count=1, usb_count=0, sensor_count=0, numa_count=0, pci_devices=(SimpleNamespace(bdf="0000:00:1f.6", vendor_id="8086", device_id="15be"),)),
            trace=SimpleNamespace(ready=True, perf_event_paranoid=2, recommendations=("Use trace",)),
            crash=SimpleNamespace(ready=True, coredump_count=2, recommendations=("Use crash",), latest_info=None),
        )

        markdown = report_to_markdown(report, limit=1)

        self.assertIn("# LxPerun Report", markdown)
        self.assertIn("## System", markdown)
        self.assertIn("## Crash", markdown)
        self.assertIn("Fedora", markdown)
        self.assertIn("0000:00:1f.6", markdown)

    def test_report_to_markdown_includes_latest_crash_block(self) -> None:
        report = PerunReport(
            generated_at="2026-06-05T12:00:00+00:00",
            snapshot=SimpleNamespace(identity=SimpleNamespace(hostname="fedora", kernel="7.0", distribution="Fedora"), uptime=1.0, load_average=(0.1, 0.2, 0.3)),
            capabilities=SimpleNamespace(is_root=False, effective_uid=1000, probes=()),
            security=SimpleNamespace(is_root=False, effective_uid=1000, signals=(), findings=(), recommendations=()),
            containers=SimpleNamespace(is_root=False, effective_uid=1000, signals=(), findings=(), recommendations=()),
            firewall=SimpleNamespace(backends=(), mappings=(), recommendations=()),
            performance=SimpleNamespace(pressure=(), interrupts=(), softirqs=(), slabinfo=(), recommendations=()),
            rings=SimpleNamespace(layers=()),
            doctor=SimpleNamespace(issues=()),
            processes=SimpleNamespace(total=0, unreadable=0, processes=()),
            services=SimpleNamespace(total_units=0, failed_count=0, failed_units=(), raw_failed_units=()),
            storage=SimpleNamespace(mount_count=0, device_count=0, mounts=()),
            hardware=SimpleNamespace(pci_count=0, usb_count=0, sensor_count=0, numa_count=0, pci_devices=()),
            trace=SimpleNamespace(ready=False, perf_event_paranoid=None, recommendations=()),
            crash=SimpleNamespace(ready=True, coredump_count=1, recommendations=(), latest_info="line 1\nline 2"),
        )

        markdown = report_to_markdown(report, limit=1)

        self.assertIn("### Latest", markdown)
        self.assertIn("line 1", markdown)


if __name__ == "__main__":
    unittest.main()
