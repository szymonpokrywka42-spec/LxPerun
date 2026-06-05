import unittest

from lxperun.services import service_report


class ServicesTest(unittest.TestCase):
    def test_service_report_parses_systemctl_output(self) -> None:
        def fake_which(name: str) -> str | None:
            return "/usr/bin/systemctl" if name == "systemctl" else None

        def fake_run_command(command: list[str], timeout: float) -> tuple[int, str, str]:
            if command[1] == "list-units":
                return (
                    0,
                    "\n".join(
                        [
                            "foo.service loaded active running Foo Service",
                            "bar.service loaded failed failed Bar Service",
                            "baz.timer loaded active waiting Baz Timer",
                        ]
                    ),
                    "",
                )
            if command[1] == "--failed":
                return (0, "bar.service loaded failed failed Bar Service\n", "")
            raise AssertionError(f"unexpected command: {command}")

        report = service_report(run_command_fn=fake_run_command, which_fn=fake_which)

        self.assertTrue(report.available)
        self.assertEqual(report.total_units, 3)
        self.assertEqual(report.active_units, 2)
        self.assertEqual(report.running_units, 1)
        self.assertEqual(report.failed_count, 1)
        self.assertEqual(report.failed_units[0].name, "bar.service")
        self.assertEqual(report.raw_failed_units, ("bar.service",))

    def test_service_report_handles_missing_systemctl(self) -> None:
        report = service_report(run_command_fn=lambda command, timeout: (0, "", ""), which_fn=lambda name: None)

        self.assertFalse(report.available)
        self.assertEqual(report.total_units, 0)
        self.assertEqual(report.failed_count, 0)


if __name__ == "__main__":
    unittest.main()
