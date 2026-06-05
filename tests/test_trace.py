from pathlib import Path
import tempfile
import unittest

from lxperun.trace import trace_command, trace_report


class TraceTest(unittest.TestCase):
    def test_trace_report_uses_tool_availability(self) -> None:
        def fake_which(name: str) -> str | None:
            mapping = {
                "strace": "/usr/bin/strace",
                "perf": None,
                "ltrace": None,
                "gdb": "/usr/bin/gdb",
                "coredumpctl": "/usr/bin/coredumpctl",
            }
            return mapping.get(name)

        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "sys" / "kernel").mkdir(parents=True)
            (proc / "sys" / "kernel" / "perf_event_paranoid").write_text("2\n", encoding="utf-8")

            report = trace_report(proc=proc, which_fn=fake_which)

            self.assertTrue(report.ready)
            self.assertEqual(report.perf_event_paranoid, 2)
            tools = {tool.name: tool for tool in report.tools}
            self.assertTrue(tools["strace"].available)
            self.assertFalse(tools["perf"].available)
            self.assertTrue(tools["gdb"].available)

    def test_trace_command_builds_strace_invocation(self) -> None:
        captured = {}

        def fake_which(name: str) -> str | None:
            return "/usr/bin/strace" if name == "strace" else None

        def fake_run_command(command: list[str], timeout: float) -> tuple[int, str, str]:
            captured["command"] = command
            return (0, "stdout", "")

        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "trace.log"
            trace_path.write_text("openat(AT_FDCWD, \"file\", O_RDONLY) = 3\n", encoding="utf-8")

            def fake_named_tempfile(*args, **kwargs):
                class Handle:
                    name = str(trace_path)

                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        return False

                return Handle()

            # Patch by temporarily replacing the helper on the module.
            import lxperun.trace as trace_module

            original_named_tempfile = trace_module.tempfile.NamedTemporaryFile
            original_unlink = trace_module.os.unlink
            try:
                trace_module.tempfile.NamedTemporaryFile = fake_named_tempfile
                trace_module.os.unlink = lambda path: None
                execution = trace_command(
                    ["echo", "hello"],
                    mode="strace",
                    which_fn=fake_which,
                    run_command_fn=fake_run_command,
                )
            finally:
                trace_module.tempfile.NamedTemporaryFile = original_named_tempfile
                trace_module.os.unlink = original_unlink

        self.assertEqual(captured["command"][:4], ["/usr/bin/strace", "-f", "-tt", "-qq"])
        self.assertEqual(execution.mode, "strace")
        self.assertEqual(execution.exit_code, 0)
        self.assertEqual(execution.trace_lines, ("openat(AT_FDCWD, \"file\", O_RDONLY) = 3",))


if __name__ == "__main__":
    unittest.main()
