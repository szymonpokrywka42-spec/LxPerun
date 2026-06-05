"""Tracing helpers for syscall and performance debugging."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil
import tempfile
from typing import Callable

from .linux import PROC, run_command


@dataclass(frozen=True)
class TraceTool:
    name: str
    available: bool
    detail: str
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TraceReport:
    perf_event_paranoid: int | None
    tools: tuple[TraceTool, ...]
    recommendations: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return any(tool.available for tool in self.tools)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TraceExecution:
    mode: str
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    trace_file: str | None
    trace_lines: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def trace_report(proc: Path = PROC, which_fn: Callable[[str], str | None] = shutil.which) -> TraceReport:
    perf_paranoid = _read_int_optional(proc / "sys" / "kernel" / "perf_event_paranoid")
    tools = (
        _tool("strace", which_fn("strace"), "syscall tracing"),
        _tool("perf", which_fn("perf"), "performance counters and profiling"),
        _tool("ltrace", which_fn("ltrace"), "library call tracing"),
        _tool("gdb", which_fn("gdb"), "native debugging and backtraces"),
        _tool("coredumpctl", which_fn("coredumpctl"), "coredump lookup and backtraces"),
    )
    recommendations = _recommendations(tools, perf_paranoid)
    return TraceReport(perf_event_paranoid=perf_paranoid, tools=tools, recommendations=recommendations)


def trace_command(
    command: list[str],
    mode: str = "strace",
    timeout: float = 30.0,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
) -> TraceExecution:
    if not command:
        raise ValueError("command must not be empty")

    if mode == "strace":
        return _run_strace(command, timeout, which_fn, run_command_fn)
    if mode == "perf":
        return _run_perf_stat(command, timeout, which_fn, run_command_fn)
    raise ValueError(f"unsupported trace mode: {mode}")


def _run_strace(
    command: list[str],
    timeout: float,
    which_fn: Callable[[str], str | None],
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
) -> TraceExecution:
    strace = which_fn("strace")
    if strace is None:
        return TraceExecution(
            mode="strace",
            command=tuple(command),
            exit_code=127,
            stdout="",
            stderr="strace is not installed",
            trace_file=None,
            trace_lines=(),
        )

    with tempfile.NamedTemporaryFile(prefix="lxperun-strace-", suffix=".log", delete=False) as handle:
        trace_path = Path(handle.name)

    trace_command_line = [strace, "-f", "-tt", "-qq", "-s", "128", "-o", str(trace_path), "--", *command]
    exit_code, stdout, stderr = run_command_fn(trace_command_line, timeout)
    trace_lines = _read_trace_lines(trace_path)
    _remove_file(trace_path)
    return TraceExecution(
        mode="strace",
        command=tuple(command),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        trace_file=str(trace_path),
        trace_lines=trace_lines,
    )


def _run_perf_stat(
    command: list[str],
    timeout: float,
    which_fn: Callable[[str], str | None],
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
) -> TraceExecution:
    perf = which_fn("perf")
    if perf is None:
        return TraceExecution(
            mode="perf",
            command=tuple(command),
            exit_code=127,
            stdout="",
            stderr="perf is not installed",
            trace_file=None,
            trace_lines=(),
        )

    exit_code, stdout, stderr = run_command_fn([perf, "stat", "-d", "--", *command], timeout)
    trace_lines = tuple(line for line in stderr.splitlines() if line.strip())
    return TraceExecution(
        mode="perf",
        command=tuple(command),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        trace_file=None,
        trace_lines=trace_lines,
    )


def _tool(name: str, path: str | None, detail: str) -> TraceTool:
    if path is None:
        return TraceTool(
            name=name,
            available=False,
            detail=detail,
            missing=(f"{name} not installed or not in PATH",),
        )
    return TraceTool(name=name, available=True, detail=detail, evidence=(path,))


def _recommendations(tools: tuple[TraceTool, ...], perf_paranoid: int | None) -> tuple[str, ...]:
    recommendations = []
    if any(tool.name == "strace" and tool.available for tool in tools):
        recommendations.append("Use `lxperun trace --mode strace -- <command>` for syscall-level debugging.")
    if any(tool.name == "perf" and tool.available for tool in tools):
        if perf_paranoid is None or perf_paranoid <= 2:
            recommendations.append("Use `lxperun trace --mode perf -- <command>` for CPU and scheduling profiling.")
        else:
            recommendations.append(f"perf is installed but perf_event_paranoid={perf_paranoid}; root may be needed.")
    if any(tool.name == "gdb" and tool.available for tool in tools):
        recommendations.append("Use `gdb` or `coredumpctl gdb` for crashes and native backtraces.")
    return tuple(recommendations)


def _read_int_optional(path: Path) -> int | None:
    try:
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _read_trace_lines(path: Path) -> tuple[str, ...]:
    try:
        return tuple(line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    except OSError:
        return ()


def _remove_file(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
