"""Crash and coredump inspection helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
from typing import Callable

from .linux import PROC, run_command


@dataclass(frozen=True)
class CrashTool:
    name: str
    available: bool
    detail: str
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CrashReport:
    tools: tuple[CrashTool, ...]
    coredump_count: int
    coredump_summaries: tuple[str, ...]
    latest_info: str | None
    debug_symbol_paths: tuple[str, ...]
    recommendations: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return any(tool.available for tool in self.tools)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def crash_report(
    proc: Path = PROC,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    limit: int = 8,
    include_latest: bool = False,
) -> CrashReport:
    tools = (
        _tool("coredumpctl", which_fn("coredumpctl"), "querying coredumps and metadata"),
        _tool("gdb", which_fn("gdb"), "native backtraces and post-mortem debugging"),
        _tool("eu-stack", which_fn("eu-stack"), "elfutils stack walking"),
    )
    debug_symbol_paths = _debug_symbol_paths(proc)
    coredump_summaries = _load_coredump_summaries(run_command_fn, which_fn)
    latest_info = _load_latest_coredump_info(run_command_fn, which_fn) if include_latest else None
    recommendations = _recommendations(tools, debug_symbol_paths, coredump_summaries)
    return CrashReport(
        tools=tools,
        coredump_count=len(coredump_summaries),
        coredump_summaries=coredump_summaries[:limit],
        latest_info=latest_info,
        debug_symbol_paths=debug_symbol_paths,
        recommendations=recommendations,
    )


def _load_coredump_summaries(
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
    which_fn: Callable[[str], str | None],
) -> tuple[str, ...]:
    coredumpctl = which_fn("coredumpctl")
    if coredumpctl is None:
        return ()

    code, stdout, stderr = run_command_fn([coredumpctl, "--no-pager", "--no-legend", "list"], 5.0)
    if code not in {0, 1}:
        return ()
    entries = []
    for line in stdout.splitlines():
        normalized = line.strip()
        if not normalized:
            continue
        if normalized.lower().startswith("no coredumps"):
            return ()
        if normalized.upper().startswith("TIME "):
            continue
        entries.append(normalized)
    return tuple(entries)


def _load_latest_coredump_info(
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
    which_fn: Callable[[str], str | None],
) -> str | None:
    coredumpctl = which_fn("coredumpctl")
    if coredumpctl is None:
        return None

    code, stdout, stderr = run_command_fn([coredumpctl, "--no-pager", "info"], 8.0)
    if code not in {0, 1}:
        return None
    text = stdout.strip() or stderr.strip()
    return text or None


def _debug_symbol_paths(proc: Path) -> tuple[str, ...]:
    candidates = (
        proc / "usr" / "lib" / "debug",
        proc / "usr" / "lib" / "debug" / "usr" / "lib" / "modules",
        proc / "usr" / "lib64" / "debug",
    )
    return tuple(str(path) for path in candidates if path.exists())


def _recommendations(
    tools: tuple[CrashTool, ...],
    debug_symbol_paths: tuple[str, ...],
    coredump_summaries: tuple[str, ...],
) -> tuple[str, ...]:
    recommendations = []
    if any(tool.name == "coredumpctl" and tool.available for tool in tools):
        recommendations.append("Use `lxperun crash --latest` to inspect the newest coredump metadata.")
    if any(tool.name == "gdb" and tool.available for tool in tools):
        recommendations.append("Use `coredumpctl gdb` or `gdb <binary> <core>` for backtraces.")
    if not debug_symbol_paths:
        recommendations.append("Install debug symbols for native stack traces to be meaningful.")
    if coredump_summaries:
        recommendations.append("Recent coredumps were found; inspect them before the next reboot clears context.")
    return tuple(recommendations)


def _tool(name: str, path: str | None, detail: str) -> CrashTool:
    if path is None:
        return CrashTool(
            name=name,
            available=False,
            detail=detail,
            missing=(f"{name} not installed or not in PATH",),
        )
    return CrashTool(name=name, available=True, detail=detail, evidence=(path,))
