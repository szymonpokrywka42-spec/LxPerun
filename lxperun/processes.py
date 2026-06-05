"""Process inspection helpers based on /proc."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import pwd


PROC = Path("/proc")


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    uid: int | None
    user: str | None
    name: str | None
    state: str | None
    threads: int | None
    vm_rss: int | None
    vm_size: int | None
    voluntary_ctxt_switches: int | None
    nonvoluntary_ctxt_switches: int | None
    fd_count: int | None
    exe: str | None
    cwd: str | None
    cmdline: tuple[str, ...]
    readable: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProcessReport:
    processes: tuple[ProcessInfo, ...]
    unreadable: int

    @property
    def total(self) -> int:
        return len(self.processes)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def process_report(proc: Path = PROC) -> ProcessReport:
    processes = []
    unreadable = 0
    for entry in sorted(proc.iterdir(), key=_pid_sort_key):
        if not entry.name.isdigit():
            continue
        info = inspect_process(int(entry.name), proc)
        if not info.readable:
            unreadable += 1
        processes.append(info)
    return ProcessReport(processes=tuple(processes), unreadable=unreadable)


def inspect_process(pid: int, proc: Path = PROC) -> ProcessInfo:
    process_path = proc / str(pid)
    try:
        status = _parse_status(process_path / "status")
        cmdline = _read_cmdline(process_path / "cmdline")
        uid = _first_int(status.get("Uid"))
        return ProcessInfo(
            pid=pid,
            ppid=_int_or_none(status.get("PPid")),
            uid=uid,
            user=_username(uid),
            name=status.get("Name"),
            state=status.get("State"),
            threads=_int_or_none(status.get("Threads")),
            vm_rss=_kib_field(status.get("VmRSS")),
            vm_size=_kib_field(status.get("VmSize")),
            voluntary_ctxt_switches=_int_or_none(status.get("voluntary_ctxt_switches")),
            nonvoluntary_ctxt_switches=_int_or_none(status.get("nonvoluntary_ctxt_switches")),
            fd_count=_fd_count(process_path / "fd"),
            exe=_readlink_optional(process_path / "exe"),
            cwd=_readlink_optional(process_path / "cwd"),
            cmdline=cmdline,
            readable=True,
        )
    except (FileNotFoundError, ProcessLookupError) as error:
        return _unreadable_process(pid, str(error))
    except PermissionError as error:
        return _unreadable_process(pid, str(error))
    except OSError as error:
        return _unreadable_process(pid, str(error))


def top_by_memory(report: ProcessReport, limit: int = 10) -> tuple[ProcessInfo, ...]:
    readable = [process for process in report.processes if process.readable]
    return tuple(sorted(readable, key=lambda process: process.vm_rss or 0, reverse=True)[:limit])


def zombie_processes(report: ProcessReport) -> tuple[ProcessInfo, ...]:
    return tuple(process for process in report.processes if process.state and process.state.startswith("Z"))


def _parse_status(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        values[key] = value.strip()
    return values


def _read_cmdline(path: Path) -> tuple[str, ...]:
    raw = path.read_bytes()
    if not raw:
        return ()
    return tuple(part.decode("utf-8", errors="replace") for part in raw.rstrip(b"\0").split(b"\0") if part)


def _fd_count(path: Path) -> int | None:
    try:
        return sum(1 for _ in path.iterdir())
    except OSError:
        return None


def _readlink_optional(path: Path) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _kib_field(value: str | None) -> int | None:
    if value is None:
        return None
    fields = value.split()
    if not fields:
        return None
    try:
        return int(fields[0]) * 1024
    except ValueError:
        return None


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.split()[0])
    except (ValueError, IndexError):
        return None


def _first_int(value: str | None) -> int | None:
    return _int_or_none(value)


def _username(uid: int | None) -> str | None:
    if uid is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _unreadable_process(pid: int, error: str) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        ppid=None,
        uid=None,
        user=None,
        name=None,
        state=None,
        threads=None,
        vm_rss=None,
        vm_size=None,
        voluntary_ctxt_switches=None,
        nonvoluntary_ctxt_switches=None,
        fd_count=None,
        exe=None,
        cwd=None,
        cmdline=(),
        readable=False,
        error=error,
    )


def _pid_sort_key(path: Path) -> tuple[int, int | str]:
    if path.name.isdigit():
        return (0, int(path.name))
    return (1, path.name)
