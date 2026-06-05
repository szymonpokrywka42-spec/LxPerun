"""Diagnostic checks built on top of LxPerun Linux collectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
import warnings

from .linux import LinuxSnapshot, disk_usage, run_command, snapshot


@dataclass(frozen=True)
class DiagnosticIssue:
    severity: str
    source: str
    message: str
    detail: str | None = None
    suggestion: str | None = None


@dataclass(frozen=True)
class DoctorReport:
    issues: tuple[DiagnosticIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity in {"error", "critical"} for issue in self.issues)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def diagnose(project_root: Path | str = ".") -> DoctorReport:
    info = snapshot()
    issues: list[DiagnosticIssue] = []
    issues.extend(_resource_checks(info))
    issues.extend(_kernel_checks(info))
    issues.extend(_network_checks(info))
    issues.extend(_systemd_checks())
    issues.extend(_kernel_log_checks())
    issues.extend(python_syntax_errors(Path(project_root)))
    return DoctorReport(tuple(issues))


def python_syntax_errors(root: Path) -> tuple[DiagnosticIssue, ...]:
    if not root.exists():
        return ()

    issues = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        except (SyntaxError, UnicodeDecodeError) as error:
            issues.append(
                DiagnosticIssue(
                    severity="error",
                    source="python",
                    message=f"Syntax error in {path}",
                    detail=str(error),
                    suggestion="Open the file and fix the syntax error reported by Python.",
                )
            )
    return tuple(issues)


def _resource_checks(info: LinuxSnapshot) -> tuple[DiagnosticIssue, ...]:
    issues = []
    if info.memory.used_percent >= 95:
        issues.append(
            DiagnosticIssue(
                severity="critical",
                source="memory",
                message=f"RAM usage is very high: {info.memory.used_percent:.2f}%",
                suggestion="Check memory-heavy processes and consider closing or restarting them.",
            )
        )
    elif info.memory.used_percent >= 85:
        issues.append(
            DiagnosticIssue(
                severity="warning",
                source="memory",
                message=f"RAM usage is high: {info.memory.used_percent:.2f}%",
                suggestion="Inspect process memory usage before the system starts swapping heavily.",
            )
        )

    if info.memory.swap_total and info.memory.swap_free / info.memory.swap_total < 0.1:
        issues.append(
            DiagnosticIssue(
                severity="warning",
                source="swap",
                message="Swap is almost exhausted.",
                suggestion="Look for memory pressure, leaks, or undersized swap.",
            )
        )

    root = disk_usage("/")
    if root.used_percent >= 95:
        issues.append(
            DiagnosticIssue(
                severity="critical",
                source="disk",
                message=f"Root filesystem is almost full: {root.used_percent:.2f}%",
                suggestion="Free space under /, clean caches/logs, or move data to another filesystem.",
            )
        )
    elif root.used_percent >= 85:
        issues.append(
            DiagnosticIssue(
                severity="warning",
                source="disk",
                message=f"Root filesystem usage is high: {root.used_percent:.2f}%",
                suggestion="Review large files and package/cache directories before it becomes critical.",
            )
        )
    return tuple(issues)


def _kernel_checks(info: LinuxSnapshot) -> tuple[DiagnosticIssue, ...]:
    issues = []
    tainted = info.sysctl_kernel.get("tainted")
    if tainted and tainted != "0":
        issues.append(
            DiagnosticIssue(
                severity="warning",
                source="kernel",
                message=f"Kernel is tainted: {tainted}",
                detail="Non-zero /proc/sys/kernel/tainted means the kernel has seen unsupported/proprietary/unsafe state.",
                suggestion="Check loaded third-party modules and recent kernel warnings; VirtualBox/NVIDIA modules often taint kernels.",
            )
        )
    return tuple(issues)


def _network_checks(info: LinuxSnapshot) -> tuple[DiagnosticIssue, ...]:
    issues = []
    for interface in info.network:
        if interface.name == "lo":
            continue
        if interface.carrier == 1 and interface.ipv4 is None:
            issues.append(
                DiagnosticIssue(
                    severity="warning",
                    source="network",
                    message=f"{interface.name} has carrier but no IPv4 address.",
                    suggestion=f"Check DHCP, NetworkManager/systemd-networkd state, or static IP config for {interface.name}.",
                )
            )
    return tuple(issues)


def _systemd_checks() -> tuple[DiagnosticIssue, ...]:
    if shutil.which("systemctl") is None:
        return ()

    code, stdout, stderr = run_command(["systemctl", "--failed", "--no-legend", "--plain"], timeout=3.0)
    if code not in {0, 1}:
        return (
            DiagnosticIssue(
                severity="info",
                source="systemd",
                message="Could not query failed systemd units.",
                detail=stderr or stdout,
                suggestion="Run systemctl --failed manually to inspect permissions or systemd availability.",
            ),
        )

    issues = []
    for line in stdout.splitlines():
        fields = line.split(maxsplit=4)
        if not fields:
            continue
        issues.append(
            DiagnosticIssue(
                severity="error",
                source="systemd",
                message=f"Failed unit: {fields[0]}",
                detail=line,
                suggestion=f"Run: systemctl status {fields[0]} && journalctl -u {fields[0]} -b",
            )
        )
    return tuple(issues)


def _kernel_log_checks() -> tuple[DiagnosticIssue, ...]:
    if shutil.which("journalctl") is not None:
        code, stdout, stderr = run_command(["journalctl", "-k", "-p", "3", "-n", "30", "--no-pager"], timeout=3.0)
        if code == 0 and stdout:
            return tuple(
                DiagnosticIssue(
                    severity="error",
                    source="kernel-log",
                    message="Kernel error log entry.",
                    detail=line,
                    suggestion="Inspect surrounding boot logs with: journalctl -k -b -p warning",
                )
                for line in _unique_lines(stdout.splitlines())
                if line.strip()
            )
        if code not in {0, 1}:
            return (
                DiagnosticIssue(
                    severity="info",
                    source="kernel-log",
                    message="Could not query kernel journal.",
                    detail=stderr or stdout,
                    suggestion="Try running doctor with sudo or check journal permissions.",
                ),
            )

    if shutil.which("dmesg") is None:
        return ()

    code, stdout, stderr = run_command(["dmesg", "--level=err,crit,alert,emerg"], timeout=3.0)
    if code == 0 and stdout:
        return tuple(
            DiagnosticIssue(
                severity="error",
                source="dmesg",
                message="Kernel error log entry.",
                detail=line,
                suggestion="Inspect surrounding kernel logs with: dmesg --level=warn,err,crit,alert,emerg",
            )
            for line in _unique_lines(stdout.splitlines()[-30:])
            if line.strip()
        )
    if code not in {0, 1}:
        return (
            DiagnosticIssue(
                severity="info",
                source="dmesg",
                message="Could not query dmesg.",
                detail=stderr or stdout,
                suggestion="Try running doctor with sudo or check kernel.dmesg_restrict.",
            ),
        )
    return ()


def _unique_lines(lines: list[str]) -> tuple[str, ...]:
    seen = set()
    unique = []
    for line in lines:
        normalized = line.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(line)
    return tuple(unique)
