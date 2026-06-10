"""Security posture checks for LxPerun."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from pathlib import Path
import os
import shutil
import stat
from typing import Callable

from .linux import PROC, run_command
from .network import NetworkReport, network_report


@dataclass(frozen=True)
class SecuritySignal:
    name: str
    available: bool
    detail: str
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityFinding:
    category: str
    severity: str
    message: str
    detail: str | None = None
    suggestion: str | None = None
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityReport:
    effective_uid: int
    is_root: bool
    signals: tuple[SecuritySignal, ...]
    findings: tuple[SecurityFinding, ...]
    recommendations: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not any(finding.severity in {"warning", "error", "critical"} for finding in self.findings)

    @property
    def advisory_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity == "warning")

    @property
    def issue_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity in {"error", "critical"})

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def security_report(
    root: Path = Path("/"),
    network_report_obj: NetworkReport | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    is_root_fn: Callable[[], int] = os.geteuid,
    max_world_writable: int = 25,
    critical_paths: tuple[str, ...] = ("/etc", "/opt", "/usr/local"),
) -> SecurityReport:
    effective_uid = is_root_fn()
    is_root = effective_uid == 0
    network = network_report_obj or network_report()

    signals = (
        _root_signal(is_root),
        _selinux_signal(root, which_fn, run_command_fn),
        _apparmor_signal(root, which_fn, run_command_fn),
        _container_cgroup_signal(root),
        _namespace_signal(root),
    )

    findings: list[SecurityFinding] = []
    findings.extend(_exposed_listener_findings(network.listening_sockets))
    findings.extend(_container_socket_findings(root))
    findings.extend(_uid0_findings(root))
    if is_root:
        findings.extend(_shadow_findings(root))
    findings.extend(_world_writable_findings(root, critical_paths, max_world_writable))

    recommendations = _recommendations(signals, findings)
    return SecurityReport(
        effective_uid=effective_uid,
        is_root=is_root,
        signals=signals,
        findings=tuple(findings),
        recommendations=tuple(recommendations),
    )


def _root_signal(is_root: bool) -> SecuritySignal:
    return SecuritySignal(
        name="root",
        available=is_root,
        detail="Process runs as root." if is_root else "Process runs without root privileges.",
        missing=() if is_root else ("root unlocks /etc/shadow and broader permission checks",),
    )


def _selinux_signal(root: Path, which_fn: Callable[[str], str | None], run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> SecuritySignal:
    selinux = root / "sys" / "fs" / "selinux"
    enforce = selinux / "enforce"
    enabled = selinux / "enabled"
    if enforce.exists():
        state = _read_text(enforce)
        if state == "1":
            return SecuritySignal("selinux", True, "SELinux is enforcing.", evidence=(str(enforce),))
        if state == "0":
            return SecuritySignal("selinux", True, "SELinux is permissive.", evidence=(str(enforce),))
    if (selinux / "enabled").exists():
        enabled_state = _read_text(selinux / "enabled")
        if enabled_state and enabled_state.strip().lower() in {"1", "y", "yes", "enabled"}:
            return SecuritySignal("selinux", True, "SELinux is enabled.", evidence=(str(selinux / "enabled"),))

    getenforce = which_fn("getenforce")
    if getenforce is not None:
        code, stdout, stderr = run_command_fn([getenforce], 3.0)
        value = (stdout or stderr).strip().lower()
        if code == 0 and value:
            return SecuritySignal("selinux", value != "disabled", f"SELinux is {value}.", evidence=(getenforce,))

    return SecuritySignal(
        name="selinux",
        available=False,
        detail="SELinux is disabled or not visible.",
        evidence=(),
        missing=("getenforce not installed or SELinux not mounted",),
    )


def _apparmor_signal(root: Path, which_fn: Callable[[str], str | None], run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> SecuritySignal:
    enabled = root / "sys" / "module" / "apparmor" / "parameters" / "enabled"
    if enabled.exists():
        value = _read_text(enabled)
        if value:
            lowered = value.strip().lower()
            if lowered.startswith("y"):
                return SecuritySignal("apparmor", True, "AppArmor is enabled.", evidence=(str(enabled),))
            if lowered.startswith("n"):
                return SecuritySignal("apparmor", False, "AppArmor is disabled.", evidence=(str(enabled),))

    aa_status = which_fn("aa-status")
    if aa_status is not None:
        code, stdout, stderr = run_command_fn([aa_status], 3.0)
        output = (stdout or stderr).lower()
        if code == 0 and output:
            if "profiles are loaded" in output or "loaded" in output:
                if "enforce mode" in output:
                    return SecuritySignal("apparmor", True, "AppArmor is enabled and enforcing.", evidence=(aa_status,))
                if "complain mode" in output:
                    return SecuritySignal("apparmor", True, "AppArmor is enabled in complain mode.", evidence=(aa_status,))
                return SecuritySignal("apparmor", True, "AppArmor is enabled.", evidence=(aa_status,))

    return SecuritySignal(
        name="apparmor",
        available=False,
        detail="AppArmor is disabled or not visible.",
        evidence=(),
        missing=("aa-status not installed or AppArmor not mounted",),
    )


def _container_cgroup_signal(root: Path) -> SecuritySignal:
    cgroup = root / "proc" / "1" / "cgroup"
    if not cgroup.exists():
        return SecuritySignal(
            name="container",
            available=False,
            detail="No /proc/1/cgroup data is available.",
            evidence=(),
            missing=("/proc/1/cgroup not visible",),
        )

    lines = _read_lines(cgroup)
    markers = []
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in ("docker", "podman", "libpod", "lxc", "kubepods", "containerd", "machine.slice")):
            markers.append(line)
    if markers:
        return SecuritySignal(
            name="container",
            available=True,
            detail="Container cgroup markers were detected.",
            evidence=tuple(markers[:8]),
        )
    return SecuritySignal(
        name="container",
        available=False,
        detail="No obvious container cgroup markers were detected.",
        evidence=tuple(lines[:8]),
    )


def _namespace_signal(root: Path) -> SecuritySignal:
    namespace_paths = (
        root / "proc" / "1" / "ns" / "pid",
        root / "proc" / "1" / "ns" / "net",
        root / "proc" / "1" / "ns" / "mnt",
        root / "proc" / "self" / "ns" / "pid",
        root / "proc" / "self" / "ns" / "net",
        root / "proc" / "self" / "ns" / "mnt",
    )
    entries = []
    for namespace_path in namespace_paths:
        try:
            target = os.readlink(namespace_path)
        except OSError:
            continue
        entries.append(f"{namespace_path} -> {target}")
    if not entries:
        return SecuritySignal(
            name="namespaces",
            available=False,
            detail="Namespace links are not visible.",
            evidence=(),
            missing=("/proc/*/ns/* not visible",),
        )
    return SecuritySignal(
        name="namespaces",
        available=True,
        detail="Namespace links are visible for pid, net, and mount.",
        evidence=tuple(entries[:8]),
    )


def _container_socket_findings(root: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    socket_paths = (
        root / "var" / "run" / "docker.sock",
        root / "run" / "docker.sock",
        root / "run" / "podman" / "podman.sock",
        root / "var" / "run" / "podman" / "podman.sock",
    )
    exposed = []
    for socket_path in socket_paths:
        try:
            mode = os.stat(socket_path).st_mode
        except OSError:
            continue
        if stat.S_ISSOCK(mode):
            exposed.append(str(socket_path))
    if exposed:
        findings.append(
            SecurityFinding(
                category="container",
                severity="warning",
                message="Container runtime API sockets are present.",
                detail="A local process with access to these sockets can control containers and, depending on configuration, the host.",
                suggestion="Restrict socket access or disable the runtime API when it is not needed.",
                evidence=tuple(exposed[:10]),
            )
        )
    return findings


def _exposed_listener_findings(sockets) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    exposed = []
    for socket_entry in sockets:
        if socket_entry.local_port == 0:
            continue
        if socket_entry.local_address in {"0.0.0.0", "::", "0:0:0:0:0:0:0:0"}:
            pid_text = ",".join(str(pid) for pid in socket_entry.pids) if socket_entry.pids else "-"
            exposed.append(f"{socket_entry.protocol} {socket_entry.local_address}:{socket_entry.local_port} pid={pid_text}")
    if exposed:
        findings.append(
            SecurityFinding(
                category="network",
                severity="warning",
                message="Some services are listening on all interfaces.",
                detail="That is sometimes intentional, but it is worth reviewing if the service should stay local.",
                suggestion="Bind to localhost or a specific interface if the service should not be externally reachable.",
                evidence=tuple(exposed[:25]),
            )
        )
    return findings


def _uid0_findings(root: Path) -> list[SecurityFinding]:
    passwd = root / "etc" / "passwd"
    if not passwd.exists():
        return []
    uid0_users = []
    for line in _read_lines(passwd):
        parts = line.split(":")
        if len(parts) < 3:
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        if uid == 0:
            uid0_users.append(parts[0])
    if len(uid0_users) <= 1:
        return []
    return [
        SecurityFinding(
            category="accounts",
            severity="error",
            message="Multiple UID 0 accounts were found.",
            detail="Duplicate root-level accounts can complicate privilege auditing and recovery.",
            suggestion="Keep only the intended root-equivalent account(s) and review sudo/sudoers access.",
            evidence=tuple(uid0_users),
        )
    ]


def _shadow_findings(root: Path) -> list[SecurityFinding]:
    shadow = root / "etc" / "shadow"
    if not shadow.exists():
        return []
    passwordless = []
    for line in _read_lines(shadow):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        if parts[1] == "":
            passwordless.append(parts[0])
    if not passwordless:
        return []
    return [
        SecurityFinding(
            category="accounts",
            severity="error",
            message="Passwordless accounts were found in /etc/shadow.",
            detail="Blank password fields mean the account is not protected by a password hash.",
            suggestion="Assign a password or lock the account if it should not be interactive.",
            evidence=tuple(passwordless),
        )
    ]


def _world_writable_findings(root: Path, critical_paths: tuple[str, ...], max_findings: int) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    paths = []
    for critical_path in critical_paths:
        base = root / critical_path.lstrip("/")
        if not base.exists():
            continue
        paths.extend(_scan_world_writable(base, max_findings - len(paths)))
        if len(paths) >= max_findings:
            break
    if paths:
        findings.append(
            SecurityFinding(
                category="permissions",
                severity="warning",
                message="World-writable files or directories were found in critical paths.",
                detail="Loose permissions under system paths can lead to privilege escalation or configuration tampering.",
                suggestion="Review the reported paths and tighten permissions with chmod/chown.",
                evidence=tuple(paths[:max_findings]),
            )
        )
    return findings


def _scan_world_writable(base: Path, limit: int) -> list[str]:
    matches: list[str] = []
    for root, dirnames, filenames in os.walk(base, followlinks=False):
        if len(matches) >= limit:
            break
        current = Path(root)
        try:
            current_stat = os.lstat(current)
            if stat.S_ISDIR(current_stat.st_mode) and current_stat.st_mode & stat.S_IWOTH:
                matches.append(str(current))
                if len(matches) >= limit:
                    break
        except OSError:
            pass
        for name in list(dirnames) + list(filenames):
            if len(matches) >= limit:
                break
            path = current / name
            try:
                path_stat = os.lstat(path)
                if not (stat.S_ISREG(path_stat.st_mode) or stat.S_ISDIR(path_stat.st_mode)):
                    continue
                if path_stat.st_mode & stat.S_IWOTH:
                    matches.append(str(path))
            except OSError:
                continue
    return matches


def _recommendations(signals: tuple[SecuritySignal, ...], findings: list[SecurityFinding]) -> list[str]:
    recommendations = []
    selinux = next((signal for signal in signals if signal.name == "selinux"), None)
    apparmor = next((signal for signal in signals if signal.name == "apparmor"), None)
    if selinux and not selinux.available:
        recommendations.append("Enable SELinux if your distro supports it, or confirm the security policy is intentional.")
    if apparmor and not apparmor.available:
        recommendations.append("Enable AppArmor if your distro uses it, or confirm the security profile is intentional.")
    if any(finding.category == "network" for finding in findings):
        recommendations.append("Review services exposed on all interfaces and bind them only where needed.")
    if any(finding.category == "accounts" for finding in findings):
        recommendations.append("Audit root-equivalent accounts and password hashes before exposing the system.")
    if any(finding.category == "permissions" for finding in findings):
        recommendations.append("Tighten permissions in system paths and re-run the security scan.")
    return recommendations


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None


def _read_lines(path: Path) -> tuple[str, ...]:
    try:
        return tuple(line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
    except OSError:
        return ()
