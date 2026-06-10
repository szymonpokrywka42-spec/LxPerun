"""Backward-compatibility checks for older kernels and distributions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import platform
from pathlib import Path
from typing import Iterable
import shutil


@dataclass(frozen=True)
class CompatibilityCheck:
    name: str
    available: bool
    detail: str
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CompatibilityReport:
    kernel_release: str
    kernel_version: tuple[int, int, int] | None
    distro: str | None
    legacy_mode: bool
    checks: tuple[CompatibilityCheck, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["kernel_version"] = list(self.kernel_version) if self.kernel_version is not None else None
        return data


def compatibility_report(root: Path = Path("/")) -> CompatibilityReport:
    kernel_release = platform.release()
    kernel_version = _parse_kernel_version(kernel_release)
    distro = _read_os_release(root / "etc" / "os-release")
    proc = root / "proc"
    sys = root / "sys"

    checks = (
        _check("procfs", (proc / "self").exists(), "procfs is available.", evidence=_existing(proc, proc / "self")),
        _check("sysfs", (sys / "class").exists(), "sysfs is available.", evidence=_existing(sys, sys / "class")),
        _check(
            "psi",
            (proc / "pressure").exists(),
            "Pressure Stall Information is available.",
            evidence=_existing(proc / "pressure"),
            missing=("older kernels may not expose PSI",),
        ),
        _check(
            "conntrack",
            (proc / "net" / "nf_conntrack").exists() or (proc / "net" / "ip_conntrack").exists(),
            "Connection tracking data is available.",
            evidence=_existing(proc / "net" / "nf_conntrack", proc / "net" / "ip_conntrack"),
            missing=("older kernels or restricted builds may omit conntrack tables",),
        ),
        _check(
            "cgroup",
            (proc / "1" / "cgroup").exists(),
            "Cgroup metadata is available.",
            evidence=_existing(proc / "1" / "cgroup"),
        ),
        _check(
            "systemd",
            _tool_paths("systemctl", "journalctl") != (),
            "systemd-style diagnostics are present when systemctl/journalctl exist.",
            evidence=_tool_paths("systemctl", "journalctl"),
            missing=() if _tool_paths("systemctl", "journalctl") else ("systemd tools not installed or not in PATH",),
        ),
        _check(
            "firewall",
            _tool_paths("nft", "iptables") != (),
            "Firewall tools are optional and detected at runtime.",
            evidence=_tool_paths("nft", "iptables"),
            missing=() if _tool_paths("nft", "iptables") else ("nftables/iptables tools not installed",),
        ),
    )

    legacy_mode = _is_legacy_kernel(kernel_version) or not checks[2].available or not checks[3].available
    recommendations = _recommendations(kernel_version, checks, distro)
    return CompatibilityReport(
        kernel_release=kernel_release,
        kernel_version=kernel_version,
        distro=distro,
        legacy_mode=legacy_mode,
        checks=checks,
        recommendations=tuple(recommendations),
    )


def _check(name: str, available: bool, detail: str, evidence: tuple[str, ...] = (), missing: tuple[str, ...] = ()) -> CompatibilityCheck:
    return CompatibilityCheck(name=name, available=available, detail=detail, evidence=evidence, missing=missing)


def _recommendations(kernel_version: tuple[int, int, int] | None, checks: tuple[CompatibilityCheck, ...], distro: str | None) -> list[str]:
    recommendations: list[str] = []
    if kernel_version is not None and kernel_version < (4, 20, 0):
        recommendations.append("This kernel is older than the PSI era; pressure metrics may be unavailable and that is expected.")
    if not _check_by_name(checks, "psi").available:
        recommendations.append("PSI is missing on this system; LxPerun will skip pressure metrics instead of failing.")
    if not _check_by_name(checks, "conntrack").available:
        recommendations.append("Conntrack tables are not visible; network diagnostics will fall back to sockets, ARP, and bandwidth only.")
    if distro and "fedora" not in distro.lower() and "systemd" not in distro.lower():
        recommendations.append("Some sections rely on systemd tooling; on non-systemd distros, those sections may be partial.")
    return recommendations


def _check_by_name(checks: Iterable[CompatibilityCheck], name: str) -> CompatibilityCheck:
    for check in checks:
        if check.name == name:
            return check
    raise KeyError(name)


def _is_legacy_kernel(kernel_version: tuple[int, int, int] | None) -> bool:
    return kernel_version is not None and kernel_version < (4, 20, 0)


def _parse_kernel_version(release: str) -> tuple[int, int, int] | None:
    base = release.split("-", maxsplit=1)[0]
    parts = []
    for segment in base.split("."):
        digits = []
        for character in segment:
            if character.isdigit():
                digits.append(character)
            else:
                break
        if not digits:
            continue
        try:
            parts.append(int("".join(digits)))
        except ValueError:
            continue
        if len(parts) == 3:
            break
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def _read_os_release(path: Path) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    values = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    pretty_name = values.get("PRETTY_NAME")
    if pretty_name:
        return pretty_name
    name = values.get("NAME")
    version = values.get("VERSION")
    if name and version and version not in name:
        return f"{name} {version}".strip()
    return name or version


def _existing(*paths: Path) -> tuple[str, ...]:
    return tuple(str(path) for path in paths if path.exists())


def _tool_paths(*names: str) -> tuple[str, ...]:
    return tuple(path for name in names if (path := shutil.which(name)) is not None)
