"""Host capability detection for safe deep diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil


@dataclass(frozen=True)
class CapabilityProbe:
    name: str
    available: bool
    level: str
    detail: str
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityReport:
    effective_uid: int
    is_root: bool
    probes: tuple[CapabilityProbe, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def capability_report(root: Path = Path("/")) -> CapabilityReport:
    effective_uid = os.geteuid()
    is_root = effective_uid == 0
    proc = root / "proc"
    sys = root / "sys"
    dev = root / "dev"

    probes = (
        _root_probe(is_root),
        _procfs_probe(proc),
        _sysfs_probe(sys),
        _kmsg_probe(dev, is_root),
        _security_posture_probe(root, is_root),
        _perf_probe(proc, sys, is_root),
        _bpf_probe(sys, is_root),
        _audit_probe(is_root),
        _systemd_probe(),
        _journal_probe(),
        _efi_probe(sys, is_root),
        _tpm_probe(dev, is_root),
        _firmware_update_probe(),
        _debug_symbols_probe(root),
    )
    return CapabilityReport(effective_uid=effective_uid, is_root=is_root, probes=probes)


def _root_probe(is_root: bool) -> CapabilityProbe:
    return CapabilityProbe(
        name="root",
        available=is_root,
        level="privilege",
        detail="Process runs as root." if is_root else "Process runs without root privileges.",
        missing=() if is_root else ("sudo/root required for some kernel, audit, TPM and firmware checks",),
    )


def _procfs_probe(proc: Path) -> CapabilityProbe:
    evidence = _existing(proc, proc / "self", proc / "cpuinfo", proc / "meminfo")
    return CapabilityProbe(
        name="procfs",
        available=(proc / "self").exists(),
        level="ring3",
        detail="Process and kernel-exported runtime metadata.",
        evidence=evidence,
        missing=() if evidence else ("procfs not mounted or hidden",),
    )


def _sysfs_probe(sys: Path) -> CapabilityProbe:
    evidence = _existing(sys, sys / "class", sys / "devices", sys / "module")
    return CapabilityProbe(
        name="sysfs",
        available=(sys / "class").exists(),
        level="ring3/ring0-exported",
        detail="Kernel object and device metadata.",
        evidence=evidence,
        missing=() if evidence else ("sysfs not mounted or hidden",),
    )


def _kmsg_probe(dev: Path, is_root: bool) -> CapabilityProbe:
    path = dev / "kmsg"
    available = path.exists() and os.access(path, os.R_OK)
    missing = []
    if not path.exists():
        missing.append("/dev/kmsg not visible")
    if path.exists() and not available:
        missing.append("read permission missing")
    if not is_root:
        missing.append("root is commonly required")
    return CapabilityProbe(
        name="kmsg",
        available=available,
        level="kernel-log",
        detail="Direct kernel log access.",
        evidence=_existing(path),
        missing=tuple(missing),
    )


def _security_posture_probe(root: Path, is_root: bool) -> CapabilityProbe:
    evidence = _existing(
        root / "etc" / "passwd",
        root / "sys" / "fs" / "selinux",
        root / "sys" / "module" / "apparmor",
    )
    missing = []
    if not is_root:
        missing.append("root unlocks /etc/shadow, deeper file-permission and account checks")
    return CapabilityProbe(
        name="security-posture",
        available=bool(evidence),
        level="hardening",
        detail="SELinux/AppArmor, exposed listeners, UID 0 accounts, and world-writable paths.",
        evidence=evidence,
        missing=tuple(missing),
    )


def _perf_probe(proc: Path, sys: Path, is_root: bool) -> CapabilityProbe:
    paranoid = _read_optional(proc / "sys" / "kernel" / "perf_event_paranoid")
    perf_tool = shutil.which("perf")
    available = perf_tool is not None and (is_root or paranoid in {None, "-1", "0", "1"})
    missing = []
    if perf_tool is None:
        missing.append("perf tool not installed")
    if paranoid not in {None, "-1", "0", "1"} and not is_root:
        missing.append(f"perf_event_paranoid={paranoid}")
    return CapabilityProbe(
        name="perf",
        available=available,
        level="kernel profiling",
        detail="CPU profiling, tracepoints and low-level performance counters.",
        evidence=tuple(item for item in (perf_tool, str(sys / "kernel" / "tracing")) if item),
        missing=tuple(missing),
    )


def _bpf_probe(sys: Path, is_root: bool) -> CapabilityProbe:
    bpftool = shutil.which("bpftool")
    bpf_fs = sys / "fs" / "bpf"
    tracing = sys / "kernel" / "tracing"
    available = bpftool is not None and bpf_fs.exists() and is_root
    missing = []
    if bpftool is None:
        missing.append("bpftool not installed")
    if not bpf_fs.exists():
        missing.append("bpffs not mounted at /sys/fs/bpf")
    if not tracing.exists():
        missing.append("tracefs not visible")
    if not is_root:
        missing.append("root or CAP_BPF/CAP_PERFMON commonly required")
    return CapabilityProbe(
        name="ebpf",
        available=available,
        level="kernel observability",
        detail="Safe programmable tracing when used with explicit privileges.",
        evidence=_existing(bpf_fs, tracing),
        missing=tuple(missing),
    )


def _audit_probe(is_root: bool) -> CapabilityProbe:
    auditctl = shutil.which("auditctl")
    available = auditctl is not None and is_root
    missing = []
    if auditctl is None:
        missing.append("auditctl not installed")
    if not is_root:
        missing.append("root or CAP_AUDIT_CONTROL required")
    return CapabilityProbe(
        name="audit",
        available=available,
        level="security telemetry",
        detail="Linux audit subsystem visibility.",
        evidence=() if auditctl is None else (auditctl,),
        missing=tuple(missing),
    )


def _systemd_probe() -> CapabilityProbe:
    systemctl = shutil.which("systemctl")
    return CapabilityProbe(
        name="systemd",
        available=systemctl is not None,
        level="service manager",
        detail="Service/unit state and failed daemon diagnostics.",
        evidence=() if systemctl is None else (systemctl,),
        missing=() if systemctl else ("systemctl not installed or not in PATH",),
    )


def _journal_probe() -> CapabilityProbe:
    journalctl = shutil.which("journalctl")
    return CapabilityProbe(
        name="journal",
        available=journalctl is not None,
        level="logs",
        detail="System, service and kernel log visibility.",
        evidence=() if journalctl is None else (journalctl,),
        missing=() if journalctl else ("journalctl not installed or not in PATH",),
    )


def _efi_probe(sys: Path, is_root: bool) -> CapabilityProbe:
    efi = sys / "firmware" / "efi"
    efivars = efi / "efivars"
    available = efi.exists()
    missing = []
    if not available:
        missing.append("system was not booted with visible UEFI metadata")
    if available and not efivars.exists():
        missing.append("efivarfs not mounted or hidden")
    if not is_root:
        missing.append("root may be required for deeper EFI variable inspection")
    return CapabilityProbe(
        name="efi",
        available=available,
        level="firmware",
        detail="UEFI metadata and EFI variable visibility.",
        evidence=_existing(efi, efivars),
        missing=tuple(missing),
    )


def _tpm_probe(dev: Path, is_root: bool) -> CapabilityProbe:
    devices = _existing(dev / "tpm0", dev / "tpmrm0")
    tpm2_getcap = shutil.which("tpm2_getcap")
    available = bool(devices)
    missing = []
    if not devices:
        missing.append("TPM device node not visible")
    if tpm2_getcap is None:
        missing.append("tpm2-tools not installed")
    if available and not is_root:
        missing.append("root or tss group permissions may be required")
    return CapabilityProbe(
        name="tpm",
        available=available,
        level="firmware/security chip",
        detail="Trusted Platform Module presence and tooling.",
        evidence=devices + (() if tpm2_getcap is None else (tpm2_getcap,)),
        missing=tuple(missing),
    )


def _firmware_update_probe() -> CapabilityProbe:
    fwupdmgr = shutil.which("fwupdmgr")
    return CapabilityProbe(
        name="fwupd",
        available=fwupdmgr is not None,
        level="firmware inventory",
        detail="Firmware device inventory and update metadata.",
        evidence=() if fwupdmgr is None else (fwupdmgr,),
        missing=() if fwupdmgr else ("fwupdmgr not installed or not in PATH",),
    )


def _debug_symbols_probe(root: Path) -> CapabilityProbe:
    likely_paths = (
        root / "usr" / "lib" / "debug",
        root / "usr" / "lib" / "debug" / "usr" / "lib" / "modules",
    )
    evidence = _existing(*likely_paths)
    return CapabilityProbe(
        name="debug-symbols",
        available=bool(evidence),
        level="software debugging",
        detail="Debug symbol directories useful for stack traces and native crash analysis.",
        evidence=evidence,
        missing=() if evidence else ("debug symbol directories not found",),
    )


def _existing(*paths: Path) -> tuple[str, ...]:
    return tuple(str(path) for path in paths if path.exists())


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
