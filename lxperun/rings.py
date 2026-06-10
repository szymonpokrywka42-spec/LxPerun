"""Privilege and platform-layer access mapping for LxPerun."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil


@dataclass(frozen=True)
class AccessLayer:
    ring: str
    name: str
    available: bool
    access: str
    evidence: tuple[str, ...]
    missing: tuple[str, ...]
    safe_next_steps: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AccessMap:
    effective_uid: int
    is_root: bool
    layers: tuple[AccessLayer, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def access_map(root: Path = Path("/")) -> AccessMap:
    effective_uid = os.geteuid()
    is_root = effective_uid == 0
    proc = root / "proc"
    sys = root / "sys"
    dev = root / "dev"

    layers = (
        _ring3_layer(proc, sys, is_root),
        _ring0_layer(proc, sys, dev, is_root),
        _ring_minus1_layer(proc, sys),
        _ring_minus2_layer(sys, dev, is_root),
        _ring_minus3_layer(sys, dev, is_root),
    )
    return AccessMap(effective_uid=effective_uid, is_root=is_root, layers=layers)


def _ring3_layer(proc: Path, sys: Path, is_root: bool) -> AccessLayer:
    evidence = _existing(
        proc / "self",
        proc / "cpuinfo",
        proc / "meminfo",
        sys / "class" / "net",
    )
    return AccessLayer(
        ring="3",
        name="user space",
        available=bool(evidence),
        access="read-only system introspection through procfs/sysfs and libc/syscalls",
        evidence=evidence,
        missing=() if evidence else ("procfs/sysfs are not mounted or not visible",),
        safe_next_steps=("collect processes from /proc/<pid>", "inspect open files and sockets visible to this user", "audit posture with `lxperun security`"),
    )


def _ring0_layer(proc: Path, sys: Path, dev: Path, is_root: bool) -> AccessLayer:
    evidence = _existing(
        proc / "modules",
        proc / "sys" / "kernel" / "tainted",
        sys / "module",
        sys / "kernel",
    )
    missing = []
    if not is_root:
        missing.append("root or specific Linux capabilities for deeper kernel diagnostics")
    if not (dev / "kmsg").exists():
        missing.append("/dev/kmsg is not visible")
    return AccessLayer(
        ring="0",
        name="kernel space",
        available=bool(evidence),
        access="kernel-exported state only; no arbitrary kernel memory access",
        evidence=evidence,
        missing=tuple(missing),
        safe_next_steps=("use eBPF/perf/audit with explicit privileges", "optionally add a signed kernel module later", "check exposed services and hardening with `lxperun security`"),
    )


def _ring_minus1_layer(proc: Path, sys: Path) -> AccessLayer:
    evidence = _existing(
        proc / "cpuinfo",
        sys / "hypervisor",
        sys / "devices" / "virtual" / "dmi" / "id" / "product_name",
    )
    cpuinfo = _read_optional(proc / "cpuinfo")
    hypervisor_hint = "hypervisor" in cpuinfo if cpuinfo else False
    missing = () if hypervisor_hint or (sys / "hypervisor").exists() else ("no obvious hypervisor hint detected",)
    return AccessLayer(
        ring="-1",
        name="hypervisor / virtualization layer",
        available=hypervisor_hint or (sys / "hypervisor").exists(),
        access="detection and guest-visible metadata only",
        evidence=evidence,
        missing=missing,
        safe_next_steps=("detect KVM/VirtualBox/VMware/Hyper-V fingerprints", "query virt-what/systemd-detect-virt when installed"),
    )


def _ring_minus2_layer(sys: Path, dev: Path, is_root: bool) -> AccessLayer:
    evidence = _existing(
        sys / "firmware",
        sys / "firmware" / "efi",
        sys / "class" / "dmi" / "id",
        dev / "tpm0",
        dev / "tpmrm0",
    )
    missing = []
    if not is_root:
        missing.append("root may be required for dmidecode, efivarfs writes, TPM tooling, or flash metadata")
    if shutil.which("fwupdmgr") is None:
        missing.append("fwupdmgr is not installed or not in PATH")
    return AccessLayer(
        ring="-2",
        name="firmware / UEFI / ACPI / TPM-visible layer",
        available=bool(evidence),
        access="OS-exposed firmware metadata only",
        evidence=evidence,
        missing=tuple(missing),
        safe_next_steps=("read DMI/EFI metadata", "integrate fwupd read-only device reports", "inspect TPM presence safely"),
    )


def _ring_minus3_layer(sys: Path, dev: Path, is_root: bool) -> AccessLayer:
    evidence = _existing(
        sys / "kernel" / "security",
        sys / "bus" / "pci" / "devices",
    )
    missing = (
        "Intel ME / AMD PSP internals are intentionally isolated from the OS",
        "direct access requires vendor tooling, firmware images, debug hardware, or lab permissions",
    )
    return AccessLayer(
        ring="-3",
        name="management engine / platform security processor",
        available=False,
        access="not directly accessible from normal OS code",
        evidence=evidence,
        missing=missing,
        safe_next_steps=("detect platform and firmware versions", "report security posture without bypassing isolation"),
    )


def _existing(*paths: Path) -> tuple[str, ...]:
    return tuple(str(path) for path in paths if path.exists())


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
