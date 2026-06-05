"""Small Linux inspection helpers built on top of /proc, /sys and stdlib calls."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
from typing import Iterable


PROC = Path("/proc")
SYS_CLASS_NET = Path("/sys/class/net")
SYS_BLOCK = Path("/sys/block")
SYS_DMI = Path("/sys/class/dmi/id")


@dataclass(frozen=True)
class SystemIdentity:
    hostname: str
    kernel: str
    machine: str
    distribution: str
    boot_id: str | None
    product_name: str | None
    product_vendor: str | None


@dataclass(frozen=True)
class CpuInfo:
    architecture: str
    logical_cpus: int
    model_name: str | None
    vendor_id: str | None
    cpu_mhz: float | None
    flags: tuple[str, ...]


@dataclass(frozen=True)
class MemoryInfo:
    total: int
    available: int
    free: int
    buffers: int
    cached: int
    swap_total: int
    swap_free: int

    @property
    def used(self) -> int:
        return max(0, self.total - self.available)

    @property
    def used_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.used / self.total) * 100, 2)


@dataclass(frozen=True)
class CpuTimes:
    user: int
    nice: int
    system: int
    idle: int
    iowait: int
    irq: int
    softirq: int
    steal: int
    guest: int
    guest_nice: int

    @property
    def total(self) -> int:
        return sum(asdict(self).values())


@dataclass(frozen=True)
class DiskUsage:
    path: str
    total: int
    used: int
    free: int

    @property
    def used_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.used / self.total) * 100, 2)


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    mac: str | None
    ipv4: str | None
    mtu: int | None
    carrier: int | None
    operstate: str | None
    rx_bytes: int | None
    tx_bytes: int | None


@dataclass(frozen=True)
class BlockDevice:
    name: str
    size: int | None
    removable: bool | None
    rotational: bool | None
    model: str | None
    vendor: str | None


@dataclass(frozen=True)
class MountPoint:
    device: str
    mount_point: str
    filesystem: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class KernelModule:
    name: str
    size: int
    used_by_count: int
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class LinuxSnapshot:
    identity: SystemIdentity
    uptime: float
    load_average: tuple[float, float, float]
    memory: MemoryInfo
    cpu: CpuTimes
    cpu_info: CpuInfo
    root_disk: DiskUsage
    network: tuple[NetworkInterface, ...]
    block_devices: tuple[BlockDevice, ...]
    mounts: tuple[MountPoint, ...]
    kernel_modules: tuple[KernelModule, ...]
    sysctl_kernel: dict[str, str]

    @property
    def hostname(self) -> str:
        return self.identity.hostname

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def system_identity() -> SystemIdentity:
    return SystemIdentity(
        hostname=socket.gethostname(),
        kernel=platform.release(),
        machine=platform.machine(),
        distribution=_distribution_name(),
        boot_id=_read_optional(Path("/proc/sys/kernel/random/boot_id")),
        product_name=_read_optional(SYS_DMI / "product_name"),
        product_vendor=_read_optional(SYS_DMI / "sys_vendor"),
    )


def cpu_info(proc: Path = PROC) -> CpuInfo:
    processors = 0
    first_cpu: dict[str, str] = {}
    for line in _read_text(proc / "cpuinfo").splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", maxsplit=1)]
        if key == "processor":
            processors += 1
        first_cpu.setdefault(key, value)

    cpu_mhz = _float_or_none(first_cpu.get("cpu MHz"))
    return CpuInfo(
        architecture=platform.machine(),
        logical_cpus=processors or (os.cpu_count() or 0),
        model_name=first_cpu.get("model name") or first_cpu.get("Processor"),
        vendor_id=first_cpu.get("vendor_id"),
        cpu_mhz=cpu_mhz,
        flags=tuple(first_cpu.get("flags", "").split()),
    )


def uptime_seconds(proc: Path = PROC) -> float:
    fields = _read_text(proc / "uptime").split()
    if not fields:
        raise RuntimeError("Cannot parse /proc/uptime")
    return float(fields[0])


def memory_info(proc: Path = PROC) -> MemoryInfo:
    values = _parse_meminfo(proc / "meminfo")
    return MemoryInfo(
        total=values.get("MemTotal", 0),
        available=values.get("MemAvailable", values.get("MemFree", 0)),
        free=values.get("MemFree", 0),
        buffers=values.get("Buffers", 0),
        cached=values.get("Cached", 0),
        swap_total=values.get("SwapTotal", 0),
        swap_free=values.get("SwapFree", 0),
    )


def cpu_times(proc: Path = PROC) -> CpuTimes:
    first_line = _read_text(proc / "stat").splitlines()[0]
    label, *raw_values = first_line.split()
    if label != "cpu":
        raise RuntimeError("Cannot parse aggregate CPU line from /proc/stat")

    values = [int(value) for value in raw_values[:10]]
    values.extend([0] * (10 - len(values)))
    return CpuTimes(*values[:10])


def disk_usage(path: str | os.PathLike[str] = "/") -> DiskUsage:
    stat = os.statvfs(path)
    total = stat.f_blocks * stat.f_frsize
    free = stat.f_bavail * stat.f_frsize
    used = total - free
    return DiskUsage(path=os.fspath(path), total=total, used=used, free=free)


def network_interfaces(sys_class_net: Path = SYS_CLASS_NET) -> tuple[NetworkInterface, ...]:
    if not sys_class_net.exists():
        return ()

    interfaces = []
    for interface_path in sorted(sys_class_net.iterdir(), key=lambda item: item.name):
        interfaces.append(
            NetworkInterface(
                name=interface_path.name,
                mac=_read_optional(interface_path / "address"),
                ipv4=_ipv4_address(interface_path.name),
                mtu=_read_optional_int(interface_path / "mtu"),
                carrier=_read_optional_int(interface_path / "carrier"),
                operstate=_read_optional(interface_path / "operstate"),
                rx_bytes=_read_optional_int(interface_path / "statistics" / "rx_bytes"),
                tx_bytes=_read_optional_int(interface_path / "statistics" / "tx_bytes"),
            )
        )
    return tuple(interfaces)


def block_devices(sys_block: Path = SYS_BLOCK) -> tuple[BlockDevice, ...]:
    if not sys_block.exists():
        return ()

    devices = []
    for device_path in sorted(sys_block.iterdir(), key=lambda item: item.name):
        if device_path.name.startswith(("loop", "ram")):
            continue
        sectors = _read_optional_int(device_path / "size")
        devices.append(
            BlockDevice(
                name=device_path.name,
                size=None if sectors is None else sectors * 512,
                removable=_bool_optional(device_path / "removable"),
                rotational=_bool_optional(device_path / "queue" / "rotational"),
                model=_read_optional(device_path / "device" / "model"),
                vendor=_read_optional(device_path / "device" / "vendor"),
            )
        )
    return tuple(devices)


def mount_points(proc: Path = PROC) -> tuple[MountPoint, ...]:
    mountinfo = proc / "self" / "mountinfo"
    if mountinfo.exists():
        return _parse_mountinfo(mountinfo)
    return _parse_mounts(proc / "mounts")


def kernel_modules(proc: Path = PROC) -> tuple[KernelModule, ...]:
    modules = proc / "modules"
    if not modules.exists():
        return ()

    parsed = []
    for line in _read_text(modules).splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        dependencies = () if fields[3] == "-" else tuple(fields[3].rstrip(",").split(","))
        parsed.append(
            KernelModule(
                name=fields[0],
                size=int(fields[1]),
                used_by_count=int(fields[2]),
                dependencies=dependencies,
            )
        )
    return tuple(parsed)


def sysctl_kernel(proc: Path = PROC) -> dict[str, str]:
    kernel_path = proc / "sys" / "kernel"
    keys = ("hostname", "ostype", "osrelease", "version", "tainted", "panic", "randomize_va_space")
    values = {}
    for key in keys:
        value = _read_optional(kernel_path / key)
        if value is not None:
            values[key] = value
    return values


def snapshot() -> LinuxSnapshot:
    return LinuxSnapshot(
        identity=system_identity(),
        uptime=uptime_seconds(),
        load_average=os.getloadavg(),
        memory=memory_info(),
        cpu=cpu_times(),
        cpu_info=cpu_info(),
        root_disk=disk_usage("/"),
        network=network_interfaces(),
        block_devices=block_devices(),
        mounts=mount_points(),
        kernel_modules=kernel_modules(),
        sysctl_kernel=sysctl_kernel(),
    )


def _parse_meminfo(path: Path) -> dict[str, int]:
    values = {}
    for line in _read_text(path).splitlines():
        name, raw_value = line.split(":", maxsplit=1)
        fields = raw_value.strip().split()
        if fields:
            values[name] = int(fields[0]) * 1024
    return values


def _distribution_name() -> str:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return "unknown"

    values = {}
    for line in os_release.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", maxsplit=1)
        values[key] = value.strip().strip('"')
    return values.get("PRETTY_NAME") or values.get("NAME") or "unknown"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _read_optional(path: Path) -> str | None:
    try:
        return _read_text(path)
    except OSError:
        return None


def _read_optional_int(path: Path) -> int | None:
    value = _read_optional(path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _bool_optional(path: Path) -> bool | None:
    value = _read_optional_int(path)
    if value is None:
        return None
    return bool(value)


def _float_or_none(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _ipv4_address(interface: str) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", interface.encode("utf-8")[:15])
        response = fcntl.ioctl(sock.fileno(), 0x8915, request)
        return socket.inet_ntoa(response[20:24])
    except OSError:
        return None
    finally:
        if "sock" in locals():
            sock.close()


def _parse_mountinfo(path: Path) -> tuple[MountPoint, ...]:
    mounts = []
    for line in _read_text(path).splitlines():
        fields = line.split()
        if "-" not in fields:
            continue
        separator = fields.index("-")
        if len(fields) <= separator + 2:
            continue
        mounts.append(
            MountPoint(
                device=fields[separator + 2],
                mount_point=fields[4],
                filesystem=fields[separator + 1],
                options=tuple(fields[5].split(",")),
            )
        )
    return tuple(mounts)


def _parse_mounts(path: Path) -> tuple[MountPoint, ...]:
    mounts = []
    for line in _read_text(path).splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        mounts.append(
            MountPoint(
                device=fields[0],
                mount_point=fields[1],
                filesystem=fields[2],
                options=tuple(fields[3].split(",")),
            )
        )
    return tuple(mounts)


def run_command(command: list[str], timeout: float = 2.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, PermissionError) as error:
        return 127, "", str(error)
    except subprocess.TimeoutExpired as error:
        return 124, error.stdout or "", error.stderr or "command timed out"
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def format_bytes(value: int) -> str:
    units: Iterable[str] = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    last_unit = "B"
    for unit in units:
        last_unit = unit
        if amount < 1024 or unit == "PiB":
            break
        amount /= 1024
    return f"{amount:.1f} {last_unit}"
