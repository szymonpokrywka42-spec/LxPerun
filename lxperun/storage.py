"""Storage inspection helpers for mounts, block devices and I/O stats."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
from typing import Callable

from .linux import BlockDevice, MountPoint, disk_usage, mount_points


SYS_BLOCK = Path("/sys/block")
PROC_DISKSTATS = Path("/proc/diskstats")


@dataclass(frozen=True)
class StorageMount:
    device: str
    mount_point: str
    filesystem: str
    options: tuple[str, ...]
    total: int
    used: int
    free: int

    @property
    def used_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.used / self.total) * 100, 2)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BlockIOStats:
    name: str
    reads_completed: int
    reads_merged: int
    sectors_read: int
    read_time_ms: int
    writes_completed: int
    writes_merged: int
    sectors_written: int
    write_time_ms: int
    io_in_progress: int
    io_time_ms: int
    weighted_io_time_ms: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class StorageDevice:
    name: str
    size: int | None
    removable: bool | None
    rotational: bool | None
    read_only: bool | None
    model: str | None
    vendor: str | None
    scheduler: str | None
    logical_block_size: int | None
    physical_block_size: int | None
    io: BlockIOStats | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class StorageReport:
    mounts: tuple[StorageMount, ...]
    devices: tuple[StorageDevice, ...]
    mount_count: int
    device_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def storage_report(
    proc_mounts: Callable[[], tuple[MountPoint, ...]] = mount_points,
    statvfs_fn: Callable[[str], os.statvfs_result] = os.statvfs,
    sys_block: Path = SYS_BLOCK,
    diskstats_path: Path = PROC_DISKSTATS,
) -> StorageReport:
    mounts = tuple(_load_mounts(proc_mounts(), statvfs_fn))
    devices = _load_devices(sys_block, diskstats_path)
    return StorageReport(
        mounts=mounts,
        devices=devices,
        mount_count=len(mounts),
        device_count=len(devices),
    )


def _load_mounts(mount_points_value: tuple[MountPoint, ...], statvfs_fn: Callable[[str], os.statvfs_result]) -> tuple[StorageMount, ...]:
    mounts = []
    seen_paths: set[str] = set()
    for mount in mount_points_value:
        if mount.mount_point in seen_paths:
            continue
        seen_paths.add(mount.mount_point)
        try:
            stat = statvfs_fn(mount.mount_point)
        except OSError:
            continue
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used = total - free
        mounts.append(
            StorageMount(
                device=mount.device,
                mount_point=mount.mount_point,
                filesystem=mount.filesystem,
                options=mount.options,
                total=total,
                used=used,
                free=free,
            )
        )
    return tuple(mounts)


def _load_devices(sys_block: Path, diskstats_path: Path) -> tuple[StorageDevice, ...]:
    diskstats = _parse_diskstats(diskstats_path)
    if not sys_block.exists():
        return ()

    devices = []
    for device_path in sorted(sys_block.iterdir(), key=lambda item: item.name):
        if device_path.name.startswith(("loop", "ram")):
            continue
        size_sectors = _read_optional_int(device_path / "size")
        devices.append(
            StorageDevice(
                name=device_path.name,
                size=None if size_sectors is None else size_sectors * 512,
                removable=_bool_optional(device_path / "removable"),
                rotational=_bool_optional(device_path / "queue" / "rotational"),
                read_only=_bool_optional(device_path / "ro"),
                model=_read_optional(device_path / "device" / "model"),
                vendor=_read_optional(device_path / "device" / "vendor"),
                scheduler=_read_scheduler(device_path / "queue" / "scheduler"),
                logical_block_size=_read_optional_int(device_path / "queue" / "logical_block_size"),
                physical_block_size=_read_optional_int(device_path / "queue" / "physical_block_size"),
                io=diskstats.get(device_path.name),
            )
        )
    return tuple(devices)


def _parse_diskstats(path: Path) -> dict[str, BlockIOStats]:
    if not path.exists():
        return {}

    stats: dict[str, BlockIOStats] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        name = fields[2]
        try:
            stats[name] = BlockIOStats(
                name=name,
                reads_completed=int(fields[3]),
                reads_merged=int(fields[4]),
                sectors_read=int(fields[5]),
                read_time_ms=int(fields[6]),
                writes_completed=int(fields[7]),
                writes_merged=int(fields[8]),
                sectors_written=int(fields[9]),
                write_time_ms=int(fields[10]),
                io_in_progress=int(fields[11]),
                io_time_ms=int(fields[12]),
                weighted_io_time_ms=int(fields[13]),
            )
        except ValueError:
            continue
    return stats


def _read_scheduler(path: Path) -> str | None:
    value = _read_optional(path)
    if value is None:
        return None
    for token in value.split():
        if token.startswith("[") and token.endswith("]"):
            return token.strip("[]")
    return value.strip()


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None


def _read_optional_int(path: Path) -> int | None:
    value = _read_optional(path)
    if value is None:
        return None
    try:
        return int(value.split()[0])
    except (ValueError, IndexError):
        return None


def _bool_optional(path: Path) -> bool | None:
    value = _read_optional_int(path)
    if value is None:
        return None
    return bool(value)
