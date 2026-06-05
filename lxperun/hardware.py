"""Hardware inventory helpers for PCI, USB, sensors and NUMA."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
from typing import Callable


SYS_PCI = Path("/sys/bus/pci/devices")
SYS_USB = Path("/sys/bus/usb/devices")
SYS_HWMON = Path("/sys/class/hwmon")
SYS_NUMA = Path("/sys/devices/system/node")


@dataclass(frozen=True)
class PciDevice:
    bdf: str
    vendor_id: str | None
    device_id: str | None
    class_code: str | None
    vendor_name: str | None
    device_name: str | None
    subsystem_vendor_id: str | None
    subsystem_device_id: str | None
    driver: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class UsbDevice:
    path: str
    busnum: int | None
    devnum: int | None
    id_vendor: str | None
    id_product: str | None
    manufacturer: str | None
    product: str | None
    serial: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HwmonSensor:
    chip: str
    label: str
    value: float | int
    unit: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NumaNode:
    name: str
    cpulist: str | None
    mem_total_kb: int | None
    mem_free_kb: int | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HardwareReport:
    pci_devices: tuple[PciDevice, ...]
    usb_devices: tuple[UsbDevice, ...]
    sensors: tuple[HwmonSensor, ...]
    numa_nodes: tuple[NumaNode, ...]
    pci_count: int
    usb_count: int
    sensor_count: int
    numa_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def hardware_report(
    sys_pci: Path = SYS_PCI,
    sys_usb: Path = SYS_USB,
    sys_hwmon: Path = SYS_HWMON,
    sys_numa: Path = SYS_NUMA,
) -> HardwareReport:
    pci_devices = _load_pci_devices(sys_pci)
    usb_devices = _load_usb_devices(sys_usb)
    sensors = _load_hwmon_sensors(sys_hwmon)
    numa_nodes = _load_numa_nodes(sys_numa)
    return HardwareReport(
        pci_devices=pci_devices,
        usb_devices=usb_devices,
        sensors=sensors,
        numa_nodes=numa_nodes,
        pci_count=len(pci_devices),
        usb_count=len(usb_devices),
        sensor_count=len(sensors),
        numa_count=len(numa_nodes),
    )


def _load_pci_devices(sys_pci: Path) -> tuple[PciDevice, ...]:
    if not sys_pci.exists():
        return ()

    devices = []
    for device_path in sorted(sys_pci.iterdir(), key=lambda item: item.name):
        devices.append(
            PciDevice(
                bdf=device_path.name,
                vendor_id=_read_hex(device_path / "vendor"),
                device_id=_read_hex(device_path / "device"),
                class_code=_read_hex(device_path / "class"),
                vendor_name=_read_optional(device_path / "vendor_name"),
                device_name=_read_optional(device_path / "device_name"),
                subsystem_vendor_id=_read_hex(device_path / "subsystem_vendor"),
                subsystem_device_id=_read_hex(device_path / "subsystem_device"),
                driver=_readlink_tail(device_path / "driver"),
            )
        )
    return tuple(devices)


def _load_usb_devices(sys_usb: Path) -> tuple[UsbDevice, ...]:
    if not sys_usb.exists():
        return ()

    devices = []
    for device_path in sorted(sys_usb.iterdir(), key=lambda item: item.name):
        if not (device_path / "idVendor").exists() and not (device_path / "manufacturer").exists():
            continue
        devices.append(
            UsbDevice(
                path=device_path.name,
                busnum=_read_optional_int(device_path / "busnum"),
                devnum=_read_optional_int(device_path / "devnum"),
                id_vendor=_read_hex(device_path / "idVendor"),
                id_product=_read_hex(device_path / "idProduct"),
                manufacturer=_read_optional(device_path / "manufacturer"),
                product=_read_optional(device_path / "product"),
                serial=_read_optional(device_path / "serial"),
            )
        )
    return tuple(devices)


def _load_hwmon_sensors(sys_hwmon: Path) -> tuple[HwmonSensor, ...]:
    if not sys_hwmon.exists():
        return ()

    sensors = []
    for hwmon_path in sorted(sys_hwmon.iterdir(), key=lambda item: item.name):
        chip = _read_optional(hwmon_path / "name") or hwmon_path.name
        for input_path in sorted(hwmon_path.glob("*_input")):
            prefix = input_path.name[:-6]
            label = _read_optional(hwmon_path / f"{prefix}_label") or prefix
            raw_value = _read_optional(input_path)
            if raw_value is None:
                continue
            value = _coerce_numeric(raw_value)
            unit = _guess_unit(prefix)
            sensors.append(HwmonSensor(chip=chip, label=label, value=value, unit=unit))
    return tuple(sensors)


def _load_numa_nodes(sys_numa: Path) -> tuple[NumaNode, ...]:
    if not sys_numa.exists():
        return ()

    nodes = []
    for node_path in sorted(sys_numa.glob("node[0-9]*"), key=lambda item: item.name):
        meminfo = _parse_numa_meminfo(node_path / "meminfo")
        nodes.append(
            NumaNode(
                name=node_path.name,
                cpulist=_read_optional(node_path / "cpulist"),
                mem_total_kb=meminfo.get("MemTotal"),
                mem_free_kb=meminfo.get("MemFree"),
            )
        )
    return tuple(nodes)


def _parse_numa_meminfo(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}

    values = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        normalized_key = key.split()[-1]
        fields = value.strip().split()
        if not fields:
            continue
        try:
            values[normalized_key] = int(fields[0])
        except ValueError:
            continue
    return values


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
        return int(value)
    except ValueError:
        return None


def _read_hex(path: Path) -> str | None:
    value = _read_optional(path)
    if value is None:
        return None
    return value.strip()


def _readlink_tail(path: Path) -> str | None:
    try:
        return os.readlink(path).rsplit("/", maxsplit=1)[-1]
    except OSError:
        return None


def _coerce_numeric(value: str) -> float | int:
    try:
        number = float(value)
    except ValueError:
        return value
    if number.is_integer():
        return int(number)
    return number


def _guess_unit(prefix: str) -> str:
    if prefix.startswith("temp"):
        return "mC"
    if prefix.startswith("fan"):
        return "RPM"
    if prefix.startswith("power"):
        return "uW"
    if prefix.startswith("curr"):
        return "uA"
    if prefix.startswith("in"):
        return "mV"
    return "raw"
