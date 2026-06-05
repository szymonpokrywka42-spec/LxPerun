"""Pretty formatting helpers for human-readable output."""

from __future__ import annotations


def human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    unit = "B"
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == "PiB":
            break
        amount /= 1024
    return f"{amount:.1f} {unit}"


def human_celsius_from_millideg(value: float | int) -> str:
    return f"{float(value) / 1000:.1f} C"


def human_rpm(value: float | int) -> str:
    return f"{int(float(value))} RPM"


def human_sensor_value(value: float | int, unit: str) -> str:
    if unit == "mC":
        return human_celsius_from_millideg(value)
    if unit == "RPM":
        return human_rpm(value)
    if unit == "mV":
        return f"{float(value) / 1000:.2f} V"
    if unit == "uA":
        return f"{float(value) / 1000000:.2f} A"
    if unit == "uW":
        return f"{float(value) / 1000000:.2f} W"
    if unit == "raw":
        return str(value)
    return f"{value} {unit}"


def human_uptime(seconds: float) -> str:
    minutes = seconds / 60
    hours = seconds / 3600
    if hours >= 24:
        days = hours / 24
        return f"{days:.1f} d"
    if hours >= 1:
        return f"{hours:.1f} h"
    if minutes >= 1:
        return f"{minutes:.1f} m"
    return f"{seconds:.1f} s"
