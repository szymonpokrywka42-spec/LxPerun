"""Systemd service inspection helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import shutil
from typing import Callable

from .linux import run_command


@dataclass(frozen=True)
class ServiceUnit:
    name: str
    load: str
    active: str
    sub: str
    description: str
    unit_file_state: str | None = None
    unit_file_preset: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ServiceReport:
    available: bool
    total_units: int
    active_units: int
    running_units: int
    failed_units: tuple[ServiceUnit, ...]
    units: tuple[ServiceUnit, ...]
    raw_failed_units: tuple[str, ...]

    @property
    def failed_count(self) -> int:
        return len(self.failed_units)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def service_report(
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    which_fn: Callable[[str], str | None] = shutil.which,
) -> ServiceReport:
    systemctl = which_fn("systemctl")
    if systemctl is None:
        return ServiceReport(
            available=False,
            total_units=0,
            active_units=0,
            running_units=0,
            failed_units=(),
            units=(),
            raw_failed_units=(),
        )

    units = _load_units(run_command_fn)
    failed_units = tuple(unit for unit in units if unit.active == "failed" or unit.sub == "failed")
    raw_failed_units = _load_failed_unit_names(run_command_fn)
    return ServiceReport(
        available=True,
        total_units=len(units),
        active_units=sum(1 for unit in units if unit.active in {"active", "reloading"}),
        running_units=sum(1 for unit in units if unit.active == "active" and unit.sub == "running"),
        failed_units=failed_units,
        units=units,
        raw_failed_units=raw_failed_units,
    )


def _load_units(run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> tuple[ServiceUnit, ...]:
    code, stdout, stderr = run_command_fn(
        [
            "systemctl",
            "list-units",
            "--all",
            "--no-legend",
            "--plain",
            "--type=service",
            "--type=socket",
            "--type=timer",
        ],
        3.0,
    )
    if code not in {0, 1}:
        return ()

    units = []
    for line in stdout.splitlines():
        parsed = _parse_list_units_line(line)
        if parsed is None:
            continue
        units.append(parsed)
    return tuple(units)


def _load_failed_unit_names(run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> tuple[str, ...]:
    code, stdout, stderr = run_command_fn(
        ["systemctl", "--failed", "--no-legend", "--plain"], 3.0
    )
    if code not in {0, 1}:
        return ()

    names = []
    for line in stdout.splitlines():
        parsed = _parse_list_units_line(line)
        if parsed is not None:
            names.append(parsed.name)
            continue
        fields = line.split(maxsplit=1)
        if fields:
            names.append(fields[0])
    return tuple(names)


def _parse_list_units_line(line: str) -> ServiceUnit | None:
    fields = line.split(maxsplit=4)
    if len(fields) < 5:
        return None
    return ServiceUnit(
        name=fields[0],
        load=fields[1],
        active=fields[2],
        sub=fields[3],
        description=fields[4],
    )
