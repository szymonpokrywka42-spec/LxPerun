"""Performance deep-dive checks for LxPerun."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PressureSample:
    resource: str
    some_avg10: float | None
    some_avg60: float | None
    some_avg300: float | None
    some_total: int | None
    full_avg10: float | None
    full_avg60: float | None
    full_avg300: float | None
    full_total: int | None
    raw: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CpuLoad:
    cpu: str
    total: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SlabCache:
    name: str
    active_objs: int
    total_objs: int
    object_size: int
    active_bytes: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PerformanceReport:
    pressure: tuple[PressureSample, ...]
    interrupts: tuple[CpuLoad, ...]
    softirqs: tuple[CpuLoad, ...]
    slabinfo: tuple[SlabCache, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def performance_report(
    root: Path = Path("/"),
    max_slab_caches: int = 12,
) -> PerformanceReport:
    proc = root / "proc"
    pressure = tuple(
        _pressure_sample(proc / "pressure" / name, name)
        for name in ("cpu", "memory", "io")
        if (proc / "pressure" / name).exists()
    )
    interrupts = _interrupt_summary(proc / "interrupts")
    softirqs = _interrupt_summary(proc / "softirqs")
    slabinfo = _slabinfo(proc / "slabinfo", max_slab_caches)
    recommendations = _recommendations(pressure, interrupts, softirqs, slabinfo)
    return PerformanceReport(
        pressure=pressure,
        interrupts=interrupts,
        softirqs=softirqs,
        slabinfo=slabinfo,
        recommendations=tuple(recommendations),
    )


def _pressure_sample(path: Path, resource: str) -> PressureSample:
    lines = _read_lines(path)
    some = _parse_pressure_line(next((line for line in lines if line.startswith("some ")), None))
    full = _parse_pressure_line(next((line for line in lines if line.startswith("full ")), None))
    return PressureSample(
        resource=resource,
        some_avg10=some.get("avg10"),
        some_avg60=some.get("avg60"),
        some_avg300=some.get("avg300"),
        some_total=some.get("total"),
        full_avg10=full.get("avg10"),
        full_avg60=full.get("avg60"),
        full_avg300=full.get("avg300"),
        full_total=full.get("total"),
        raw=lines,
    )


def _parse_pressure_line(line: str | None) -> dict[str, float | int]:
    parsed: dict[str, float | int] = {}
    if not line:
        return parsed
    for token in line.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", maxsplit=1)
        if key == "total":
            try:
                parsed[key] = int(value)
            except ValueError:
                continue
        else:
            try:
                parsed[key] = float(value)
            except ValueError:
                continue
    return parsed


def _interrupt_summary(path: Path) -> tuple[CpuLoad, ...]:
    lines = _read_lines(path)
    if not lines:
        return ()
    header = []
    counts: dict[str, int] = {}
    for line in lines:
        parts = line.split()
        if parts and all(part.startswith("CPU") for part in parts):
            header = parts
            continue
        if ":" not in line or not header:
            continue
        _, raw_counts = line.split(":", maxsplit=1)
        values = [part for part in raw_counts.split() if part.isdigit()]
        for index, value in enumerate(values[: len(header)]):
            cpu = header[index]
            counts[cpu] = counts.get(cpu, 0) + int(value)
    return tuple(sorted((CpuLoad(cpu=cpu, total=total) for cpu, total in counts.items()), key=lambda item: item.total, reverse=True))


def _slabinfo(path: Path, limit: int) -> tuple[SlabCache, ...]:
    lines = _read_lines(path)
    if len(lines) <= 2:
        return ()
    caches = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[0]
        try:
            active_objs = int(parts[1])
            total_objs = int(parts[2])
            object_size = int(parts[3])
        except ValueError:
            continue
        caches.append(
            SlabCache(
                name=name,
                active_objs=active_objs,
                total_objs=total_objs,
                object_size=object_size,
                active_bytes=active_objs * object_size,
            )
        )
    caches.sort(key=lambda cache: cache.active_bytes, reverse=True)
    return tuple(caches[:limit])


def _recommendations(
    pressure: tuple[PressureSample, ...],
    interrupts: tuple[CpuLoad, ...],
    softirqs: tuple[CpuLoad, ...],
    slabinfo: tuple[SlabCache, ...],
) -> list[str]:
    recommendations = []
    if any(
        (sample.some_avg10 is not None and sample.some_avg10 >= 0.50) or (sample.full_avg10 is not None and sample.full_avg10 >= 0.25)
        for sample in pressure
    ):
        recommendations.append("PSI shows meaningful pressure; check for contention, swaps, or storage stalls.")
    if _is_skewed(interrupts):
        recommendations.append(f"Interrupt load is concentrated on {interrupts[0].cpu}; consider irqbalance or affinity tuning.")
    if _is_skewed(softirqs):
        recommendations.append(f"Softirq load is concentrated on {softirqs[0].cpu}; inspect networking or storage softirq hotspots.")
    if slabinfo and slabinfo[0].active_bytes >= 256 * 1024 * 1024:
        recommendations.append(f"Top slab cache {slabinfo[0].name} is large; watch kernel memory growth if it keeps climbing.")
    return recommendations


def _is_skewed(cpus: tuple[CpuLoad, ...]) -> bool:
    if len(cpus) < 2:
        return bool(cpus)
    top = cpus[0].total
    second = cpus[1].total
    total = sum(cpu.total for cpu in cpus)
    if total == 0:
        return False
    return top / total >= 0.55 and top >= second * 2.0


def _read_lines(path: Path) -> tuple[str, ...]:
    try:
        return tuple(line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
    except OSError:
        return ()
