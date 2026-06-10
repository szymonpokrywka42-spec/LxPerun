from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .capabilities import capability_report
from .crash import crash_report
from .doctor import diagnose
from .hardware import hardware_report
from .linux import snapshot
from .network import network_report
from .processes import process_report
from .rings import access_map
from .security import security_report
from .services import service_report
from .storage import storage_report
from .trace import trace_report


@dataclass(frozen=True)
class PerunReport:
    generated_at: str
    snapshot: object
    capabilities: object
    security: object
    rings: object
    doctor: object
    processes: object
    services: object
    storage: object
    hardware: object
    trace: object
    crash: object
    network: object | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def generate_report(project_root: Path | str = ".", limit: int = 12, include_latest_crash: bool = False) -> PerunReport:
    generated_at = datetime.now(timezone.utc).isoformat()
    return PerunReport(
        generated_at=generated_at,
        snapshot=snapshot(),
        capabilities=capability_report(),
        security=security_report(),
        rings=access_map(),
        doctor=diagnose(project_root),
        processes=process_report(),
        services=service_report(),
        storage=storage_report(),
        hardware=hardware_report(),
        trace=trace_report(),
        crash=crash_report(limit=limit, include_latest=include_latest_crash),
        network=network_report(),
    )


def report_to_markdown(report: PerunReport, limit: int = 12) -> str:
    lines: list[str] = []
    lines.append("# LxPerun Report")
    lines.append("")
    lines.append(f"Generated at: `{report.generated_at}`")
    lines.append("")
    _add_snapshot_section(lines, report.snapshot)
    _add_capabilities_section(lines, report.capabilities)
    _add_security_section(lines, report.security)
    _add_rings_section(lines, report.rings)
    _add_doctor_section(lines, report.doctor)
    _add_network_section(lines, report.network)
    _add_processes_section(lines, report.processes, limit)
    _add_services_section(lines, report.services, limit)
    _add_storage_section(lines, report.storage, limit)
    _add_hardware_section(lines, report.hardware, limit)
    _add_trace_section(lines, report.trace)
    _add_crash_section(lines, report.crash)
    return "\n".join(lines).rstrip() + "\n"


def _add_snapshot_section(lines: list[str], snapshot_report: object) -> None:
    lines.append("## System")
    lines.append(f"- Host: `{snapshot_report.identity.hostname}`")
    lines.append(f"- Kernel: `{snapshot_report.identity.kernel}`")
    lines.append(f"- Distro: `{snapshot_report.identity.distribution}`")
    lines.append(f"- Uptime: `{snapshot_report.uptime:.2f}` seconds")
    lines.append(f"- Load: `{snapshot_report.load_average[0]:.2f}`, `{snapshot_report.load_average[1]:.2f}`, `{snapshot_report.load_average[2]:.2f}`")
    lines.append("")


def _add_capabilities_section(lines: list[str], capabilities_report: object) -> None:
    lines.append("## Capabilities")
    lines.append(f"- Root: `{capabilities_report.is_root}`")
    lines.append(f"- Effective UID: `{capabilities_report.effective_uid}`")
    if not capabilities_report.is_root:
        lines.append("- Tip: rerun with `--root` to unlock deeper kernel, TPM, and cleanup access.")
    for probe in capabilities_report.probes:
        lines.append(f"- `{probe.name}`: `{probe.available}` - {probe.detail}")
    lines.append("")


def _add_security_section(lines: list[str], security_report_obj: object) -> None:
    lines.append("## Security")
    lines.append(f"- Root: `{security_report_obj.is_root}`")
    lines.append(f"- Effective UID: `{security_report_obj.effective_uid}`")
    lines.append(f"- Signals: `{len(security_report_obj.signals)}`")
    lines.append(f"- Issues: `{getattr(security_report_obj, 'issue_count', 0)}`")
    lines.append(f"- Advisories: `{getattr(security_report_obj, 'advisory_count', 0)}`")
    for finding in security_report_obj.findings[:10]:
        lines.append(f"- `{finding.severity.upper()}` `{finding.category}`: {finding.message}")
    for recommendation in security_report_obj.recommendations:
        lines.append(f"- {recommendation}")
    lines.append("")


def _add_rings_section(lines: list[str], rings_report: object) -> None:
    lines.append("## Rings")
    for layer in rings_report.layers:
        lines.append(f"- Ring `{layer.ring}` `{layer.name}`: `{layer.available}`")
    lines.append("")


def _add_doctor_section(lines: list[str], doctor_report: object) -> None:
    lines.append("## Doctor")
    if not doctor_report.issues:
        lines.append("- No issues found.")
        lines.append("")
        return
    for issue in doctor_report.issues:
        lines.append(f"- `{issue.severity.upper()}` `{issue.source}`: {issue.message}")
    lines.append("")


def _add_network_section(lines: list[str], network_report_obj: object | None) -> None:
    if network_report_obj is None:
        return
    lines.append("## Network")
    lines.append(f"- Sockets: `{len(network_report_obj.sockets)}`")
    lines.append(f"- Listening sockets: `{len(network_report_obj.listening_sockets)}`")
    lines.append(f"- ARP entries: `{len(network_report_obj.arp)}`")
    lines.append(f"- Conntrack entries: `{len(network_report_obj.conntrack)}`")
    lines.append(f"- Interfaces sampled: `{len(network_report_obj.bandwidth.interfaces)}`")
    lines.append("")


def _add_processes_section(lines: list[str], processes_report: object, limit: int) -> None:
    lines.append("## Processes")
    lines.append(f"- Total: `{processes_report.total}`")
    lines.append(f"- Unreadable: `{processes_report.unreadable}`")
    lines.append(f"- Zombies: `{len([process for process in processes_report.processes if process.state and process.state.startswith('Z')])}`")
    for process in processes_report.processes[:limit]:
        command = " ".join(process.cmdline) if process.cmdline else process.name or "-"
        lines.append(f"- PID `{process.pid}` `{process.user or '-'}` `{command}`")
    lines.append("")


def _add_services_section(lines: list[str], services_report: object, limit: int) -> None:
    lines.append("## Services")
    lines.append(f"- Total units: `{services_report.total_units}`")
    lines.append(f"- Failed units: `{services_report.failed_count}`")
    for unit in services_report.failed_units[:limit]:
        lines.append(f"- `{unit.name}` `{unit.active}/{unit.sub}` - {unit.description}")
    if not services_report.failed_units and services_report.raw_failed_units:
        for name in services_report.raw_failed_units[:limit]:
            lines.append(f"- `{name}`")
    lines.append("")


def _add_storage_section(lines: list[str], storage_report_obj: object, limit: int) -> None:
    lines.append("## Storage")
    lines.append(f"- Mounts: `{storage_report_obj.mount_count}`")
    lines.append(f"- Devices: `{storage_report_obj.device_count}`")
    for mount in storage_report_obj.mounts[:limit]:
        lines.append(f"- `{mount.mount_point}` `{mount.filesystem}` `{mount.used_percent:.1f}%`")
    lines.append("")


def _add_hardware_section(lines: list[str], hardware_report_obj: object, limit: int) -> None:
    lines.append("## Hardware")
    lines.append(f"- PCI: `{hardware_report_obj.pci_count}`")
    lines.append(f"- USB: `{hardware_report_obj.usb_count}`")
    lines.append(f"- Sensors: `{hardware_report_obj.sensor_count}`")
    lines.append(f"- NUMA nodes: `{hardware_report_obj.numa_count}`")
    for device in hardware_report_obj.pci_devices[:limit]:
        lines.append(f"- PCI `{device.bdf}` `{device.vendor_id or '-'}`:`{device.device_id or '-'}`")
    lines.append("")


def _add_trace_section(lines: list[str], trace_report_obj: object) -> None:
    lines.append("## Trace")
    lines.append(f"- Ready: `{trace_report_obj.ready}`")
    lines.append(f"- perf_event_paranoid: `{trace_report_obj.perf_event_paranoid}`")
    for recommendation in trace_report_obj.recommendations:
        lines.append(f"- {recommendation}")
    lines.append("")


def _add_crash_section(lines: list[str], crash_report_obj: object) -> None:
    lines.append("## Crash")
    lines.append(f"- Ready: `{crash_report_obj.ready}`")
    lines.append(f"- Coredumps: `{crash_report_obj.coredump_count}`")
    for recommendation in crash_report_obj.recommendations:
        lines.append(f"- {recommendation}")
    if crash_report_obj.latest_info:
        lines.append("")
        lines.append("### Latest")
        lines.append("```text")
        lines.extend(crash_report_obj.latest_info.splitlines())
        lines.append("```")
    lines.append("")
