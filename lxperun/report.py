from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Iterable

from .capabilities import capability_report
from .crash import crash_report
from .containers import container_report
from .doctor import diagnose, group_issues
from .firewall import firewall_report
from .hardware import hardware_report
from .linux import snapshot
from .network import network_report
from .performance import performance_report
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
    containers: object | None
    firewall: object | None
    performance: object | None
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
        containers=container_report(),
        firewall=firewall_report(),
        performance=performance_report(),
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
    _add_containers_section(lines, report.containers)
    _add_firewall_section(lines, report.firewall)
    _add_performance_section(lines, report.performance)
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


def report_to_html(report: PerunReport, limit: int = 12) -> str:
    doctor_groups = group_issues(report.doctor.issues)
    sections = {
        "snapshot": _snapshot_cards(report.snapshot),
        "capabilities": _capability_table(report.capabilities),
        "security": _finding_table(report.security),
        "containers": _finding_table(report.containers),
        "firewall": _firewall_table(report.firewall, limit),
        "performance": _performance_table(report.performance, limit),
        "rings": _rings_table(report.rings),
        "doctor": _doctor_table(report.doctor, doctor_groups, limit),
        "network": _network_table(report.network, limit),
        "processes": _processes_table(report.processes, limit),
        "services": _services_table(report.services, limit),
        "storage": _storage_table(report.storage, limit),
        "hardware": _hardware_table(report.hardware, limit),
        "trace": _trace_table(report.trace),
        "crash": _crash_table(report.crash, limit),
    }

    cards = [
        ("Generated", report.generated_at),
        ("Issues", str(len(report.doctor.issues))),
        ("Grouped", str(len(doctor_groups))),
        ("Coredumps", str(report.crash.coredump_count)),
        ("Processes", str(report.processes.total)),
        ("Mounts", str(report.storage.mount_count)),
    ]

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LxPerun Report</title>
  <style>{css}</style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div>
        <div class="eyebrow">LxPerun</div>
        <h1>Linux diagnostics report</h1>
        <p>Readable bugreport with grouped findings, tables, and fast navigation.</p>
      </div>
      <div class="hero-badge">
        <div class="hero-badge-label">Generated at</div>
        <div class="hero-badge-value">{generated_at}</div>
      </div>
    </section>
    <section class="cards">{cards_html}</section>
    <section class="toc">
      <h2>Contents</h2>
      <div class="toc-grid">{toc_html}</div>
    </section>
    {sections_html}
  </main>
</body>
</html>
""".format(
        css=_html_css(),
        generated_at=escape(report.generated_at),
        cards_html="".join(_card_html(label, value) for label, value in cards),
        toc_html="".join(f'<a href="#{slug}">{title}</a>' for slug, title in _table_of_contents()),
        sections_html="".join(
            _html_section(slug, title, body)
            for slug, title, body in (
                ("system", "System", sections["snapshot"]),
                ("capabilities", "Capabilities", sections["capabilities"]),
                ("security", "Security", sections["security"]),
                ("containers", "Containers", sections["containers"]),
                ("firewall", "Firewall", sections["firewall"]),
                ("performance", "Performance", sections["performance"]),
                ("rings", "Rings", sections["rings"]),
                ("doctor", "Doctor", sections["doctor"]),
                ("network", "Network", sections["network"]),
                ("processes", "Processes", sections["processes"]),
                ("services", "Services", sections["services"]),
                ("storage", "Storage", sections["storage"]),
                ("hardware", "Hardware", sections["hardware"]),
                ("trace", "Trace", sections["trace"]),
                ("crash", "Crash", sections["crash"]),
            )
        ),
    )


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


def _add_containers_section(lines: list[str], container_report_obj: object | None) -> None:
    if container_report_obj is None:
        return
    lines.append("## Containers")
    lines.append(f"- Root: `{container_report_obj.is_root}`")
    lines.append(f"- Effective UID: `{container_report_obj.effective_uid}`")
    lines.append(f"- Signals: `{len(container_report_obj.signals)}`")
    lines.append(f"- Findings: `{len(container_report_obj.findings)}`")
    for finding in container_report_obj.findings:
        lines.append(f"- `{finding.severity.upper()}` `{finding.category}`: {finding.message}")
    lines.append("")


def _add_firewall_section(lines: list[str], firewall_report_obj: object | None) -> None:
    if firewall_report_obj is None:
        return
    lines.append("## Firewall")
    lines.append(f"- Backends: `{len(firewall_report_obj.backends)}`")
    lines.append(f"- Mappings: `{len(firewall_report_obj.mappings)}`")
    for backend in firewall_report_obj.backends:
        lines.append(f"- `{backend.name}`: `{backend.available}`")
    for mapping in firewall_report_obj.mappings[:10]:
        lines.append(f"- `{mapping.backend}` `{mapping.protocol}/{mapping.port}` `{mapping.decision}` - {mapping.reason}")
    lines.append("")


def _add_performance_section(lines: list[str], performance_report_obj: object | None) -> None:
    if performance_report_obj is None:
        return
    lines.append("## Performance")
    lines.append(f"- PSI samples: `{len(performance_report_obj.pressure)}`")
    lines.append(f"- Interrupt CPUs: `{len(performance_report_obj.interrupts)}`")
    lines.append(f"- Softirq CPUs: `{len(performance_report_obj.softirqs)}`")
    lines.append(f"- Slab caches: `{len(performance_report_obj.slabinfo)}`")
    for sample in performance_report_obj.pressure:
        lines.append(f"- `{sample.resource}` pressure")
    for cache in performance_report_obj.slabinfo[:10]:
        lines.append(f"- `{cache.name}` `{cache.active_bytes}` bytes active")
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


def _snapshot_cards(snapshot_report: object) -> str:
    rows = [
        ("Host", snapshot_report.identity.hostname),
        ("Kernel", snapshot_report.identity.kernel),
        ("Distro", snapshot_report.identity.distribution),
        ("Uptime", f"{snapshot_report.uptime:.2f} s"),
        ("Load", f"{snapshot_report.load_average[0]:.2f} / {snapshot_report.load_average[1]:.2f} / {snapshot_report.load_average[2]:.2f}"),
    ]
    return _kv_table(rows)


def _capability_table(capabilities_report: object) -> str:
    rows = [("Root", str(capabilities_report.is_root)), ("Effective UID", str(capabilities_report.effective_uid))]
    rows.extend((probe.name, f"{probe.available} — {probe.detail}") for probe in capabilities_report.probes)
    return _kv_table(rows)


def _finding_table(report_obj: object | None) -> str:
    if report_obj is None:
        return _empty_block("Not available in this run.")
    rows = [
        ("Root", str(report_obj.is_root)),
        ("Effective UID", str(report_obj.effective_uid)),
    ]
    signals = getattr(report_obj, "signals", ())
    if signals:
        rows.extend((signal.name, f"{signal.available} — {signal.detail}") for signal in signals)
    findings = getattr(report_obj, "findings", ())
    if findings:
        return _table(
            ("Severity", "Category", "Message"),
            ((finding.severity.upper(), finding.category, finding.message) for finding in findings),
        ) + _kv_table(rows)
    return _kv_table(rows)


def _firewall_table(report_obj: object | None, limit: int) -> str:
    if report_obj is None:
        return _empty_block("No firewall backend was detected.")
    rows = [("Backends", str(len(report_obj.backends))), ("Mappings", str(len(report_obj.mappings)))]
    html_parts = [_kv_table(rows)]
    html_parts.append(_table(("Backend", "Available", "Policy"), ((backend.name, str(backend.available), backend.policy or "-") for backend in report_obj.backends)))
    if report_obj.mappings:
        html_parts.append(_table(("Backend", "Proto/Port", "Address", "Decision"), ((mapping.backend, f"{mapping.protocol}/{mapping.port}", mapping.address, mapping.decision) for mapping in report_obj.mappings[:limit])))
    return "".join(html_parts)


def _performance_table(report_obj: object | None, limit: int) -> str:
    if report_obj is None:
        return _empty_block("No performance data was collected.")
    html_parts = [
        _kv_table(
            (
                ("PSI samples", str(len(report_obj.pressure))),
                ("Interrupt CPUs", str(len(report_obj.interrupts))),
                ("Softirq CPUs", str(len(report_obj.softirqs))),
                ("Slab caches", str(len(report_obj.slabinfo))),
            )
        )
    ]
    if report_obj.pressure:
        html_parts.append(_table(("Resource", "some avg10/60/300", "full avg10/60/300"), ((sample.resource, f"{sample.some_avg10}/{sample.some_avg60}/{sample.some_avg300}", f"{sample.full_avg10}/{sample.full_avg60}/{sample.full_avg300}") for sample in report_obj.pressure)))
    if report_obj.slabinfo:
        html_parts.append(_table(("Cache", "Active", "Object size", "Active bytes"), ((cache.name, str(cache.active_objs), str(cache.object_size), str(cache.active_bytes)) for cache in report_obj.slabinfo[:limit])))
    return "".join(html_parts)


def _rings_table(rings_report: object) -> str:
    return _table(("Ring", "Name", "Availability"), ((layer.ring, layer.name, str(layer.available)) for layer in rings_report.layers))


def _doctor_table(doctor_report: object, groups: tuple[object, ...], limit: int) -> str:
    if not doctor_report.issues:
        return _empty_block("No issues found.")
    parts = [f'<div class="subtle">Raw issues: {len(doctor_report.issues)} · grouped findings: {len(groups)}</div>']
    parts.append(_table(("Severity", "Finding", "Count"), ((group.severity.upper(), group.title, str(group.count)) for group in groups)))
    parts.append("<div class=\"spacer\"></div>")
    parts.append("<div class=\"subtle\">Top raw issues</div>")
    parts.append(_table(("Severity", "Source", "Message"), ((issue.severity.upper(), issue.source, issue.message) for issue in doctor_report.issues[:limit])))
    return "".join(parts)


def _network_table(network_report_obj: object | None, limit: int) -> str:
    if network_report_obj is None:
        return _empty_block("No network data was collected.")
    parts = [
        _kv_table(
            (
                ("Sockets", str(len(network_report_obj.sockets))),
                ("Listening", str(len(network_report_obj.listening_sockets))),
                ("ARP entries", str(len(network_report_obj.arp))),
                ("Conntrack", str(len(network_report_obj.conntrack))),
            )
        )
    ]
    parts.append(_table(("Interface", "RX", "TX", "RX rate", "TX rate"), ((sample.name, str(sample.rx_bytes), str(sample.tx_bytes), str(sample.rx_rate_bps or "-"), str(sample.tx_rate_bps or "-")) for sample in network_report_obj.bandwidth.interfaces[:limit])))
    return "".join(parts)


def _processes_table(processes_report: object, limit: int) -> str:
    return _table(("PID", "User", "RSS", "FD", "State", "Command"), ((process.pid, process.user or "-", str(process.vm_rss), str(process.fd_count), process.state, " ".join(process.cmdline) if process.cmdline else process.name or "-") for process in processes_report.processes[:limit]))


def _services_table(services_report: object, limit: int) -> str:
    parts = [_kv_table((("Total units", str(services_report.total_units)), ("Failed units", str(services_report.failed_count))))]
    if services_report.failed_units:
        parts.append(_table(("Name", "Active", "Sub", "Description"), ((unit.name, unit.active, unit.sub, unit.description) for unit in services_report.failed_units[:limit])))
    return "".join(parts)


def _storage_table(storage_report_obj: object, limit: int) -> str:
    parts = [_kv_table((("Mounts", str(storage_report_obj.mount_count)), ("Devices", str(storage_report_obj.device_count))))]
    parts.append(_table(("Mount", "Filesystem", "Used %"), ((mount.mount_point, mount.filesystem, f"{mount.used_percent:.1f}%") for mount in storage_report_obj.mounts[:limit])))
    return "".join(parts)


def _hardware_table(hardware_report_obj: object, limit: int) -> str:
    parts = [_kv_table((("PCI", str(hardware_report_obj.pci_count)), ("USB", str(hardware_report_obj.usb_count)), ("Sensors", str(hardware_report_obj.sensor_count)), ("NUMA nodes", str(hardware_report_obj.numa_count))))]
    parts.append(_table(("PCI BDF", "Vendor", "Device"), ((device.bdf, device.vendor_id or "-", device.device_id or "-") for device in hardware_report_obj.pci_devices[:limit])))
    if hardware_report_obj.usb_devices:
        parts.append(_table(("USB path", "VID", "PID", "Product"), ((device.path, device.id_vendor or "-", device.id_product or "-", device.product or device.manufacturer or "-") for device in hardware_report_obj.usb_devices[:limit])))
    return "".join(parts)


def _trace_table(trace_report_obj: object) -> str:
    parts = [_kv_table((("Ready", str(trace_report_obj.ready)), ("perf_event_paranoid", str(trace_report_obj.perf_event_paranoid))))]
    if trace_report_obj.recommendations:
        parts.append(_table(("Recommendation",), ((recommendation,) for recommendation in trace_report_obj.recommendations)))
    return "".join(parts)


def _crash_table(crash_report_obj: object, limit: int) -> str:
    parts = [_kv_table((("Ready", str(crash_report_obj.ready)), ("Coredumps", str(crash_report_obj.coredump_count))))]
    if crash_report_obj.coredump_summaries:
        parts.append(_table(("Coredump summary",), ((line,) for line in crash_report_obj.coredump_summaries[:limit])))
    if crash_report_obj.latest_info:
        parts.append(f"<pre class=\"code\">{escape(crash_report_obj.latest_info)}</pre>")
    return "".join(parts)


def _html_section(slug: str, title: str, body: str) -> str:
    return f'<section class="section" id="{slug}"><h2>{escape(title)}</h2>{body}</section>'


def _card_html(label: str, value: str) -> str:
    return f'<div class="card"><div class="card-label">{escape(label)}</div><div class="card-value">{escape(value)}</div></div>'


def _table(headers: tuple[str, ...], rows: Iterable[tuple[object, ...]]) -> str:
    head = "".join(f"<th>{escape(str(header))}</th>" for header in headers)
    body_rows = []
    for row in rows:
        body_rows.append("<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>")
    return f'<table class="table"><thead><tr>{head}</tr></thead><tbody>{"".join(body_rows)}</tbody></table>'


def _kv_table(rows: Iterable[tuple[str, object]]) -> str:
    return _table(("Key", "Value"), tuple((key, value) for key, value in rows))


def _empty_block(text: str) -> str:
    return f'<div class="empty">{escape(text)}</div>'


def _table_of_contents() -> tuple[tuple[str, str], ...]:
    return (
        ("system", "System"),
        ("capabilities", "Capabilities"),
        ("security", "Security"),
        ("containers", "Containers"),
        ("firewall", "Firewall"),
        ("performance", "Performance"),
        ("rings", "Rings"),
        ("doctor", "Doctor"),
        ("network", "Network"),
        ("processes", "Processes"),
        ("services", "Services"),
        ("storage", "Storage"),
        ("hardware", "Hardware"),
        ("trace", "Trace"),
        ("crash", "Crash"),
    )


def _html_css() -> str:
    return """
:root {
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #121a33;
  --panel-2: #17213e;
  --line: rgba(255,255,255,.08);
  --text: #e8eefc;
  --muted: #9bb0da;
  --accent: #74c0fc;
  --accent-2: #8ce99a;
  --warn: #ffd43b;
  --bad: #ff8787;
  --good: #69db7c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    radial-gradient(circle at top left, rgba(116, 192, 252, 0.14), transparent 35%),
    radial-gradient(circle at top right, rgba(140, 233, 154, 0.10), transparent 30%),
    linear-gradient(180deg, #070b16, var(--bg));
  color: var(--text);
}
.page { max-width: 1320px; margin: 0 auto; padding: 32px 20px 64px; }
.hero {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  align-items: end;
  padding: 28px;
  border: 1px solid var(--line);
  border-radius: 24px;
  background: linear-gradient(180deg, rgba(18,26,51,.95), rgba(11,16,32,.96));
  box-shadow: 0 24px 70px rgba(0,0,0,.35);
}
.eyebrow {
  color: var(--accent-2);
  text-transform: uppercase;
  letter-spacing: .18em;
  font-size: 12px;
  font-weight: 700;
  margin-bottom: 10px;
}
h1, h2 { margin: 0; line-height: 1.1; }
h1 { font-size: clamp(2rem, 4vw, 3.6rem); }
h2 { font-size: 1.35rem; margin-bottom: 16px; }
p { margin: 12px 0 0; color: var(--muted); max-width: 72ch; }
.hero-badge {
  min-width: 260px;
  padding: 16px 18px;
  border-radius: 18px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.03);
}
.hero-badge-label { color: var(--muted); font-size: .85rem; }
.hero-badge-value { margin-top: 8px; font-weight: 700; word-break: break-word; }
.cards {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 14px;
  margin: 18px 0 24px;
}
.card {
  padding: 18px;
  border-radius: 18px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.03);
}
.card-label { color: var(--muted); font-size: .86rem; margin-bottom: 8px; }
.card-value { font-size: 1.1rem; font-weight: 700; }
.toc, .section {
  border: 1px solid var(--line);
  border-radius: 22px;
  background: rgba(18,26,51,.78);
  padding: 22px;
  margin-bottom: 18px;
}
.toc-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.toc-grid a {
  color: var(--text);
  text-decoration: none;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.03);
  padding: 8px 12px;
  border-radius: 999px;
}
.toc-grid a:hover { border-color: rgba(116,192,252,.5); color: var(--accent); }
.table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0 0;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: rgba(0,0,0,.12);
}
.table th, .table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
  text-align: left;
}
.table th {
  color: #d5e2ff;
  font-size: .85rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  background: rgba(255,255,255,.03);
}
.table tr:last-child td { border-bottom: none; }
.table td { color: var(--text); }
.subtle { color: var(--muted); font-size: .93rem; margin-top: 4px; }
.empty {
  padding: 18px;
  border: 1px dashed rgba(255,255,255,.12);
  border-radius: 16px;
  color: var(--muted);
  margin-top: 12px;
}
.spacer { height: 14px; }
.code {
  margin: 12px 0 0;
  padding: 16px;
  border-radius: 16px;
  border: 1px solid var(--line);
  background: rgba(0,0,0,.25);
  overflow: auto;
  color: #f3f7ff;
}
@media (max-width: 1080px) { .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 720px) {
  .hero { flex-direction: column; align-items: start; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
""".strip()
