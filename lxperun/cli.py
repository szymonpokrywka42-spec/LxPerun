"""Command line interface for LxPerun Linux helpers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .capabilities import capability_report
from .crash import crash_report
from .doctor import diagnose
from .formatting import human_bytes, human_sensor_value, human_uptime
from .hardware import hardware_report
from .linux import format_bytes, snapshot
from .processes import process_report, top_by_memory, zombie_processes
from .report import generate_report, report_to_markdown
from .rings import access_map
from .services import service_report
from .storage import storage_report
from .trace import trace_command, trace_report
from .ui import bold, cyan, dim, green, red, supports_color, yellow


def main() -> None:
    parser = argparse.ArgumentParser(description="LxPerun Linux diagnostics.")
    subparsers = parser.add_subparsers(dest="command")

    snapshot_parser = subparsers.add_parser("snapshot", help="show a Linux system snapshot")
    snapshot_parser.add_argument("--json", action="store_true", help="print raw JSON")

    doctor_parser = subparsers.add_parser("doctor", help="diagnose common system problems")
    doctor_parser.add_argument("--json", action="store_true", help="print raw JSON")
    doctor_parser.add_argument("--project-root", default=".", help="scan this tree for Python syntax errors")

    rings_parser = subparsers.add_parser("rings", help="show privilege and platform-layer access")
    rings_parser.add_argument("--json", action="store_true", help="print raw JSON")

    capabilities_parser = subparsers.add_parser("capabilities", help="show diagnostic capabilities")
    capabilities_parser.add_argument("--json", action="store_true", help="print raw JSON")

    processes_parser = subparsers.add_parser("processes", help="show process diagnostics")
    processes_parser.add_argument("--json", action="store_true", help="print raw JSON")
    processes_parser.add_argument("--limit", type=int, default=12, help="number of top memory processes to print")

    services_parser = subparsers.add_parser("services", help="show systemd service diagnostics")
    services_parser.add_argument("--json", action="store_true", help="print raw JSON")
    services_parser.add_argument("--limit", type=int, default=12, help="number of failed services to print")

    storage_parser = subparsers.add_parser("storage", help="show storage diagnostics")
    storage_parser.add_argument("--json", action="store_true", help="print raw JSON")
    storage_parser.add_argument("--limit", type=int, default=12, help="number of mount rows to print")

    hardware_parser = subparsers.add_parser("hardware", help="show hardware inventory")
    hardware_parser.add_argument("--json", action="store_true", help="print raw JSON")
    hardware_parser.add_argument("--limit", type=int, default=12, help="number of rows to print per section")

    trace_parser = subparsers.add_parser("trace", help="show tracing readiness or trace a command")
    trace_parser.add_argument("--json", action="store_true", help="print raw JSON")
    trace_parser.add_argument("--mode", choices=("report", "strace", "perf"), default="report", help="trace mode")
    trace_parser.add_argument("command", nargs=argparse.REMAINDER, help="command to execute under trace")

    crash_parser = subparsers.add_parser("crash", help="inspect coredumps and crash readiness")
    crash_parser.add_argument("--json", action="store_true", help="print raw JSON")
    crash_parser.add_argument("--limit", type=int, default=8, help="number of coredump entries to print")
    crash_parser.add_argument("--latest", action="store_true", help="include latest coredump info")

    report_parser = subparsers.add_parser("report", help="generate a unified LxPerun report")
    report_parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="output format")
    report_parser.add_argument("--output", help="write the report to a file")
    report_parser.add_argument("--limit", type=int, default=12, help="number of top rows to include per section")
    report_parser.add_argument("--project-root", default=".", help="scan this tree for Python syntax errors")
    report_parser.add_argument("--latest", action="store_true", help="include latest crash info")

    help_parser = subparsers.add_parser("help", help="show command guide")
    help_parser.add_argument("topic", nargs="?", help="optional command name to explain")

    all_parser = subparsers.add_parser("all", help="run every LxPerun report")
    all_parser.add_argument("--json", action="store_true", help="print raw JSON")
    all_parser.add_argument("--limit", type=int, default=12, help="number of top memory processes to print")
    all_parser.add_argument("--project-root", default=".", help="scan this tree for Python syntax errors")

    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--raw", action="store_true", help="show raw numeric values where possible")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args()

    command = args.command or "snapshot"
    color_enabled = supports_color(not args.no_color)
    if command == "doctor":
        _print_doctor(json_output=args.json, project_root=args.project_root, color_enabled=color_enabled)
    elif command == "rings":
        _print_rings(json_output=args.json, color_enabled=color_enabled)
    elif command == "capabilities":
        _print_capabilities(json_output=args.json, color_enabled=color_enabled)
    elif command == "processes":
        _print_processes(json_output=args.json, limit=args.limit, raw=args.raw, color_enabled=color_enabled)
    elif command == "services":
        _print_services(json_output=args.json, limit=args.limit, color_enabled=color_enabled)
    elif command == "storage":
        _print_storage(json_output=args.json, limit=args.limit, raw=args.raw, color_enabled=color_enabled)
    elif command == "hardware":
        _print_hardware(json_output=args.json, limit=args.limit, raw=args.raw, color_enabled=color_enabled)
    elif command == "trace":
        _print_trace(json_output=args.json, mode=args.mode, command=args.command, color_enabled=color_enabled)
    elif command == "crash":
        _print_crash(json_output=args.json, limit=args.limit, latest=args.latest, color_enabled=color_enabled)
    elif command == "help":
        _print_help(topic=args.topic, color_enabled=color_enabled)
    elif command == "report":
        _print_report(
            output_format=args.format,
            output=args.output,
            limit=args.limit,
            project_root=args.project_root,
            latest=args.latest,
        )
    elif command == "all":
        _print_all(json_output=args.json, limit=args.limit, project_root=args.project_root, raw=args.raw, color_enabled=color_enabled)
    else:
        _print_snapshot(json_output=args.json, raw=args.raw, color_enabled=color_enabled)


def _print_snapshot(json_output: bool, raw: bool, color_enabled: bool) -> None:
    info = snapshot()
    if json_output:
        print(json.dumps(info.to_dict(), indent=2))
        return

    print(cyan("System", color_enabled))
    print(f"Host:      {info.identity.hostname}")
    print(f"Kernel:    {info.identity.kernel} ({info.identity.machine})")
    print(f"Distro:    {info.identity.distribution}")
    if info.identity.product_vendor or info.identity.product_name:
        vendor = info.identity.product_vendor or "unknown vendor"
        product = info.identity.product_name or "unknown product"
        print(f"Machine:   {vendor} {product}")
    uptime_text = f"{info.uptime / 3600:.1f} h" if raw else human_uptime(info.uptime)
    print(f"Uptime:    {uptime_text}")
    print(f"Load:      {info.load_average[0]:.2f} {info.load_average[1]:.2f} {info.load_average[2]:.2f}")
    print(f"CPU:       {info.cpu_info.model_name or info.cpu_info.architecture} ({info.cpu_info.logical_cpus} threads)")
    print(
        "Memory:    "
        f"{format_bytes(info.memory.used)} / {format_bytes(info.memory.total)} "
        f"({info.memory.used_percent:.2f}%)"
    )
    print(
        "Disk /:    "
        f"{format_bytes(info.root_disk.used)} / {format_bytes(info.root_disk.total)} "
        f"({info.root_disk.used_percent:.2f}%)"
    )
    print(dim("Block:", color_enabled))
    for device in info.block_devices:
        size = "unknown" if device.size is None else format_bytes(device.size)
        kind = "hdd" if device.rotational else "ssd/nvme" if device.rotational is False else "unknown"
        print(f"  {device.name:<10} {size:<10} {kind:<8} {device.vendor or ''} {device.model or ''}".rstrip())
    print(dim("Network:", color_enabled))
    for interface in info.network:
        state = interface.operstate or "unknown"
        ipv4 = interface.ipv4 or "-"
        rx = format_bytes(interface.rx_bytes or 0)
        tx = format_bytes(interface.tx_bytes or 0)
        print(f"  {interface.name:<12} {state:<8} ip={ipv4:<15} rx={rx:<10} tx={tx:<10}")
    print(f"Mounts:    {len(info.mounts)}")
    print(f"Modules:   {len(info.kernel_modules)}")


def _print_doctor(json_output: bool, project_root: str, color_enabled: bool) -> None:
    report = diagnose(project_root)
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_doctor(report, color_enabled=color_enabled)


def _print_rings(json_output: bool, color_enabled: bool) -> None:
    report = access_map()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_rings(report, color_enabled=color_enabled)


def _print_capabilities(json_output: bool, color_enabled: bool) -> None:
    report = capability_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_capabilities(report, color_enabled=color_enabled)


def _print_processes(json_output: bool, limit: int, raw: bool, color_enabled: bool) -> None:
    report = process_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_processes(report, limit, raw=raw, color_enabled=color_enabled)


def _print_services(json_output: bool, limit: int, color_enabled: bool) -> None:
    report = service_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_services(report, limit, color_enabled=color_enabled)


def _print_storage(json_output: bool, limit: int, raw: bool, color_enabled: bool) -> None:
    report = storage_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_storage(report, limit, raw=raw, color_enabled=color_enabled)


def _print_hardware(json_output: bool, limit: int, raw: bool, color_enabled: bool) -> None:
    report = hardware_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _render_hardware(report, limit, raw=raw, color_enabled=color_enabled)



def _print_trace(json_output: bool, mode: str, command: list[str], color_enabled: bool) -> None:
    if command and command[0] == "--":
        command = command[1:]
    if command and mode == "report":
        mode = "strace"

    if not command:
        report = trace_report()
        if json_output:
            print(json.dumps(report.to_dict(), indent=2))
            return
        _render_trace_report(report, color_enabled=color_enabled)
        return

    execution = trace_command(command, mode=mode)
    if json_output:
        print(json.dumps(execution.to_dict(), indent=2))
        return
    _render_trace_execution(execution, color_enabled=color_enabled)



def _print_crash(json_output: bool, limit: int, latest: bool, color_enabled: bool) -> None:
    report = crash_report(limit=limit, include_latest=latest)
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_crash(report, color_enabled=color_enabled)



def _print_help(topic: str | None, color_enabled: bool) -> None:
    guides = {
        "snapshot": ("Quick system overview.", ["Shows host, kernel, distro, RAM, disk, network, and mounts.", "Add `--raw` if you want raw numbers where that makes sense."]),
        "doctor": ("System problem diagnostics.", ["Scans kernel, systemd, logs, and Python syntax errors.", "A good first step when you are chasing a root cause."]),
        "rings": ("Access layers from user space to firmware.", ["Shows what LxPerun can see without root and where the limits are."]),
        "capabilities": ("What LxPerun can currently inspect.", ["Audits access to procfs, sysfs, journal, perf, BPF, and TPM."]),
        "processes": ("Process analysis.", ["Top processes by memory, zombies, fd count, command line, and state."]),
        "services": ("systemd service state.", ["Failed units, activity, and basic unit health."]),
        "storage": ("Disks, mounts, and I/O.", ["Shows usage, device types, and basic block attributes."]),
        "hardware": ("PCI, USB, sensors, and NUMA.", ["Values are human-friendly by default; `--raw` shows raw numbers."]),
        "trace": ("Debugging and tracing readiness.", ["Can only report readiness or run a command under `strace`/`perf`."]),
        "crash": ("Coredump analysis.", ["Checks whether tools are available and whether the system collects crash dumps."]),
        "report": ("One report for an issue or debugging session.", ["Combines several sections into Markdown or JSON."]),
        "all": ("Everything at once.", ["Combines snapshot, capabilities, rings, doctor, processes, services, storage, hardware, trace, and crash."]),
    }

    if topic:
        entry = guides.get(topic)
        if entry is None:
            print(yellow(f"Unknown topic: {topic}", color_enabled))
            print("Available topics: " + ", ".join(sorted(guides)))
            return
        title, lines = entry
        print(bold(cyan("LxPerun help", color_enabled), color_enabled))
        print(dim(f"Topic: {topic}", color_enabled))
        print(bold(cyan(topic, color_enabled), color_enabled))
        print(title)
        for line in lines:
            print(f"- {line}")
        return

    print(bold(cyan("LxPerun help", color_enabled), color_enabled))
    print("LxPerun is a simple Linux diagnostics tool — no unnecessary noise.")
    print()
    print("Key commands:")
    for name in ("snapshot", "doctor", "processes", "services", "storage", "hardware", "trace", "crash", "rings", "capabilities", "report", "all"):
        summary, _ = guides[name]
        print(f"  {name:<12} {summary}")
    print()
    print("Global options:")
    print("  --raw       show raw values instead of friendly units")
    print("  --no-color  disable ANSI colors")
    print()
    print("Examples:")
    print("  lxperun help hardware")
    print("  lxperun hardware --raw")
    print("  lxperun doctor")
    print("  lxperun all --limit 5")



def _print_report(output_format: str, output: str | None, limit: int, project_root: str, latest: bool) -> None:
    report = generate_report(project_root=project_root, limit=limit, include_latest_crash=latest)
    if output_format == "json":
        rendered = json.dumps(report.to_dict(), indent=2)
    else:
        rendered = report_to_markdown(report, limit=limit)

    if output is None:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
        return

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")



def _print_all(json_output: bool, limit: int, project_root: str, raw: bool, color_enabled: bool) -> None:
    info = snapshot()
    capabilities = capability_report()
    rings = access_map()
    doctor = diagnose(project_root)
    processes = process_report()
    services = service_report()
    storage = storage_report()
    hardware = hardware_report()
    trace = trace_report()
    crash = crash_report()

    if json_output:
        print(
            json.dumps(
                {
                    "snapshot": info.to_dict(),
                    "capabilities": capabilities.to_dict(),
                    "rings": rings.to_dict(),
                    "doctor": doctor.to_dict(),
                    "processes": processes.to_dict(),
                    "services": services.to_dict(),
                    "storage": storage.to_dict(),
                    "hardware": hardware.to_dict(),
                    "trace": trace.to_dict(),
                    "crash": crash.to_dict(),
                },
                indent=2,
            )
        )
        return

    _render_snapshot(info, raw=raw, color_enabled=color_enabled)
    print()
    _render_capabilities(capabilities, color_enabled=color_enabled)
    print()
    _render_rings(rings, color_enabled=color_enabled)
    print()
    _render_doctor(doctor, color_enabled=color_enabled)
    print()
    _render_processes(processes, limit, raw=raw, color_enabled=color_enabled)
    print()
    _render_services(services, limit, color_enabled=color_enabled)
    print()
    _render_storage(storage, limit, raw=raw, color_enabled=color_enabled)
    print()
    _render_hardware(hardware, limit, raw=raw, color_enabled=color_enabled)
    print()
    _render_trace_report(trace, color_enabled=color_enabled)
    print()
    _render_crash(crash, color_enabled=color_enabled)



def _render_snapshot(info, raw: bool, color_enabled: bool) -> None:
    print(bold(cyan("System", color_enabled), color_enabled))
    print(f"Host:      {info.identity.hostname}")
    print(f"Kernel:    {info.identity.kernel} ({info.identity.machine})")
    print(f"Distro:    {info.identity.distribution}")
    if info.identity.product_vendor or info.identity.product_name:
        vendor = info.identity.product_vendor or "unknown vendor"
        product = info.identity.product_name or "unknown product"
        print(f"Machine:   {vendor} {product}")
    uptime_text = f"{info.uptime / 3600:.1f} h" if raw else human_uptime(info.uptime)
    print(f"Uptime:    {uptime_text}")
    print(f"Load:      {info.load_average[0]:.2f} {info.load_average[1]:.2f} {info.load_average[2]:.2f}")
    print(f"CPU:       {info.cpu_info.model_name or info.cpu_info.architecture} ({info.cpu_info.logical_cpus} threads)")
    print(
        "Memory:    "
        f"{format_bytes(info.memory.used)} / {format_bytes(info.memory.total)} "
        f"({info.memory.used_percent:.2f}%)"
    )
    print(
        "Disk /:    "
        f"{format_bytes(info.root_disk.used)} / {format_bytes(info.root_disk.total)} "
        f"({info.root_disk.used_percent:.2f}%)"
    )
    print(dim("Block:", color_enabled))
    for device in info.block_devices:
        size = "unknown" if device.size is None else format_bytes(device.size)
        kind = "hdd" if device.rotational else "ssd/nvme" if device.rotational is False else "unknown"
        print(f"  {device.name:<10} {size:<10} {kind:<8} {device.vendor or ''} {device.model or ''}".rstrip())
    print(dim("Network:", color_enabled))
    for interface in info.network:
        state = interface.operstate or "unknown"
        ipv4 = interface.ipv4 or "-"
        rx = format_bytes(interface.rx_bytes or 0)
        tx = format_bytes(interface.tx_bytes or 0)
        print(f"  {interface.name:<12} {state:<8} ip={ipv4:<15} rx={rx:<10} tx={tx:<10}")
    print(f"Mounts:    {len(info.mounts)}")
    print(f"Modules:   {len(info.kernel_modules)}")



def _render_doctor(report, color_enabled: bool) -> None:
    print(bold(cyan("Doctor", color_enabled), color_enabled))
    if not report.issues:
        print(green("LxPerun doctor: no issues found.", color_enabled))
        return

    print(yellow(f"LxPerun doctor: {len(report.issues)} issue(s) found.", color_enabled))
    for issue in report.issues:
        severity_style = green if issue.severity in {"info", "ok"} else yellow if issue.severity == "warning" else red
        print(f"{severity_style(f'[{issue.severity.upper()}]', color_enabled)} {issue.source}: {issue.message}")
        if issue.detail:
            print(f"  {issue.detail}")
        if issue.suggestion:
            print(f"  suggestion: {issue.suggestion}")



def _render_rings(report, color_enabled: bool) -> None:
    root_text = "yes" if report.is_root else "no"
    print(bold(cyan("Rings", color_enabled), color_enabled))
    print(f"Effective UID: {report.effective_uid} root={root_text}")
    for layer in report.layers:
        status = "available" if layer.available else "limited"
        print(f"[ring {layer.ring:>2}] {layer.name}: {status}")
        print(f"  access: {layer.access}")
        if layer.evidence:
            print(f"  evidence: {', '.join(layer.evidence[:4])}")
        if layer.missing:
            print(f"  missing: {', '.join(layer.missing)}")
        if layer.safe_next_steps:
            print(f"  next: {', '.join(layer.safe_next_steps)}")



def _render_capabilities(report, color_enabled: bool) -> None:
    root_text = "yes" if report.is_root else "no"
    print(bold(cyan("Capabilities", color_enabled), color_enabled))
    print(f"Effective UID: {report.effective_uid} root={root_text}")
    for probe in report.probes:
        status = "yes" if probe.available else "no"
        print(f"{probe.name:<14} {status:<3} [{probe.level}] {probe.detail}")
        if probe.evidence:
            print(f"  evidence: {', '.join(probe.evidence[:4])}")
        if probe.missing:
            print(f"  missing: {', '.join(probe.missing)}")



def _render_processes(report, limit: int, raw: bool, color_enabled: bool) -> None:
    zombies = zombie_processes(report)
    print(bold(cyan("Processes", color_enabled), color_enabled))
    print(f"Total: {report.total} processes, unreadable: {report.unreadable}, zombies: {len(zombies)}")
    print(f"{'PID':>7} {'USER':<12} {'RSS':>10} {'FD':>5} {'STATE':<14} COMMAND")
    for process in top_by_memory(report, limit):
        command = " ".join(process.cmdline) if process.cmdline else process.name or "-"
        if len(command) > 90:
            command = command[:87] + "..."
        rss = "-" if process.vm_rss is None else (str(process.vm_rss) if raw else human_bytes(process.vm_rss))
        fd_count = "-" if process.fd_count is None else str(process.fd_count)
        state = process.state or "-"
        user = process.user or "-"
        print(f"{process.pid:>7} {user:<12.12} {rss:>10} {fd_count:>5} {state:<14.14} {command}")



def _render_services(report, limit: int, color_enabled: bool) -> None:
    print(bold(cyan("Services", color_enabled), color_enabled))
    print(
        f"Available: {report.available} total={report.total_units} "
        f"active={report.active_units} running={report.running_units} failed={report.failed_count}"
    )
    if report.raw_failed_units:
        print("Failed units:")
        for name in report.raw_failed_units[:limit]:
            print(f"  {name}")
        return
    if report.failed_units:
        print("Failed units:")
        for unit in report.failed_units[:limit]:
            print(f"  {unit.name} ({unit.active}/{unit.sub}) - {unit.description}")
        return
    print("Failed units: none")



def _render_storage(report, limit: int, raw: bool, color_enabled: bool) -> None:
    print(bold(cyan("Storage", color_enabled), color_enabled))
    print(f"Mounts: {report.mount_count} Devices: {report.device_count}")
    print(f"{'MOUNT':<18} {'FS':<10} {'USED':>10} {'TOTAL':>10} {'%':>6} DEVICE")
    for mount in report.mounts[:limit]:
        used_text = f"{mount.used} B" if raw else human_bytes(mount.used)
        total_text = f"{mount.total} B" if raw else human_bytes(mount.total)
        print(
            f"{mount.mount_point:<18.18} {mount.filesystem:<10.10} "
            f"{used_text:>10} {total_text:>10} "
            f"{mount.used_percent:>5.1f}% {mount.device}"
        )
    if not report.devices:
        return
    print(dim("Devices:", color_enabled))
    for device in report.devices[:limit]:
        size = "unknown" if device.size is None else (str(device.size) if raw else human_bytes(device.size))
        read_write = "ro" if device.read_only else "rw"
        rotation = "rot" if device.rotational else "nonrot" if device.rotational is False else "unk"
        io = ""
        if device.io is not None:
            io = f" r={device.io.reads_completed} w={device.io.writes_completed}" if raw else ""
        print(
            f"  {device.name:<10} {size:<10} {read_write:<2} {rotation:<6} "
            f"{device.vendor or ''} {device.model or ''}{io}"
        )



def _render_hardware(report, limit: int, raw: bool, color_enabled: bool) -> None:
    print(bold(cyan("Hardware", color_enabled), color_enabled))
    print(f"PCI: {report.pci_count} USB: {report.usb_count} Sensors: {report.sensor_count} NUMA nodes: {report.numa_count}")
    if report.pci_devices:
        print(dim("PCI:", color_enabled))
        for device in report.pci_devices[:limit]:
            print(
                f"  {device.bdf:<12} {device.vendor_id or '-'}:{device.device_id or '-'} "
                f"class={device.class_code or '-'} driver={device.driver or '-'} "
                f"{device.vendor_name or ''} {device.device_name or ''}".rstrip()
            )
    if report.usb_devices:
        print(dim("USB:", color_enabled))
        for device in report.usb_devices[:limit]:
            print(
                f"  {device.path:<12} {device.id_vendor or '-'}:{device.id_product or '-'} "
                f"bus={device.busnum or '-'} dev={device.devnum or '-'} "
                f"{device.manufacturer or ''} {device.product or ''} {device.serial or ''}".rstrip()
            )
    if report.sensors:
        print(dim("Sensors:", color_enabled))
        for sensor in report.sensors[:limit]:
            value_text = f"{sensor.value} {sensor.unit}" if raw else human_sensor_value(sensor.value, sensor.unit)
            print(f"  {sensor.chip:<16} {sensor.label:<18} {value_text}")
    if report.numa_nodes:
        print(dim("NUMA:", color_enabled))
        for node in report.numa_nodes[:limit]:
            print(
                f"  {node.name:<8} cpus={node.cpulist or '-'} "
                f"mem_total_kb={node.mem_total_kb or '-'} mem_free_kb={node.mem_free_kb or '-'}"
            )



def _render_trace_report(report, color_enabled: bool) -> None:
    print(bold(cyan("Trace", color_enabled), color_enabled))
    print(f"Ready: {report.ready} perf_event_paranoid={report.perf_event_paranoid}")
    for tool in report.tools:
        status = "yes" if tool.available else "no"
        print(f"{tool.name:<14} {status:<3} {tool.detail}")
        if tool.evidence:
            print(f"  evidence: {', '.join(tool.evidence[:4])}")
        if tool.missing:
            print(f"  missing: {', '.join(tool.missing)}")
    if report.recommendations:
        print("Recommendations:")
        for recommendation in report.recommendations:
            print(f"  {recommendation}")



def _render_trace_execution(execution, color_enabled: bool) -> None:
    command_text = " ".join(execution.command)
    print(bold(cyan("Trace", color_enabled), color_enabled))
    print(f"Mode: {execution.mode} Exit: {execution.exit_code}")
    print(f"Command: {command_text}")
    if execution.stdout:
        print("Stdout:")
        print(execution.stdout)
    if execution.stderr:
        print("Stderr:")
        print(execution.stderr)
    if execution.trace_lines:
        print("Trace:")
        for line in execution.trace_lines[:40]:
            print(f"  {line}")



def _render_crash(report, color_enabled: bool) -> None:
    print(bold(cyan("Crash", color_enabled), color_enabled))
    print(f"Ready: {report.ready} coredumps={report.coredump_count}")
    for tool in report.tools:
        status = "yes" if tool.available else "no"
        print(f"{tool.name:<12} {status:<3} {tool.detail}")
        if tool.evidence:
            print(f"  evidence: {', '.join(tool.evidence[:4])}")
        if tool.missing:
            print(f"  missing: {', '.join(tool.missing)}")
    if report.debug_symbol_paths:
        print("Debug symbols:")
        for path in report.debug_symbol_paths[:4]:
            print(f"  {path}")
    if report.coredump_summaries:
        print("Coredumps:")
        for line in report.coredump_summaries[:8]:
            print(f"  {line}")
    if report.latest_info:
        print("Latest:")
        for line in report.latest_info.splitlines()[:40]:
            print(f"  {line}")
    if report.recommendations:
        print("Recommendations:")
        for recommendation in report.recommendations:
            print(f"  {recommendation}")


if __name__ == "__main__":
    main()
