from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .capabilities import capability_report
from .clean import clean as clean_system
from .crash import crash_report
from .containers import container_report
from .doctor import diagnose
from .firewall import firewall_report
from .formatting import human_bytes, human_sensor_value, human_uptime
from .hardware import hardware_report
from .linux import format_bytes, snapshot
from .network import group_sockets, network_report
from .performance import performance_report
from .processes import process_report, top_by_memory, zombie_processes
from .report import generate_report, report_to_markdown
from .rings import access_map
from .security import security_report
from .services import service_report
from .storage import storage_report
from .trace import trace_command, trace_report
from .ui import bold, cyan, dim, green, red, supports_color, yellow


_ROOT_SENSITIVE_COMMANDS = {"doctor", "rings", "capabilities", "processes", "services", "storage", "hardware", "trace", "crash", "clean", "report", "all", "network", "security", "firewall", "containers"}


def main() -> None:
    raw_argv = sys.argv[1:]
    root_requested = "--root" in raw_argv
    argv = [arg for arg in raw_argv if arg != "--root"]

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

    network_parser = subparsers.add_parser("network", help="show network diagnostics")
    network_parser.add_argument("--json", action="store_true", help="print raw JSON")
    network_parser.add_argument("--watch", action="store_true", help="refresh the view until interrupted")
    network_parser.add_argument("--interval", type=float, default=2.0, help="seconds between refreshes in watch mode")

    security_parser = subparsers.add_parser("security", help="show security posture checks")
    security_parser.add_argument("--json", action="store_true", help="print raw JSON")

    firewall_parser = subparsers.add_parser("firewall", help="audit firewall rules against open ports")
    firewall_parser.add_argument("--json", action="store_true", help="print raw JSON")

    performance_parser = subparsers.add_parser("performance", help="show PSI, interrupts, and slabinfo")
    performance_parser.add_argument("--json", action="store_true", help="print raw JSON")
    performance_parser.add_argument("--raw", action="store_true", help="print raw numeric values")

    containers_parser = subparsers.add_parser("containers", help="show container and namespace visibility")
    containers_parser.add_argument("--json", action="store_true", help="print raw JSON")

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

    clean_parser = subparsers.add_parser("clean", help="reclaim disk space from caches and coredumps")
    clean_parser.add_argument("--json", action="store_true", help="print raw JSON")
    clean_parser.add_argument("--apply", action="store_true", help="actually run cleanup commands")
    clean_parser.add_argument("--older-than-days", type=int, default=7, help="remove only coredumps older than this many days")

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
    parser.add_argument("--root", action="store_true", help="rerun the command through sudo for deeper access")
    args = parser.parse_args(argv)

    command = args.command or "snapshot"
    if root_requested and os.geteuid() != 0 and command in _ROOT_SENSITIVE_COMMANDS:
        _reexec_with_sudo()
        return

    color_enabled = supports_color(not args.no_color)
    if command == "doctor":
        _print_doctor(json_output=args.json, project_root=args.project_root, color_enabled=color_enabled)
    elif command == "rings":
        _print_rings(json_output=args.json, color_enabled=color_enabled)
    elif command == "capabilities":
        _print_capabilities(json_output=args.json, color_enabled=color_enabled)
    elif command == "network":
        _print_network(json_output=args.json, watch=args.watch, interval=args.interval, color_enabled=color_enabled)
    elif command == "security":
        _print_security(json_output=args.json, color_enabled=color_enabled)
    elif command == "firewall":
        _print_firewall(json_output=args.json, color_enabled=color_enabled)
    elif command == "performance":
        _print_performance(json_output=args.json, raw=args.raw, color_enabled=color_enabled)
    elif command == "containers":
        _print_containers(json_output=args.json, color_enabled=color_enabled)
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
    elif command == "clean":
        _print_clean(json_output=args.json, apply=args.apply, older_than_days=args.older_than_days, color_enabled=color_enabled)
    elif command == "help":
        _print_help(topic=args.topic, color_enabled=color_enabled)
    elif command == "report":
        _print_report(output_format=args.format, output=args.output, limit=args.limit, project_root=args.project_root, latest=args.latest)
    elif command == "all":
        _print_all(json_output=args.json, limit=args.limit, project_root=args.project_root, raw=args.raw, color_enabled=color_enabled)
    else:
        _print_snapshot(json_output=args.json, raw=args.raw, color_enabled=color_enabled)

    if not args.json and not root_requested and os.geteuid() != 0 and command in _ROOT_SENSITIVE_COMMANDS:
        print()
        _print_root_tip(color_enabled)


def _print_snapshot(json_output: bool, raw: bool, color_enabled: bool) -> None:
    info = snapshot()
    if json_output:
        print(json.dumps(info.to_dict(), indent=2))
        return
    _render_snapshot(info, raw=raw, color_enabled=color_enabled)


def _render_snapshot(info, raw: bool, color_enabled: bool) -> None:
    _section_header("System", color_enabled, "A compact overview of the current machine.")
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
    print(f"Memory:    {format_bytes(info.memory.used)} / {format_bytes(info.memory.total)} ({info.memory.used_percent:.2f}%)")
    print(f"Disk /:    {format_bytes(info.root_disk.used)} / {format_bytes(info.root_disk.total)} ({info.root_disk.used_percent:.2f}%)")
    print(dim("Network interfaces", color_enabled))
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


def _print_network(json_output: bool, watch: bool, interval: float, color_enabled: bool) -> None:
    if watch and json_output:
        watch = False
    if watch:
        previous_bandwidth = None
        try:
            while True:
                report = network_report(previous_bandwidth=previous_bandwidth)
                previous_bandwidth = report.bandwidth
                if os.name == "nt":
                    os.system("cls")
                else:
                    os.system("clear")
                _render_network(report, color_enabled=color_enabled)
                time.sleep(max(interval, 0.25))
        except KeyboardInterrupt:
            print()
            return
    report = network_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_network(report, color_enabled=color_enabled)


def _print_security(json_output: bool, color_enabled: bool) -> None:
    report = security_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_security(report, color_enabled=color_enabled)


def _print_firewall(json_output: bool, color_enabled: bool) -> None:
    report = firewall_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_firewall(report, color_enabled=color_enabled)


def _print_performance(json_output: bool, raw: bool, color_enabled: bool) -> None:
    report = performance_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_performance(report, raw=raw, color_enabled=color_enabled)


def _print_containers(json_output: bool, color_enabled: bool) -> None:
    report = container_report()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_containers(report, color_enabled=color_enabled)


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


def _print_clean(json_output: bool, apply: bool, older_than_days: int, color_enabled: bool) -> None:
    report = clean_system(older_than_days=older_than_days, dry_run=not apply)
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
        return
    _render_clean(report, color_enabled=color_enabled)


def _print_help(topic: str | None, color_enabled: bool) -> None:
    guides = {
        "snapshot": ("Quick system overview.", ["Shows host, kernel, distro, RAM, disk, network, and mounts.", "Add `--raw` if you want raw numbers where that makes sense."]),
        "doctor": ("System problem diagnostics.", ["Scans kernel, systemd, logs, and Python syntax errors.", "A good first step when you are chasing a root cause."]),
        "rings": ("Access layers from user space to firmware.", ["Shows what LxPerun can see without root and where the limits are."]),
        "capabilities": ("What LxPerun can currently inspect.", ["Audits access to procfs, sysfs, journal, perf, BPF, and TPM."]),
        "network": ("Socket, ARP, conntrack, and bandwidth diagnostics.", ["Shows listening ports, per-PID sockets, ARP entries, conntrack, and rx/tx samples.", "Add `--watch` to refresh the view live."]),
        "security": ("Security posture checks.", ["Checks SELinux/AppArmor status, exposed listeners, UID 0 accounts, and loose permissions.", "Add `--root` for deeper checks such as /etc/shadow."]),
        "firewall": ("Firewall audit.", ["Shows iptables/nftables rules and maps listening sockets to allow/block decisions."]),
        "performance": ("Performance deep-dive.", ["Shows PSI, interrupt distribution, softirqs, and slab caches. Add `--raw` for raw counters."]),
        "containers": ("Container visibility.", ["Shows cgroup markers, runtime sockets, and namespace visibility."]),
        "processes": ("Process analysis.", ["Top processes by memory, zombies, fd count, command line, and state."]),
        "services": ("systemd service state.", ["Failed units, activity, and basic unit health."]),
        "storage": ("Disks, mounts, and I/O.", ["Shows usage, device types, and basic block attributes."]),
        "hardware": ("PCI, USB, sensors, and NUMA.", ["Values are human-friendly by default; `--raw` shows raw numbers."]),
        "trace": ("Debugging and tracing readiness.", ["Can only report readiness or run a command under `strace`/`perf`."]),
        "crash": ("Coredump analysis.", ["Checks whether tools are available and whether the system collects crash dumps."]),
        "clean": ("Disk cleanup.", ["Dry-runs by default; use `--apply` to remove old coredumps and clean caches."]),
        "report": ("One report for an issue or debugging session.", ["Combines several sections into Markdown or JSON."]),
        "all": ("Everything at once.", ["Combines snapshot, capabilities, security, containers, firewall, performance, rings, doctor, network, processes, services, storage, hardware, trace, and crash."]),
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
    for name in ("snapshot", "doctor", "network", "security", "firewall", "performance", "containers", "processes", "services", "storage", "hardware", "trace", "crash", "clean", "rings", "capabilities", "report", "all"):
        summary, _ = guides[name]
        print(f"  {name:<12} {summary}")
    print()
    print("Global options:")
    print("  --raw       show raw values instead of friendly units")
    print("  --no-color  disable ANSI colors")
    print("  --root      rerun the command through sudo for deeper access")
    print("  --project-root PATH  set the project root used by doctor/report/all")
    print()
    print("Examples:")
    print("  lxperun help hardware")
    print("  lxperun hardware --raw")
    print("  lxperun doctor")
    print("  lxperun security --root")
    print("  lxperun firewall --root")
    print("  lxperun performance")
    print("  lxperun performance --raw")
    print("  lxperun containers --root")
    print("  lxperun clean --apply")
    print("  lxperun --root clean --apply")
    print("  lxperun all --project-root ~/Pulpit/LxPerun")
    print("  lxperun all --limit 5")


def _reexec_with_sudo() -> None:
    argv = [arg for arg in sys.argv[1:] if arg != "--root"]
    command = ["sudo", "-E", sys.executable, "-m", "lxperun.cli", *argv]
    raise SystemExit(subprocess.call(command))


def _print_root_tip(color_enabled: bool) -> None:
    print(dim("Tip: add `--root` to rerun this command with sudo and unlock deeper diagnostics.", color_enabled))


def _section_header(title: str, color_enabled: bool, subtitle: str | None = None) -> None:
    print(bold(cyan(title, color_enabled), color_enabled))
    print(dim("─" * 72, color_enabled))
    if subtitle:
        print(dim(subtitle, color_enabled))


def _list_item(text: str, color_enabled: bool) -> None:
    print(f"  {dim('•', color_enabled)} {text}")


def _print_report(output_format: str, output: str | None, limit: int, project_root: str, latest: bool) -> None:
    report = generate_report(project_root=project_root, limit=limit, include_latest_crash=latest)
    rendered = json.dumps(report.to_dict(), indent=2) if output_format == "json" else report_to_markdown(report, limit=limit)
    if output is None:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
        return
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")


def _print_all(json_output: bool, limit: int, project_root: str, raw: bool, color_enabled: bool) -> None:
    info = snapshot()
    capabilities = capability_report()
    security = security_report()
    firewall = firewall_report()
    performance = performance_report()
    containers = container_report()
    rings = access_map()
    doctor = diagnose(project_root)
    network = network_report()
    processes = process_report()
    services = service_report()
    storage = storage_report()
    hardware = hardware_report()
    trace = trace_report()
    crash = crash_report()
    if json_output:
        print(json.dumps({"snapshot": info.to_dict(), "capabilities": capabilities.to_dict(), "security": security.to_dict(), "containers": containers.to_dict(), "firewall": firewall.to_dict(), "performance": performance.to_dict(), "rings": rings.to_dict(), "doctor": doctor.to_dict(), "network": network.to_dict(), "processes": processes.to_dict(), "services": services.to_dict(), "storage": storage.to_dict(), "hardware": hardware.to_dict(), "trace": trace.to_dict(), "crash": crash.to_dict()}, indent=2))
        return
    _section_header("LxPerun All", color_enabled, "A single pass across the whole diagnostics stack.")
    _render_snapshot(info, raw=raw, color_enabled=color_enabled)
    print()
    _render_capabilities(capabilities, color_enabled=color_enabled)
    print()
    _render_security(security, color_enabled=color_enabled)
    print()
    _render_containers(containers, color_enabled=color_enabled)
    print()
    _render_firewall(firewall, color_enabled=color_enabled)
    print()
    _render_performance(performance, raw=raw, color_enabled=color_enabled)
    print()
    _render_rings(rings, color_enabled=color_enabled)
    print()
    _render_doctor(doctor, color_enabled=color_enabled)
    print()
    _render_network(network, color_enabled=color_enabled)
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


def _render_doctor(report, color_enabled: bool) -> None:
    _section_header("Doctor", color_enabled, "Kernel, logs, services, and syntax diagnostics.")
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
    _section_header("Rings", color_enabled, "What the current context can safely reach.")
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
    _section_header("Capabilities", color_enabled, "Which subsystems are reachable right now.")
    print(f"Effective UID: {report.effective_uid} root={root_text}")
    for probe in report.probes:
        status = "yes" if probe.available else "no"
        print(f"{probe.name:<14} {status:<3} [{probe.level}] {probe.detail}")
        if probe.evidence:
            print(f"  evidence: {', '.join(probe.evidence[:4])}")
        if probe.missing:
            print(f"  missing: {', '.join(probe.missing)}")


def _render_security(report, color_enabled: bool) -> None:
    root_text = "yes" if report.is_root else "no"
    _section_header("Security", color_enabled, "Posture checks for exposure, permissions, and isolation.")
    print(f"Effective UID: {report.effective_uid} root={root_text}")
    if report.issue_count:
        print(yellow(f"Summary: {report.issue_count} issue(s), {report.advisory_count} advisory finding(s).", color_enabled))
    elif report.advisory_count:
        print(green(f"Summary: {report.advisory_count} advisory finding(s).", color_enabled))
    else:
        print(green("Summary: no notable security posture issues found.", color_enabled))
    print("Signals:")
    for signal in report.signals:
        status = "yes" if signal.available else "no"
        print(f"  {signal.name:<12} {status:<3} {signal.detail}")
        if signal.evidence:
            print(f"    evidence: {', '.join(signal.evidence[:4])}")
        if signal.missing:
            print(f"    missing: {', '.join(signal.missing)}")
    if report.findings:
        print(dim("Findings", color_enabled))
        for finding in report.findings:
            severity_style = green if finding.severity in {"info", "ok"} else yellow if finding.severity == "warning" else red
            print(f"  {severity_style(f'[{finding.severity.upper()}]', color_enabled)} {finding.category}: {finding.message}")
            if finding.detail:
                print(f"    {finding.detail}")
            if finding.suggestion:
                print(f"    suggestion: {finding.suggestion}")
            if finding.evidence:
                print(f"    evidence: {', '.join(finding.evidence[:5])}")
    else:
        print(green("No security posture issues found.", color_enabled))
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _render_containers(report, color_enabled: bool) -> None:
    root_text = "yes" if report.is_root else "no"
    _section_header("Containers", color_enabled, "Container runtime and namespace visibility.")
    print(f"Effective UID: {report.effective_uid} root={root_text}")
    for signal in report.signals:
        status = "yes" if signal.available else "no"
        print(f"{signal.name:<12} {status:<3} {signal.detail}")
        if signal.evidence:
            print(f"  evidence: {', '.join(signal.evidence[:4])}")
        if signal.missing:
            print(f"  missing: {', '.join(signal.missing)}")
    if report.findings:
        print(dim("Findings", color_enabled))
        for finding in report.findings:
            print(f"  [{finding.severity.upper()}] {finding.category}: {finding.message}")
            if finding.detail:
                print(f"    {finding.detail}")
            if finding.suggestion:
                print(f"    suggestion: {finding.suggestion}")
            if finding.evidence:
                print(f"    evidence: {', '.join(finding.evidence[:5])}")
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _render_firewall(report, color_enabled: bool) -> None:
    _section_header("Firewall", color_enabled, "Firewall backends and what they allow through.")
    for backend in report.backends:
        state = "yes" if backend.available else "no"
        print(f"{backend.name:<12} {state:<3} command={backend.command}")
        if backend.policy:
            print(f"  default policy: {backend.policy}")
        if backend.missing:
            print(f"  missing: {', '.join(backend.missing)}")
    if report.mappings:
        print(dim("Listening socket mapping", color_enabled))
        for mapping in report.mappings[:20]:
            print(f"  {mapping.backend:<10} {mapping.protocol}/{mapping.port:<5} {mapping.address:<15} {mapping.decision}")
            print(f"    {mapping.reason}")
            if mapping.rule:
                print(f"    rule: {mapping.rule}")
    else:
        print("No matching firewall mappings found.")
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _render_performance(report, raw: bool, color_enabled: bool) -> None:
    _section_header("Performance", color_enabled, "Pressure, interrupts, softirqs, and slab pressure.")
    if report.pressure:
        print(dim("Pressure Stall Information", color_enabled))
        for sample in report.pressure:
            if raw:
                some = f"{sample.some_avg10}/{sample.some_avg60}/{sample.some_avg300}"
                full = f"{sample.full_avg10}/{sample.full_avg60}/{sample.full_avg300}"
            else:
                some = _format_pressure_triplet(sample.some_avg10, sample.some_avg60, sample.some_avg300)
                full = _format_pressure_triplet(sample.full_avg10, sample.full_avg60, sample.full_avg300)
            print(f"  {sample.resource:<6} some={some:<24} full={full}")
    if report.interrupts:
        print(dim("Interrupt load", color_enabled))
        interrupt_total = sum(cpu.total for cpu in report.interrupts) or 1
        for cpu in report.interrupts[:8]:
            if raw:
                value = str(cpu.total)
            else:
                value = f"{_format_count(cpu.total)} ({(cpu.total / interrupt_total) * 100:.1f}%)"
            print(f"  {cpu.cpu:<8} {value}")
    if report.softirqs:
        print(dim("Softirq load", color_enabled))
        softirq_total = sum(cpu.total for cpu in report.softirqs) or 1
        for cpu in report.softirqs[:8]:
            if raw:
                value = str(cpu.total)
            else:
                value = f"{_format_count(cpu.total)} ({(cpu.total / softirq_total) * 100:.1f}%)"
            print(f"  {cpu.cpu:<8} {value}")
    if report.slabinfo:
        print(dim("Slab caches", color_enabled))
        for cache in report.slabinfo[:12]:
            if raw:
                print(f"  {cache.name:<24} active={cache.active_objs:<8} size={cache.object_size:<6} bytes={cache.active_bytes}")
            else:
                print(f"  {cache.name:<24} active={_format_count(cache.active_objs):<8} size={_format_bytes(cache.object_size):<8} bytes={_format_bytes(cache.active_bytes)}")
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _format_pressure_triplet(avg10: float | None, avg60: float | None, avg300: float | None) -> str:
    return "/".join(_format_percent(value) for value in (avg10, avg60, avg300))


def _format_percent(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}%"


def _format_count(value: int) -> str:
    thresholds = (
        (1_000_000_000, "B"),
        (1_000_000, "M"),
        (1_000, "K"),
    )
    for threshold, suffix in thresholds:
        if value >= threshold:
            return f"{value / threshold:.1f}{suffix}"
    return str(value)


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    for suffix, threshold in (("KiB", 1024), ("MiB", 1024**2), ("GiB", 1024**3), ("TiB", 1024**4)):
        if value < threshold * 1024 or suffix == "TiB":
            return f"{value / threshold:.1f} {suffix}"
    return f"{value} B"


def _render_network(report, color_enabled: bool) -> None:
    _section_header("Network", color_enabled, "Sockets, ARP, conntrack, and bandwidth samples.")
    print(f"Sockets: {len(report.sockets)} listening={len(report.listening_sockets)} arp={len(report.arp)} conntrack={len(report.conntrack)}")
    print(f"Bandwidth sample time: {report.bandwidth.timestamp:.0f}")
    for sample in report.bandwidth.interfaces[:12]:
        rx = format_bytes(sample.rx_bytes)
        tx = format_bytes(sample.tx_bytes)
        rx_rate = f"{format_bytes(sample.rx_rate_bps)}/s" if sample.rx_rate_bps is not None else "-"
        tx_rate = f"{format_bytes(sample.tx_rate_bps)}/s" if sample.tx_rate_bps is not None else "-"
        print(f"  {sample.name:<12} rx={rx:<10} tx={tx:<10} rate={rx_rate:<14} {tx_rate}")

    grouped = group_sockets(report.sockets)
    if grouped["listening"]:
        print(dim("Listening sockets", color_enabled))
        for socket_entry in grouped["listening"][:12]:
            pid_text = ",".join(str(pid) for pid in socket_entry.pids) if socket_entry.pids else "-"
            print(f"  {socket_entry.protocol:<5} {socket_entry.local_address}:{socket_entry.local_port:<5} pid={pid_text} inode={socket_entry.inode}")
    if grouped["established"]:
        print(dim("Established sockets", color_enabled))
        for socket_entry in grouped["established"][:12]:
            pid_text = ",".join(str(pid) for pid in socket_entry.pids) if socket_entry.pids else "-"
            print(f"  {socket_entry.protocol:<5} {socket_entry.local_address}:{socket_entry.local_port:<5} -> {socket_entry.remote_address}:{socket_entry.remote_port:<5} pid={pid_text}")
    if grouped["unix"]:
        print(dim("Unix sockets", color_enabled))
        for socket_entry in grouped["unix"][:12]:
            pid_text = ",".join(str(pid) for pid in socket_entry.pids) if socket_entry.pids else "-"
            print(f"  {socket_entry.state:<10} {socket_entry.path or socket_entry.local_address} pid={pid_text}")
    if grouped["other"]:
        print(dim("Other sockets", color_enabled))
        for socket_entry in grouped["other"][:12]:
            pid_text = ",".join(str(pid) for pid in socket_entry.pids) if socket_entry.pids else "-"
            endpoint = f"{socket_entry.local_address}:{socket_entry.local_port}"
            if socket_entry.remote_address or socket_entry.remote_port:
                endpoint += f" -> {socket_entry.remote_address}:{socket_entry.remote_port}"
            print(f"  {socket_entry.protocol:<5} {endpoint:<36} state={socket_entry.state:<10} pid={pid_text}")


def _render_processes(report, limit: int, raw: bool, color_enabled: bool) -> None:
    _section_header("Processes", color_enabled, "Top memory users and lightweight process metadata.")
    print(f"Total: {report.total} processes, unreadable: {report.unreadable}, zombies: {len(zombie_processes(report))}")
    print(f"    PID USER                RSS    FD STATE          COMMAND")
    for process in top_by_memory(report, limit):
        command = " ".join(process.cmdline) if process.cmdline else process.name or "-"
        if len(command) > 80:
            command = command[:77] + "..."
        print(f"{process.pid:>6} { (process.user or '-'): <16} {human_bytes(process.vm_rss):>10} {process.fd_count:>5} {process.state:<13} {command}")


def _render_services(report, limit: int, color_enabled: bool) -> None:
    _section_header("Services", color_enabled, "systemd health and failed units.")
    print(f"Available: {report.available} total={report.total_units} active={report.active_units} running={report.running_units} failed={report.failed_count}")
    if report.failed_units:
        print(dim("Failed units", color_enabled))
        for unit in report.failed_units[:limit]:
            print(f"  {unit.name}")


def _render_storage(report, limit: int, raw: bool, color_enabled: bool) -> None:
    _section_header("Storage", color_enabled, "Mounts and block devices with human-readable usage.")
    print(f"Mounts: {report.mount_count} Devices: {report.device_count}")
    print(f"{'MOUNT':<18} {'FS':<12} {'USED':>10} {'TOTAL':>10} {'%':>6} DEVICE")
    for mount in report.mounts[:limit]:
        print(f"{mount.mount_point:<18} {mount.filesystem:<12} {format_bytes(mount.used):>10} {format_bytes(mount.total):>10} {mount.used_percent:>5.1f}% {mount.device}")
    if report.devices:
        print(dim("Devices", color_enabled))
        for device in report.devices[:limit]:
            rot = "rot" if device.rotational else "nonrot" if device.rotational is False else "-"
            ro = "ro" if device.read_only else "rw" if device.read_only is False else "-"
            print(f"  {device.name:<10} {format_bytes(device.size):<10} {ro:<2} {rot:<6} {device.vendor or ''} {device.model or ''}".rstrip())


def _render_hardware(report, limit: int, raw: bool, color_enabled: bool) -> None:
    _section_header("Hardware", color_enabled, "PCI, USB, sensors, and NUMA.")
    print(f"PCI: {report.pci_count} USB: {report.usb_count} Sensors: {report.sensor_count} NUMA nodes: {report.numa_count}")
    if report.pci_devices:
        print(dim("PCI", color_enabled))
        for device in report.pci_devices[:limit]:
            print(f"  {device.bdf} {device.vendor_id or '-'}:{device.device_id or '-'} class={device.class_code or '-'} driver={device.driver or '-'}")
    if report.usb_devices:
        print(dim("USB", color_enabled))
        for device in report.usb_devices[:limit]:
            bus_label = device.path
            if device.busnum is not None:
                bus_label = f"{device.busnum}:{device.devnum}" if device.devnum is not None else str(device.busnum)
            print(f"  {bus_label:<12} {device.id_vendor or '-'}:{device.id_product or '-'} {device.manufacturer or ''} {device.product or ''}".rstrip())
    if report.sensors:
        print(dim("Sensors", color_enabled))
        for sensor in report.sensors[:limit]:
            print(f"  {sensor.chip:<16} {sensor.label:<18} {human_sensor_value(sensor.value, sensor.unit)}")
    if report.numa_nodes:
        print(dim("NUMA", color_enabled))
        for node in report.numa_nodes[:limit]:
            print(f"  {node.name:<8} cpus={node.cpulist or '-'} mem_total_kb={node.mem_total_kb or '-'} mem_free_kb={node.mem_free_kb or '-'}")


def _render_trace_report(report, color_enabled: bool) -> None:
    _section_header("Trace", color_enabled, "Tracing readiness and available debug tools.")
    print(f"Ready: {report.ready} perf_event_paranoid={report.perf_event_paranoid}")
    for tool in report.tools:
        status = "yes" if tool.available else "no"
        print(f"{tool.name:<14} {status:<3} {tool.detail}")
        if tool.evidence:
            print(f"  evidence: {', '.join(tool.evidence[:4])}")
        if tool.missing:
            print(f"  missing: {', '.join(tool.missing)}")
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _render_trace_execution(execution, color_enabled: bool) -> None:
    _section_header("Trace execution", color_enabled, "Live command trace output.")
    print(f"Mode: {execution.mode} exit={execution.exit_code}")
    print(f"Command: {' '.join(execution.command)}")
    if execution.trace_file:
        print(f"Trace file: {execution.trace_file}")
    if execution.trace_lines:
        print(dim("Trace lines", color_enabled))
        for line in execution.trace_lines[:20]:
            print(f"  {line}")


def _render_crash(report, color_enabled: bool) -> None:
    _section_header("Crash", color_enabled, "Coredumps and native backtrace readiness.")
    print(f"Ready: {report.ready} coredumps={report.coredump_count}")
    if report.coredump_summaries:
        print(dim("Coredumps", color_enabled))
        for line in report.coredump_summaries[:8]:
            print(f"  {line}")
    if report.latest_info:
        print(dim("Latest", color_enabled))
        print(report.latest_info)
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


def _render_clean(report, color_enabled: bool) -> None:
    _section_header("Clean", color_enabled, "Disk space cleanup actions and what they reclaimed.")
    mode = "apply" if not report.dry_run else "dry-run"
    print(f"Mode: {mode} reclaimed={format_bytes(report.total_reclaimed_bytes)}")
    for action in report.actions:
        state_color = green if action.state == "done" else yellow if action.state == "skipped" else red if action.state == "failed" else cyan
        print(f"{state_color(action.name, color_enabled)} [{state_color(action.state, color_enabled)}] {action.detail}")
        if action.reclaimed_bytes:
            print(f"  reclaimed: {format_bytes(action.reclaimed_bytes)}")
        if action.command:
            print(f"  command: {' '.join(action.command)}")
        if action.evidence:
            print(f"  evidence: {', '.join(action.evidence[:3])}")
        if action.missing:
            print(f"  missing: {', '.join(action.missing)}")
    if report.recommendations:
        print(dim("Recommendations", color_enabled))
        for recommendation in report.recommendations:
            _list_item(recommendation, color_enabled)


if __name__ == "__main__":
    main()
