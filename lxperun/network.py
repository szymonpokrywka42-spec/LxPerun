from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import ipaddress
import os
import socket
import struct
from typing import Callable

from .linux import PROC


@dataclass(frozen=True)
class SocketEntry:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    inode: int
    pids: tuple[int, ...]
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ArpEntry:
    ip_address: str
    hw_type: str
    flags: str
    mac_address: str
    mask: str
    device: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ConntrackEntry:
    protocol: str
    state: str | None
    src: str | None
    dst: str | None
    sport: int | None
    dport: int | None
    raw: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BandwidthSample:
    name: str
    rx_bytes: int
    tx_bytes: int
    timestamp: float
    rx_rate_bps: float | None = None
    tx_rate_bps: float | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BandwidthSnapshot:
    timestamp: float
    interfaces: tuple[BandwidthSample, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NetworkReport:
    sockets: tuple[SocketEntry, ...]
    listening_sockets: tuple[SocketEntry, ...]
    arp: tuple[ArpEntry, ...]
    conntrack: tuple[ConntrackEntry, ...]
    bandwidth: BandwidthSnapshot

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def socket_diag(
    proc_net: Path = PROC / "net",
    proc_root: Path = PROC,
) -> tuple[SocketEntry, ...]:
    sockets = []
    sockets.extend(_read_ip_sockets(proc_net / "tcp", "tcp", proc_root))
    sockets.extend(_read_ip_sockets(proc_net / "udp", "udp", proc_root))
    sockets.extend(_read_unix_sockets(proc_net / "unix", proc_root))
    return tuple(sockets)


def arp_table(proc_net: Path = PROC / "net") -> tuple[ArpEntry, ...]:
    path = proc_net / "arp"
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ()
    entries = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        entries.append(ArpEntry(ip_address=fields[0], hw_type=fields[1], flags=fields[2], mac_address=fields[3], mask=fields[4], device=fields[5]))
    return tuple(entries)


def conntrack_entries(proc_net: Path = PROC / "net") -> tuple[ConntrackEntry, ...]:
    path = proc_net / "nf_conntrack"
    if not path.exists():
        path = proc_net / "ip_conntrack"
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ()
    entries = []
    for line in lines:
        tokens = line.split()
        protocol = tokens[0] if tokens else "unknown"
        state = None
        src = dst = None
        sport = dport = None
        for token in tokens:
            if token.startswith("src="):
                src = token.split("=", 1)[1]
            elif token.startswith("dst="):
                dst = token.split("=", 1)[1]
            elif token.startswith("sport="):
                try:
                    sport = int(token.split("=", 1)[1])
                except ValueError:
                    pass
            elif token.startswith("dport="):
                try:
                    dport = int(token.split("=", 1)[1])
                except ValueError:
                    pass
            elif token in {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT", "ASSURED", "UNREPLIED", "CLOSE"}:
                state = token
        entries.append(ConntrackEntry(protocol=protocol, state=state, src=src, dst=dst, sport=sport, dport=dport, raw=line))
    return tuple(entries)


def network_bandwidth(proc_net_dev: Path = PROC / "net" / "dev", previous: BandwidthSnapshot | None = None, timestamp: float | None = None) -> BandwidthSnapshot:
    now = timestamp if timestamp is not None else _now()
    samples = []
    current = _parse_net_dev(proc_net_dev, now)
    if previous is None:
        return current
    elapsed = max(current.timestamp - previous.timestamp, 1e-9)
    previous_map = {sample.name: sample for sample in previous.interfaces}
    for sample in current.interfaces:
        prev = previous_map.get(sample.name)
        if prev is None:
            samples.append(sample)
            continue
        samples.append(BandwidthSample(
            name=sample.name,
            rx_bytes=sample.rx_bytes,
            tx_bytes=sample.tx_bytes,
            timestamp=sample.timestamp,
            rx_rate_bps=(sample.rx_bytes - prev.rx_bytes) / elapsed,
            tx_rate_bps=(sample.tx_bytes - prev.tx_bytes) / elapsed,
        ))
    return BandwidthSnapshot(timestamp=current.timestamp, interfaces=tuple(samples))


def network_report(
    proc_net: Path = PROC / "net",
    proc_root: Path = PROC,
    previous_bandwidth: BandwidthSnapshot | None = None,
) -> NetworkReport:
    bandwidth = network_bandwidth(proc_net / "dev", previous=previous_bandwidth)
    sockets = socket_diag(proc_net, proc_root)
    arp = arp_table(proc_net)
    conntrack = conntrack_entries(proc_net)
    listening = tuple(entry for entry in sockets if entry.state == "LISTEN" or entry.local_port == 0)
    return NetworkReport(sockets=sockets, listening_sockets=listening, arp=arp, conntrack=conntrack, bandwidth=bandwidth)


def group_sockets(sockets: tuple[SocketEntry, ...]) -> dict[str, tuple[SocketEntry, ...]]:
    grouped: dict[str, list[SocketEntry]] = {
        "listening": [],
        "established": [],
        "unix": [],
        "other": [],
    }
    for entry in sockets:
        if entry.protocol == "unix":
            grouped["unix"].append(entry)
        elif entry.state == "LISTEN":
            grouped["listening"].append(entry)
        elif entry.state == "ESTABLISHED":
            grouped["established"].append(entry)
        else:
            grouped["other"].append(entry)
    return {name: tuple(values) for name, values in grouped.items()}


def _read_ip_sockets(path: Path, protocol: str, proc_root: Path) -> list[SocketEntry]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    entries: list[SocketEntry] = []
    inode_map = _inode_to_pids(proc_root)
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local_ip, local_port = _decode_address(fields[1])
        remote_ip, remote_port = _decode_address(fields[2])
        state = _TCP_STATES.get(fields[3], fields[3] if protocol == "tcp" else "UNCONN")
        inode = _safe_int(fields[9])
        entries.append(SocketEntry(protocol=protocol, local_address=local_ip, local_port=local_port, remote_address=remote_ip, remote_port=remote_port, state=state, inode=inode, pids=inode_map.get(inode, ())))
    return entries


def _read_unix_sockets(path: Path, proc_root: Path) -> list[SocketEntry]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    entries: list[SocketEntry] = []
    inode_map = _inode_to_pids(proc_root)
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 7:
            continue
        inode = _safe_int(fields[6])
        path_text = fields[7] if len(fields) > 7 else None
        entries.append(SocketEntry(protocol="unix", local_address=path_text or "", local_port=0, remote_address="", remote_port=0, state=fields[5], inode=inode, pids=inode_map.get(inode, ()), path=path_text))
    return entries


def _inode_to_pids(proc_root: Path) -> dict[int, tuple[int, ...]]:
    mapping: dict[int, list[int]] = {}
    if not proc_root.exists():
        return {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        if not fd_dir.exists():
            continue
        try:
            pid = int(entry.name)
        except ValueError:
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    try:
                        inode = int(target[8:-1])
                    except ValueError:
                        continue
                    mapping.setdefault(inode, []).append(pid)
        except OSError:
            continue
    return {inode: tuple(sorted(set(pids))) for inode, pids in mapping.items()}


def _decode_address(value: str) -> tuple[str, int]:
    ip_hex, port_hex = value.split(":")
    if len(ip_hex) == 8:
        raw = bytes.fromhex(ip_hex)
        ip = str(ipaddress.IPv4Address(struct.unpack("<I", raw)[0]))
    else:
        ip = ip_hex
    return ip, int(port_hex, 16)


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def _parse_net_dev(path: Path, timestamp: float) -> BandwidthSnapshot:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return BandwidthSnapshot(timestamp=timestamp, interfaces=())
    samples = []
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, stats = line.split(":", 1)
        fields = stats.split()
        if len(fields) < 16:
            continue
        samples.append(BandwidthSample(name=name.strip(), rx_bytes=int(fields[0]), tx_bytes=int(fields[8]), timestamp=timestamp))
    return BandwidthSnapshot(timestamp=timestamp, interfaces=tuple(samples))


def _now() -> float:
    import time
    return time.time()
