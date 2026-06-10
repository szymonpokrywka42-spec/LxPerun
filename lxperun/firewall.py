"""Firewall posture checks for LxPerun."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import shutil
from typing import Callable

from .linux import run_command
from .network import NetworkReport, network_report


@dataclass(frozen=True)
class FirewallBackend:
    name: str
    available: bool
    command: str
    policy: str | None
    rules: tuple[str, ...]
    raw_output: tuple[str, ...]
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FirewallPortMapping:
    backend: str
    protocol: str
    port: int
    address: str
    decision: str
    rule: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FirewallReport:
    backends: tuple[FirewallBackend, ...]
    mappings: tuple[FirewallPortMapping, ...]
    recommendations: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not any(mapping.decision.startswith("blocked") for mapping in self.mappings)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def firewall_report(
    network_report_obj: NetworkReport | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
) -> FirewallReport:
    network = network_report_obj or network_report()
    backends = (
        _iptables_backend(which_fn, run_command_fn),
        _nft_backend(which_fn, run_command_fn),
    )
    mappings = []
    for backend in backends:
        mappings.extend(_map_listening_sockets(backend, network.listening_sockets))
    recommendations = _recommendations(backends, mappings)
    return FirewallReport(
        backends=backends,
        mappings=tuple(mappings),
        recommendations=tuple(recommendations),
    )


def _iptables_backend(which_fn: Callable[[str], str | None], run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> FirewallBackend:
    command = which_fn("iptables")
    if command is None:
        return FirewallBackend(
            name="iptables",
            available=False,
            command="iptables",
            policy=None,
            rules=(),
            raw_output=(),
            missing=("iptables not installed",),
        )
    code, stdout, stderr = run_command_fn([command, "-L", "-n", "-v", "--line-numbers"], 4.0)
    output = tuple(line for line in (stdout or stderr).splitlines() if line.strip())
    if code != 0:
        return FirewallBackend(
            name="iptables",
            available=False,
            command=command,
            policy=None,
            rules=(),
            raw_output=output,
            missing=("iptables list failed",),
        )
    return FirewallBackend(
        name="iptables",
        available=True,
        command=command,
        policy=_iptables_policy(output),
        rules=_iptables_rules(output),
        raw_output=output,
    )


def _nft_backend(which_fn: Callable[[str], str | None], run_command_fn: Callable[[list[str], float], tuple[int, str, str]]) -> FirewallBackend:
    command = which_fn("nft")
    if command is None:
        return FirewallBackend(
            name="nftables",
            available=False,
            command="nft",
            policy=None,
            rules=(),
            raw_output=(),
            missing=("nft not installed",),
        )
    code, stdout, stderr = run_command_fn([command, "list", "ruleset"], 4.0)
    output = tuple(line for line in (stdout or stderr).splitlines() if line.strip())
    if code != 0:
        return FirewallBackend(
            name="nftables",
            available=False,
            command=command,
            policy=None,
            rules=(),
            raw_output=output,
            missing=("nft ruleset list failed",),
        )
    return FirewallBackend(
        name="nftables",
        available=True,
        command=command,
        policy=_nft_policy(output),
        rules=_nft_rules(output),
        raw_output=output,
    )


def _iptables_policy(lines: tuple[str, ...]) -> str | None:
    for line in lines:
        match = re.search(r"Chain INPUT \(policy (\w+)", line)
        if match:
            return match.group(1).lower()
    return None


def _nft_policy(lines: tuple[str, ...]) -> str | None:
    for line in lines:
        match = re.search(r"policy\s+(\w+);", line)
        if match:
            return match.group(1).lower()
    return None


def _iptables_rules(lines: tuple[str, ...]) -> tuple[str, ...]:
    rules = []
    current_chain = None
    for line in lines:
        if line.startswith("Chain "):
            current_chain = line
            continue
        lowered = line.lower()
        if any(token in lowered for token in ("dpt:", "spt:")):
            rules.append(f"{current_chain or 'Chain ?'} :: {line.strip()}")
    return tuple(rules)


def _nft_rules(lines: tuple[str, ...]) -> tuple[str, ...]:
    rules = []
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in ("dport", "sport")) and any(token in lowered for token in ("accept", "drop", "reject")):
            rules.append(line.strip())
    return tuple(rules)


def _map_listening_sockets(backend: FirewallBackend, sockets) -> list[FirewallPortMapping]:
    mappings: list[FirewallPortMapping] = []
    if not backend.available:
        return mappings
    for socket_entry in sockets:
        if socket_entry.protocol not in {"tcp", "udp"} or socket_entry.local_port == 0:
            continue
        match = _match_rule(backend, socket_entry.protocol, socket_entry.local_port)
        if match is not None:
            decision, rule_text = match
            reason = f"matched {backend.name} rule"
        else:
            default_policy = backend.policy or "unknown"
            if default_policy in {"drop", "reject"}:
                decision = "blocked by policy"
                reason = f"default {backend.name} INPUT policy is {default_policy}"
            elif default_policy == "accept":
                decision = "allowed by policy"
                reason = f"default {backend.name} INPUT policy is accept"
            else:
                decision = "unknown"
                reason = f"no port-specific {backend.name} rule found"
        mappings.append(
            FirewallPortMapping(
                backend=backend.name,
                protocol=socket_entry.protocol,
                port=socket_entry.local_port,
                address=socket_entry.local_address,
                decision=decision,
                rule=rule_text if match else None,
                reason=reason,
            )
        )
    return mappings


def _match_rule(backend: FirewallBackend, protocol: str, port: int) -> tuple[str, str] | None:
    port_pattern = rf"\b(?:dpt:|dport\s+){port}\b"
    for rule in backend.rules:
        lowered = rule.lower()
        if protocol not in lowered:
            continue
        if re.search(port_pattern, lowered) is None:
            continue
        action = _extract_action(lowered)
        if action is None:
            continue
        if action == "accept":
            return ("allowed", rule)
        if action in {"drop", "reject"}:
            return ("blocked", rule)
    return None


def _extract_action(line: str) -> str | None:
    for action in ("accept", "drop", "reject"):
        if re.search(rf"\b{action}\b", line):
            return action
    if line.startswith("accept "):
        return "accept"
    if line.startswith("drop "):
        return "drop"
    if line.startswith("reject "):
        return "reject"
    tokens = line.split()
    if tokens:
        first = tokens[0]
        if first in {"accept", "drop", "reject"}:
            return first
    return None


def _recommendations(backends: tuple[FirewallBackend, ...], mappings: list[FirewallPortMapping]) -> list[str]:
    recommendations = []
    if not any(backend.available for backend in backends):
        recommendations.append("Install iptables or nftables tools if you want firewall rule visibility.")
    if any(mapping.decision.startswith("blocked") for mapping in mappings):
        recommendations.append("Some services are blocked by firewall policy; confirm that matches your intent.")
    if any(mapping.decision == "unknown" for mapping in mappings):
        recommendations.append("No explicit rule was found for some listeners; review the default firewall policy.")
    return recommendations
