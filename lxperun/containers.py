"""Container-focused view built on top of security posture checks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .network import NetworkReport
from .security import SecurityFinding, SecuritySignal, security_report


@dataclass(frozen=True)
class ContainerReport:
    effective_uid: int
    is_root: bool
    signals: tuple[SecuritySignal, ...]
    findings: tuple[SecurityFinding, ...]
    recommendations: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def container_report(
    root: Path = Path("/"),
    network_report_obj: NetworkReport | None = None,
) -> ContainerReport:
    report = security_report(root=root, network_report_obj=network_report_obj)
    signals = tuple(signal for signal in report.signals if signal.name in {"root", "container", "namespaces"})
    findings = tuple(finding for finding in report.findings if finding.category == "container")
    recommendations = []
    if findings:
        recommendations.insert(0, "Review container cgroups, runtime sockets, and namespaces before assuming bare-metal isolation.")
    return ContainerReport(
        effective_uid=report.effective_uid,
        is_root=report.is_root,
        signals=signals,
        findings=findings,
        recommendations=tuple(recommendations),
    )
