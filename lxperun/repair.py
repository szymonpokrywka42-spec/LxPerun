"""Safe repair actions built on top of LxPerun diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import shutil
from pathlib import Path
from typing import Callable

from .clean import CleanReport, clean
from .doctor import DoctorReport, DiagnosticIssue, diagnose
from .linux import run_command


@dataclass(frozen=True)
class RepairAction:
    name: str
    state: str
    detail: str
    risk: str = "safe"
    command: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RepairReport:
    dry_run: bool
    project_root: str
    issues_before: tuple[DiagnosticIssue, ...]
    issues_after: tuple[DiagnosticIssue, ...]
    sensitive_issues: tuple[DiagnosticIssue, ...]
    manual_issues: tuple[DiagnosticIssue, ...]
    clean_report: CleanReport
    reset_failed: RepairAction
    confirmation_required: bool
    recommendations: tuple[str, ...]

    @property
    def issues_before_count(self) -> int:
        return len(self.issues_before)

    @property
    def issues_after_count(self) -> int:
        return len(self.issues_after)

    @property
    def total_reclaimed_bytes(self) -> int:
        return self.clean_report.total_reclaimed_bytes

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["issues_before_count"] = self.issues_before_count
        data["issues_after_count"] = self.issues_after_count
        data["total_reclaimed_bytes"] = self.total_reclaimed_bytes
        return data


def repair(
    project_root: Path | str = ".",
    older_than_days: int = 7,
    dry_run: bool = True,
    yes: bool = False,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    is_root_fn: Callable[[], int] = os.geteuid,
    input_fn: Callable[[str], str] = input,
) -> RepairReport:
    issues_before = diagnose(project_root).issues
    sensitive_issues, manual_issues = _classify_issues(issues_before)
    clean_report = clean(
        older_than_days=older_than_days,
        dry_run=dry_run,
        which_fn=which_fn,
        run_command_fn=run_command_fn,
        is_root_fn=is_root_fn,
    )
    reset_failed_action = _reset_failed_units(
        dry_run=dry_run,
        issues=issues_before,
        yes=yes,
        input_fn=input_fn,
        which_fn=which_fn,
        run_command_fn=run_command_fn,
        is_root_fn=is_root_fn,
    )
    issues_after = diagnose(project_root).issues if not dry_run else ()
    confirmation_required = bool(sensitive_issues) and not dry_run and not yes
    recommendations = _recommendations(
        dry_run=dry_run,
        reset_failed_action=reset_failed_action,
        issues_before=issues_before,
        issues_after=issues_after,
        sensitive_issues=sensitive_issues,
        manual_issues=manual_issues,
        confirmation_required=confirmation_required,
    )
    return RepairReport(
        dry_run=dry_run,
        project_root=str(project_root),
        issues_before=issues_before,
        issues_after=issues_after,
        sensitive_issues=sensitive_issues,
        manual_issues=manual_issues,
        clean_report=clean_report,
        reset_failed=reset_failed_action,
        confirmation_required=confirmation_required,
        recommendations=tuple(recommendations),
    )


def _reset_failed_units(
    dry_run: bool,
    issues: tuple[DiagnosticIssue, ...],
    yes: bool,
    input_fn: Callable[[str], str],
    which_fn: Callable[[str], str | None],
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
    is_root_fn: Callable[[], int],
) -> RepairAction:
    systemctl = which_fn("systemctl")
    if systemctl is None:
        return RepairAction(
            name="systemd-reset-failed",
            state="unavailable",
            detail="systemctl is not installed or not in PATH.",
            missing=("systemctl not installed",),
        )

    failed_units = _failed_units_from_issues(issues)
    if not failed_units:
        return RepairAction(
            name="systemd-reset-failed",
            state="done",
            detail="No failed systemd units were reported by doctor.",
            evidence=(systemctl,),
        )

    command = [systemctl, "reset-failed"]
    if dry_run:
        return RepairAction(
            name="systemd-reset-failed",
            state="planned",
            detail=f"Would clear failed state for {len(failed_units)} unit(s).",
            risk="sensitive",
            command=tuple(command),
            evidence=(systemctl, *failed_units[:4]),
        )

    if not yes:
        answer = input_fn(
            "I'm gonna try to fix that. Are you sure you want this? [y/N] "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            return RepairAction(
                name="systemd-reset-failed",
                state="skipped",
                detail="User declined the sensitive systemd reset.",
                risk="sensitive",
                command=tuple(command),
                evidence=(systemctl, *failed_units[:4]),
                missing=("confirmation declined",),
            )

    if is_root_fn() != 0:
        return RepairAction(
            name="systemd-reset-failed",
            state="skipped",
            detail="Root privileges are required to reset failed systemd units.",
            risk="sensitive",
            command=tuple(command),
            evidence=(systemctl, *failed_units[:4]),
            missing=("run with sudo",),
        )

    code, stdout, stderr = run_command_fn(command, 30.0)
    if code != 0:
        return RepairAction(
            name="systemd-reset-failed",
            state="failed",
            detail=stderr or stdout or "systemctl reset-failed failed.",
            risk="sensitive",
            command=tuple(command),
            evidence=(systemctl, *failed_units[:4]),
        )
    return RepairAction(
        name="systemd-reset-failed",
        state="done",
        detail=stdout or f"Cleared failed state for {len(failed_units)} unit(s).",
        risk="sensitive",
        command=tuple(command),
        evidence=(systemctl, *failed_units[:4]),
    )


def _failed_units_from_issues(issues: tuple[DiagnosticIssue, ...]) -> tuple[str, ...]:
    units = []
    for issue in issues:
        if issue.source != "systemd" or not issue.message.startswith("Failed unit: "):
            continue
        units.append(issue.message.removeprefix("Failed unit: ").strip())
    return tuple(units)


def _classify_issues(issues: tuple[DiagnosticIssue, ...]) -> tuple[tuple[DiagnosticIssue, ...], tuple[DiagnosticIssue, ...]]:
    sensitive: list[DiagnosticIssue] = []
    manual: list[DiagnosticIssue] = []
    for issue in issues:
        if issue.source == "systemd" and issue.message.startswith("Failed unit: "):
            sensitive.append(issue)
        elif issue.severity in {"error", "critical"}:
            manual.append(issue)
    return tuple(sensitive), tuple(manual)


def _recommendations(
    dry_run: bool,
    reset_failed_action: RepairAction,
    issues_before: tuple[DiagnosticIssue, ...],
    issues_after: tuple[DiagnosticIssue, ...],
    sensitive_issues: tuple[DiagnosticIssue, ...],
    manual_issues: tuple[DiagnosticIssue, ...],
    confirmation_required: bool,
) -> list[str]:
    recommendations: list[str] = []
    if dry_run:
        recommendations.append("Re-run with `--apply` to execute the safe repair actions.")
    if confirmation_required:
        recommendations.append("A sensitive fix was detected; confirm the prompt before the repair can continue.")
    if reset_failed_action.state == "skipped":
        recommendations.append("Run the repair command with `--root` to reset failed systemd units.")
    if issues_after and not dry_run:
        remaining = len(issues_after)
        recommendations.append(f"{remaining} issue(s) remain after repair; inspect the remaining doctor output for manual fixes.")
    if sensitive_issues:
        recommendations.append(f"{len(sensitive_issues)} sensitive issue(s) were found; these are limited to service-state resets and similar low-risk operational changes.")
    if manual_issues:
        recommendations.append(f"{len(manual_issues)} issue(s) still require manual work; repair will not guess kernel, network, security, or syntax fixes.")
    if len(issues_before) == 0:
        recommendations.append("No issues were reported before repair, so there was nothing to fix automatically.")
    return recommendations
