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
    clean_report: CleanReport
    reset_failed: RepairAction
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
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    is_root_fn: Callable[[], int] = os.geteuid,
) -> RepairReport:
    issues_before = diagnose(project_root).issues
    clean_report = clean(
        older_than_days=older_than_days,
        dry_run=dry_run,
        which_fn=which_fn,
        run_command_fn=run_command_fn,
        is_root_fn=is_root_fn,
    )
    reset_failed_action = _reset_failed_units(dry_run=dry_run, issues=issues_before, which_fn=which_fn, run_command_fn=run_command_fn, is_root_fn=is_root_fn)
    issues_after = diagnose(project_root).issues if not dry_run else ()
    recommendations = _recommendations(dry_run=dry_run, reset_failed_action=reset_failed_action, issues_before=issues_before, issues_after=issues_after)
    return RepairReport(
        dry_run=dry_run,
        project_root=str(project_root),
        issues_before=issues_before,
        issues_after=issues_after,
        clean_report=clean_report,
        reset_failed=reset_failed_action,
        recommendations=tuple(recommendations),
    )


def _reset_failed_units(
    dry_run: bool,
    issues: tuple[DiagnosticIssue, ...],
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
            command=tuple(command),
            evidence=(systemctl, *failed_units[:4]),
        )

    if is_root_fn() != 0:
        return RepairAction(
            name="systemd-reset-failed",
            state="skipped",
            detail="Root privileges are required to reset failed systemd units.",
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
            command=tuple(command),
            evidence=(systemctl, *failed_units[:4]),
        )
    return RepairAction(
        name="systemd-reset-failed",
        state="done",
        detail=stdout or f"Cleared failed state for {len(failed_units)} unit(s).",
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


def _recommendations(
    dry_run: bool,
    reset_failed_action: RepairAction,
    issues_before: tuple[DiagnosticIssue, ...],
    issues_after: tuple[DiagnosticIssue, ...],
) -> list[str]:
    recommendations: list[str] = []
    if dry_run:
        recommendations.append("Re-run with `--apply` to execute the safe repair actions.")
    if reset_failed_action.state == "skipped":
        recommendations.append("Run the repair command with `--root` to reset failed systemd units.")
    if issues_after and not dry_run:
        remaining = len(issues_after)
        recommendations.append(f"{remaining} issue(s) remain after repair; inspect the remaining doctor output for manual fixes.")
    if len(issues_before) == 0:
        recommendations.append("No issues were reported before repair, so there was nothing to fix automatically.")
    return recommendations
