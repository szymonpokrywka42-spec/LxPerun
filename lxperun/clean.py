"""Cleanup helpers for reclaiming disk space."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import os
import shutil
import time
from typing import Callable

from .linux import run_command


@dataclass(frozen=True)
class CleanAction:
    name: str
    state: str
    detail: str
    reclaimed_bytes: int = 0
    command: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CleanReport:
    dry_run: bool
    actions: tuple[CleanAction, ...]
    total_reclaimed_bytes: int
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def clean(
    coredump_dir: Path = Path("/var/lib/systemd/coredump"),
    older_than_days: int = 7,
    dry_run: bool = True,
    which_fn: Callable[[str], str | None] = shutil.which,
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]] = run_command,
    is_root_fn: Callable[[], int] = os.geteuid,
) -> CleanReport:
    actions: list[CleanAction] = []
    recommendations: list[str] = []
    total_reclaimed_bytes = 0

    coredump_action = _clean_coredumps(
        coredump_dir=coredump_dir,
        older_than_days=older_than_days,
        dry_run=dry_run,
        is_root_fn=is_root_fn,
    )
    actions.append(coredump_action)
    total_reclaimed_bytes += coredump_action.reclaimed_bytes

    flatpak_action = _clean_flatpak(dry_run=dry_run, which_fn=which_fn, run_command_fn=run_command_fn, is_root_fn=is_root_fn)
    actions.append(flatpak_action)

    package_action = _clean_package_cache(dry_run=dry_run, which_fn=which_fn, run_command_fn=run_command_fn, is_root_fn=is_root_fn)
    actions.append(package_action)

    if dry_run:
        recommendations.append("Re-run with `--apply` to execute the cleanup steps.")
    if any(action.state == "skipped" for action in actions):
        recommendations.append("Some system-level actions need root privileges.")

    return CleanReport(
        dry_run=dry_run,
        actions=tuple(actions),
        total_reclaimed_bytes=total_reclaimed_bytes,
        recommendations=tuple(recommendations),
    )


def _clean_coredumps(
    coredump_dir: Path,
    older_than_days: int,
    dry_run: bool,
    is_root_fn: Callable[[], int],
) -> CleanAction:
    if not coredump_dir.exists():
        return CleanAction(
            name="coredumps",
            state="unavailable",
            detail=f"{coredump_dir} does not exist.",
        )

    candidates: list[Path] = []
    cutoff = time.time() - (older_than_days * 86400)
    for path in sorted(coredump_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            continue
        try:
            stat_result = path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if stat_result.st_mtime <= cutoff:
            candidates.append(path)

    if not candidates:
        return CleanAction(
            name="coredumps",
            state="done",
            detail=f"No coredump files older than {older_than_days} day(s) were found in {coredump_dir}.",
        )

    reclaimed_bytes = sum(path.stat().st_size for path in candidates if path.exists())
    if dry_run:
        return CleanAction(
            name="coredumps",
            state="planned",
            detail=f"Would remove {len(candidates)} coredump file(s) older than {older_than_days} day(s) from {coredump_dir}.",
            reclaimed_bytes=reclaimed_bytes,
            evidence=tuple(str(path) for path in candidates[:8]),
        )

    if is_root_fn() != 0:
        return CleanAction(
            name="coredumps",
            state="skipped",
            detail="Root privileges are required to remove system coredumps.",
            missing=("run with sudo",),
            evidence=tuple(str(path) for path in candidates[:8]),
        )

    removed = 0
    deleted_bytes = 0
    for path in candidates:
        try:
            deleted_bytes += path.stat().st_size
            path.unlink()
            removed += 1
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return CleanAction(
        name="coredumps",
        state="done" if removed else "failed",
        detail=f"Removed {removed} coredump file(s) from {coredump_dir}.",
        reclaimed_bytes=deleted_bytes,
        evidence=tuple(str(path) for path in candidates[:8]),
    )


def _clean_flatpak(
    dry_run: bool,
    which_fn: Callable[[str], str | None],
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
    is_root_fn: Callable[[], int],
) -> CleanAction:
    flatpak = which_fn("flatpak")
    if flatpak is None:
        return CleanAction(
            name="flatpak",
            state="unavailable",
            detail="flatpak is not installed or not in PATH.",
            missing=("flatpak not installed",),
        )

    command = [flatpak, "uninstall", "--unused", "-y"]
    if is_root_fn() == 0:
        command.insert(2, "--system")

    if dry_run:
        return CleanAction(
            name="flatpak",
            state="planned",
            detail="Would remove unused Flatpak runtimes and extensions.",
            command=tuple(command),
            evidence=(flatpak,),
        )

    code, stdout, stderr = run_command_fn(command, 120.0)
    if code != 0:
        return CleanAction(
            name="flatpak",
            state="failed",
            detail=stderr or stdout or "flatpak cleanup failed.",
            command=tuple(command),
            evidence=(flatpak,),
        )
    return CleanAction(
        name="flatpak",
        state="done",
        detail=stdout or "Removed unused Flatpak runtimes and extensions.",
        command=tuple(command),
        evidence=(flatpak,),
    )


def _clean_package_cache(
    dry_run: bool,
    which_fn: Callable[[str], str | None],
    run_command_fn: Callable[[list[str], float], tuple[int, str, str]],
    is_root_fn: Callable[[], int],
) -> CleanAction:
    candidates = (
        ("dnf", ["dnf", "clean", "all"], "Clean DNF cache"),
        ("pacman", ["pacman", "-Sc", "--noconfirm"], "Clean pacman cache"),
        ("apt-get", ["apt-get", "clean"], "Clean APT cache"),
    )
    for tool_name, command, detail in candidates:
        tool_path = which_fn(tool_name)
        if tool_path is None:
            continue

        command = [tool_path] + command[1:]
        if dry_run:
            return CleanAction(
                name="package-cache",
                state="planned",
                detail=f"Would run {tool_name} cache cleanup.",
                command=tuple(command),
                evidence=(tool_path,),
            )

        if is_root_fn() != 0:
            return CleanAction(
                name="package-cache",
                state="skipped",
                detail=f"Root privileges are required to run {tool_name} cache cleanup.",
                command=tuple(command),
                evidence=(tool_path,),
                missing=("run with sudo",),
            )

        code, stdout, stderr = run_command_fn(command, 120.0)
        if code != 0:
            return CleanAction(
                name="package-cache",
                state="failed",
                detail=stderr or stdout or f"{tool_name} cache cleanup failed.",
                command=tuple(command),
                evidence=(tool_path,),
            )
        return CleanAction(
            name="package-cache",
            state="done",
            detail=stdout or detail,
            command=tuple(command),
            evidence=(tool_path,),
        )

    return CleanAction(
        name="package-cache",
        state="unavailable",
        detail="No supported package manager cache tool was found.",
        missing=("dnf", "pacman", "apt-get"),
    )
