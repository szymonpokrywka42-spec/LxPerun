"""Minimal terminal formatting helpers for LxPerun."""

from __future__ import annotations

import os


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def supports_color(force_color: bool = False) -> bool:
    if force_color:
        return True
    return os.isatty(1) and os.environ.get("NO_COLOR") is None


def color(text: str, code: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{code}{text}{Style.RESET}"


def bold(text: str, enabled: bool = True) -> str:
    return color(text, Style.BOLD, enabled)


def dim(text: str, enabled: bool = True) -> str:
    return color(text, Style.DIM, enabled)


def green(text: str, enabled: bool = True) -> str:
    return color(text, Style.GREEN, enabled)


def yellow(text: str, enabled: bool = True) -> str:
    return color(text, Style.YELLOW, enabled)


def red(text: str, enabled: bool = True) -> str:
    return color(text, Style.RED, enabled)


def cyan(text: str, enabled: bool = True) -> str:
    return color(text, Style.CYAN, enabled)
