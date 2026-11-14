from __future__ import annotations

import os
import sys
from typing import TextIO

_RESET = "\x1b[0m"
_STYLES = {
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "underline": "\x1b[4m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
}

_LOGO = r"""
██████╗ ███████╗██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔════╝██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║  ██║█████╗  ██████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║  ██║██╔══╝  ██╔═══╝ ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝███████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""".strip("\n")


class Theme:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def paint(self, text: object, *styles: str) -> str:
        value = "" if text is None else str(text)
        if not self.enabled or not styles:
            return value
        codes = "".join(_STYLES[style] for style in styles if style in _STYLES)
        return f"{codes}{value}{_RESET}" if codes else value

    def status(self, value: object, width: int = 0) -> str:
        text = f"{value:<{width}}" if width else str(value)
        mapping = {
            "COMPLETED": ("green", "bold"),
            "PARTIAL": ("yellow", "bold"),
            "FAILED": ("red", "bold"),
            "RUNNING": ("cyan", "bold"),
            "CREATED": ("dim",),
        }
        return self.paint(text, *mapping.get(str(value), ("bold",)))

    def classification(self, value: object, width: int = 0) -> str:
        text = f"{value:<{width}}" if width else str(value)
        mapping = {
            "CONFIRMED": ("red", "bold"),
            "HIGH_CONFIDENCE": ("yellow", "bold"),
            "CANDIDATE": ("cyan",),
            "INSUFFICIENT_EVIDENCE": ("dim",),
        }
        return self.paint(text, *mapping.get(str(value), ("bold",)))

    def check(self, value: object, width: int = 0) -> str:
        text = f"{value:<{width}}" if width else str(value)
        mapping = {
            "PASS": ("green", "bold"),
            "FAIL": ("red", "bold"),
            "WARN": ("yellow", "bold"),
            "SKIP": ("dim",),
        }
        return self.paint(text, *mapping.get(str(value), ("bold",)))


theme = Theme(False)


def configure(no_color: bool = False, stream: TextIO | None = None) -> Theme:
    target = stream or sys.stderr
    forced = os.environ.get("CLICOLOR_FORCE") not in {None, "", "0"}
    disabled = (
        no_color
        or os.environ.get("NO_COLOR") not in {None, ""}
        or os.environ.get("TERM") == "dumb"
    )
    theme.enabled = forced or (not disabled and getattr(target, "isatty", lambda: False)())
    return theme


def banner(version: str) -> str:
    tagline = theme.paint(
        f"  passive dependency-confusion discovery  ·  v{version}",
        "dim",
    )
    warning = theme.paint(
        "  AUTHORIZED TARGETS ONLY  ·  GET/HEAD ONLY  ·  NO EXPLOITATION",
        "red",
        "bold",
    )
    return f"{theme.paint(_LOGO, 'cyan', 'bold')}\n{tagline}\n{warning}"
