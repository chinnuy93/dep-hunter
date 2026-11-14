from __future__ import annotations

import sys
import time
from typing import TextIO

from dephunter.core.progress import ProgressUpdate
from dephunter.core.util import format_duration
from dephunter.cli.theme import theme

_LABELS = {
    "crawl": "web crawl",
    "github": "github harvest",
    "gitlab": "gitlab harvest",
    "analyze": "registry analysis",
    "report": "report generation",
    "complete": "complete",
}
_WEIGHTS = {"crawl": 30, "github": 20, "gitlab": 5, "analyze": 40, "report": 5}


class ProgressRenderer:
    def __init__(
        self,
        phases: list[str] | tuple[str, ...],
        *,
        stream: TextIO | None = None,
    ) -> None:
        self.stream = stream or sys.stderr
        self.phases = [phase for phase in _WEIGHTS if phase in set(phases)]
        self.weights = {phase: _WEIGHTS[phase] for phase in self.phases}
        self.total_weight = sum(self.weights.values()) or 1
        self.started = time.monotonic()
        self.percent = 0
        self.current = ""
        self.tty = getattr(self.stream, "isatty", lambda: False)()
        self._last_draw = 0.0
        self._last_non_tty_percent = -10
        self._drawn = False

    def update(self, event: ProgressUpdate) -> None:
        if event.phase not in self.weights:
            return
        index = self.phases.index(event.phase)
        prior = sum(self.weights[phase] for phase in self.phases[:index])
        fraction = 1.0 if event.done else max(0.0, min(1.0, event.fraction))
        overall = (prior + self.weights[event.phase] * fraction) / self.total_weight * 100
        self.percent = max(self.percent, min(100, int(round(overall))))
        self.current = event.phase
        if self.tty:
            now = time.monotonic()
            if event.done or now - self._last_draw >= 0.08:
                self._draw(event)
                self._last_draw = now
        elif event.done or event.phase != getattr(self, "_last_phase", ""):
            self._print_event(event)
        self._last_phase = event.phase

    def finish(self, status: str, elapsed_seconds: float | None = None) -> None:
        if self.tty and self._drawn:
            self.stream.write("\r\033[2K")
        elapsed = format_duration(
            elapsed_seconds if elapsed_seconds is not None else time.monotonic() - self.started
        )
        succeeded = status in {"COMPLETED", "PARTIAL"}
        percent = 100 if succeeded else self.percent
        bar = self._bar(percent)
        color = "green" if status == "COMPLETED" else ("yellow" if succeeded else "red")
        line = (
            f"{bar} {theme.paint(f'{percent:>3}%', color, 'bold')}  "
            f"{theme.paint(status, color, 'bold')}  "
            f"{theme.paint(elapsed, 'dim')}"
        )
        self.stream.write(f"{line}\n")
        self.stream.flush()

    def _print_event(self, event: ProgressUpdate) -> None:
        bar = self._bar(self.percent)
        detail = self._detail(event)
        line = (
            f"{bar} {theme.paint(f'{self.percent:>3}%', 'green', 'bold')}  "
            f"{theme.paint(_LABELS.get(event.phase, event.phase), 'magenta')}  "
            f"{theme.paint(detail, 'dim')}"
        )
        self.stream.write(f"{line}\n")
        self.stream.flush()

    def _draw(self, event: ProgressUpdate) -> None:
        bar = self._bar(self.percent)
        detail = self._detail(event)
        line = (
            f"{bar} {theme.paint(f'{self.percent:>3}%', 'green', 'bold')}  "
            f"{theme.paint(_LABELS.get(event.phase, event.phase), 'magenta')}  "
            f"{theme.paint(detail, 'dim')}  "
            f"{theme.paint(format_duration(time.monotonic() - self.started), 'dim')}"
        )
        self.stream.write(f"\r\033[2K{line}")
        self.stream.flush()
        self._drawn = True

    @staticmethod
    def _detail(event: ProgressUpdate) -> str:
        parts: list[str] = []
        if event.message:
            parts.append(event.message)
        if event.total:
            parts.append(f"{event.completed}/{event.total}")
        return "  ".join(parts) or "working"

    @staticmethod
    def _bar(percent: int, width: int = 24) -> str:
        filled = int(width * max(0, min(100, percent)) / 100)
        if theme.enabled:
            return (
                theme.paint("█" * filled, "cyan", "bold")
                + theme.paint("░" * (width - filled), "dim")
            )
        return "[" + "=" * filled + " " * (width - filled) + "]"
