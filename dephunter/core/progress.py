from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProgressUpdate:
    """A single pipeline progress event."""

    phase: str
    fraction: float = 0.0
    completed: int = 0
    total: int = 0
    message: str = ""
    done: bool = False
