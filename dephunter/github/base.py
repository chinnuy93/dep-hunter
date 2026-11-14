from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class HarvestResult:
    repos: int = 0
    files: int = 0
    parsed: int = 0
    skipped: int = 0
    errors: int = 0
    dependencies: int = 0
    config_facts: int = 0
    warnings: int = 0
    requests: int = 0
    rate_limited: bool = False
    budget_exhausted: bool = False
    messages: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        self.messages.append(message[:500])
