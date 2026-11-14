from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import aiohttp

from dephunter.analysis.engine import AnalysisEngine, AnalysisResult
from dephunter.core.config import Settings
from dephunter.core.evidence import EvidenceStore
from dephunter.core.http import HostRateLimiter, SafeHttpClient
from dephunter.core.models import ScanPhase, ScanStatus
from dephunter.core.progress import ProgressUpdate
from dephunter.core.scope import ScopeConfig, ScopePolicy
from dephunter.crawler.crawler import CrawlResult, WebCrawler
from dephunter.database.db import Database
from dephunter.github.base import HarvestResult
from dephunter.github.harvester import GitHubHarvester
from dephunter.gitlab.harvester import GitLabHarvester
from dephunter.registries.manager import RegistryManager
from dephunter.reporting.manager import ReportManager

log = logging.getLogger(__name__)

PHASES = ("crawl", "github", "gitlab", "analyze", "report")
_REGISTRY_RATE_OVERRIDES = {
    "crates.io": 1.0,
    "index.crates.io": 1.0,
    "static.crates.io": 1.0,
    "api.github.com": 2.0,
    "gitlab.com": 2.0,
}


@dataclass(slots=True)
class PipelineOutcome:
    scan_id: int
    status: str
    crawl: CrawlResult | None = None
    github: HarvestResult | None = None
    gitlab: HarvestResult | None = None
    analysis: AnalysisResult | None = None
    reports: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    phase_timings: dict[str, float] = field(default_factory=dict)


class ScanPipeline:
    def __init__(
        self,
        settings: Settings,
        scope: ScopeConfig,
        db: Database,
        *,
        on_progress: Callable[[ProgressUpdate], None] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.db = db
        self.on_progress = on_progress
        self.log = logger or log
        self.policy = ScopePolicy(scope)

    async def run(
        self,
        scan_id: int | None = None,
        *,
        phases: Iterable[str] | None = None,
        report_formats: Iterable[str] | None = None,
        output_dir: str | Path | None = None,
    ) -> PipelineOutcome:
        selected = self._normalize_phases(phases)
        if scan_id is None:
            scan_id = self.db.create_scan(
                self.scope.program,
                str(self.scope.source_path) if self.scope.source_path else None,
                self.scope.snapshot(),
            )
        else:
            scan = self.db.get_scan(scan_id)
            if scan is None:
                raise KeyError(f"scan {scan_id} not found")
        outcome = PipelineOutcome(scan_id=scan_id, status=ScanStatus.RUNNING.value)
        self.db.update_scan(scan_id, status=ScanStatus.RUNNING, phase=ScanPhase.INIT)

        limiter = self._build_limiter()
        timeout = aiohttp.ClientTimeout(total=self.settings.http_timeout)
        connector = aiohttp.TCPConnector(limit=max(1, self.settings.http_concurrency))
        evidence = EvidenceStore(self.settings.evidence_dir)
        partial = False
        last_phase = ScanPhase.INIT
        started = time.monotonic()
        phase_timings: dict[str, float] = {}
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False) as session:
                http = SafeHttpClient(
                    session,
                    self.policy,
                    self.settings.user_agent,
                    rate_limiter=limiter,
                    timeout=self.settings.http_timeout,
                    max_body_bytes=self.settings.evidence_max_bytes,
                    logger=self.log,
                )
                for phase in (item for item in PHASES if item in selected):
                    phase_started = time.monotonic()
                    last_phase = ScanPhase(phase)
                    self.db.update_scan(scan_id, phase=last_phase)
                    self._emit_progress(phase, 0.0, message="starting")
                    finish_message = ""

                    if phase == "crawl":
                        if self.scope.web:
                            crawler = WebCrawler(
                                self.db,
                                http,
                                self.policy,
                                self.scope,
                                evidence,
                                max_body_bytes=self.settings.evidence_max_bytes,
                                progress=self._crawl_progress,
                                logger=self.log,
                            )
                            outcome.crawl = await crawler.crawl(scan_id)
                            self._save_stats(scan_id)
                        else:
                            finish_message = "skipped: no web targets"

                    elif phase == "github":
                        if self.scope.github.enabled:
                            github = GitHubHarvester(
                                self.db,
                                http,
                                self.policy,
                                self.scope,
                                evidence,
                                token=self.settings.github_token,
                                max_file_bytes=self.settings.evidence_max_bytes,
                                logger=self.log,
                            )
                            outcome.github = await github.harvest(scan_id)
                            if outcome.github.rate_limited or outcome.github.budget_exhausted:
                                partial = True
                                outcome.notes.extend(outcome.github.messages)
                            self._save_stats(scan_id)
                        else:
                            finish_message = "skipped: GitHub harvesting disabled"

                    elif phase == "gitlab":
                        if self.scope.gitlab.enabled:
                            gitlab = GitLabHarvester(
                                self.db,
                                http,
                                self.policy,
                                self.scope,
                                evidence,
                                token=self.settings.gitlab_token,
                                max_file_bytes=self.settings.evidence_max_bytes,
                                logger=self.log,
                            )
                            outcome.gitlab = await gitlab.harvest(scan_id)
                            if outcome.gitlab.rate_limited or outcome.gitlab.budget_exhausted:
                                partial = True
                                outcome.notes.extend(outcome.gitlab.messages)
                            self._save_stats(scan_id)
                        else:
                            finish_message = "skipped: GitLab harvesting disabled"

                    elif phase == "analyze":
                        manager = RegistryManager(
                            self.db,
                            http,
                            self.scope.enabled_ecosystems,
                            cache_ttl_hours=self.scope.registries.cache_ttl_hours,
                            concurrency=self.settings.registry_concurrency,
                            logger=self.log,
                        )
                        analyzer = AnalysisEngine(
                            self.db,
                            self.scope,
                            manager,
                            progress=self._analysis_progress,
                            logger=self.log,
                        )
                        outcome.analysis = await analyzer.analyze(scan_id)
                        self._save_stats(scan_id)

                    elif phase == "report":
                        reports = ReportManager(self.db, logger=self.log).generate(
                            scan_id,
                            formats=report_formats or ("md", "html", "json"),
                            output_dir=output_dir or self.settings.reports_dir,
                        )
                        outcome.reports = reports

                    phase_timings[phase] = round(time.monotonic() - phase_started, 3)
                    self._emit_progress(phase, 1.0, message=finish_message or "complete", done=True)

            elapsed = round(time.monotonic() - started, 3)
            outcome.elapsed_seconds = elapsed
            outcome.phase_timings = dict(phase_timings)
            final_status = ScanStatus.PARTIAL if partial else ScanStatus.COMPLETED
            outcome.status = final_status.value
            stats = self.db.stats(scan_id)
            stats["runtime"] = self._runtime_payload(elapsed, phase_timings)
            self.db.update_scan(
                scan_id,
                status=final_status,
                phase=last_phase,
                stats=stats,
            )
            self._emit_progress("complete", 1.0, message=outcome.status, done=True)
            return outcome
        except Exception as exc:
            stats = self.db.stats(scan_id)
            stats["runtime"] = self._runtime_payload(
                round(time.monotonic() - started, 3), phase_timings, progress=0
            )
            self.db.update_scan(
                scan_id,
                status=ScanStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}"[:2000],
                stats=stats,
            )
            raise

    def _emit_progress(
        self,
        phase: str,
        fraction: float,
        *,
        completed: int = 0,
        total: int = 0,
        message: str = "",
        done: bool = False,
    ) -> None:
        if self.on_progress is None:
            return
        try:
            self.on_progress(
                ProgressUpdate(
                    phase=phase,
                    fraction=max(0.0, min(1.0, fraction)),
                    completed=completed,
                    total=total,
                    message=message,
                    done=done,
                )
            )
        except Exception:
            self.log.debug("progress callback failed", exc_info=True)

    def _crawl_progress(self, completed: int, total: int) -> None:
        fraction = (completed / total) if total else 0.0
        self._emit_progress(
            "crawl",
            fraction,
            completed=completed,
            total=total,
            message="fetching assets",
        )

    def _analysis_progress(self, completed: int, total: int) -> None:
        fraction = (completed / total) if total else 1.0
        self._emit_progress(
            "analyze",
            fraction,
            completed=completed,
            total=total,
            message="checking registries",
        )

    @staticmethod
    def _runtime_payload(
        elapsed: float,
        phase_timings: dict[str, float],
        *,
        progress: int = 100,
    ) -> dict[str, object]:
        return {
            "duration_seconds": round(elapsed, 3),
            "progress_percent": progress,
            "phase_seconds": {phase: round(seconds, 3) for phase, seconds in phase_timings.items()},
        }

    def _build_limiter(self) -> HostRateLimiter:
        overrides = dict(_REGISTRY_RATE_OVERRIDES)
        from dephunter.core.scope import REGISTRY_HOSTS

        for ecosystem in self.scope.enabled_ecosystems:
            for host in REGISTRY_HOSTS.get(ecosystem, ()):
                overrides.setdefault(host, self.scope.registries.requests_per_second)
        default = self.scope.crawl.requests_per_second if self.scope.web else 2.0
        return HostRateLimiter(default_rps=max(0.1, default), overrides=overrides)

    def _save_stats(self, scan_id: int) -> None:
        self.db.update_scan(scan_id, stats=self.db.stats(scan_id))

    def _normalize_phases(self, phases: Iterable[str] | None) -> set[str]:
        if phases is None:
            selected = {phase for phase in PHASES if phase != "report"}
        else:
            selected = set()
            for phase in phases:
                value = (phase or "").strip().lower()
                if value in {"all", "scan"}:
                    selected.update(PHASES)
                elif value in PHASES:
                    selected.add(value)
                else:
                    raise ValueError(f"unknown phase: {phase}")
        if "report" in selected and "analyze" not in selected:
            selected.add("analyze")
        return selected
