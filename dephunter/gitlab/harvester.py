from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

from dephunter.core.errors import NetworkError, ScopeViolation
from dephunter.core.evidence import EvidenceStore
from dephunter.core.http import HttpResponse, SafeHttpClient
from dephunter.core.scope import ScopeConfig, ScopePolicy
from dephunter.database.db import Database
from dephunter.extractors.repo import RepoExtractor, history_worthy, is_repo_manifest
from dephunter.github.base import HarvestResult

log = logging.getLogger(__name__)

GITLAB_API = "https://gitlab.com/api/v4"
HISTORY_FILE_CAP = 10


class GitLabHarvester:
    def __init__(
        self,
        db: Database,
        http: SafeHttpClient,
        policy: ScopePolicy,
        scope: ScopeConfig,
        evidence: EvidenceStore,
        *,
        token: str | None = None,
        request_budget: int | None = None,
        max_file_bytes: int = 2 * 1024 * 1024,
        logger: logging.Logger | None = None,
    ) -> None:
        self.db = db
        self.http = http
        self.policy = policy
        self.scope = scope
        self.evidence = evidence
        self.token = token
        self.default_budget = request_budget if request_budget is not None else (1200 if token else 300)
        self.budget = self.default_budget
        self.max_file_bytes = max_file_bytes
        self.log = logger or log
        self.headers = {"Accept": "application/json"}
        if token:
            self.headers["PRIVATE-TOKEN"] = token

    async def harvest(self, scan_id: int) -> HarvestResult:
        result = HarvestResult()
        if not self.scope.gitlab.enabled:
            return result
        self.budget = self.default_budget
        extractor = RepoExtractor(self.db, scan_id, evidence=self.evidence, logger=self.log)
        for project in self.scope.gitlab.projects:
            if result.rate_limited or self.budget <= 0:
                if self.budget <= 0:
                    result.budget_exhausted = True
                    result.note("GitLab request budget exhausted")
                break
            if not self.policy.gitlab_project_allowed(project):
                continue
            await self._harvest_project(scan_id, project, extractor, result)
            result.repos += 1
        if result.rate_limited:
            result.note("GitLab API rate limit or authentication failure; harvest stopped")
        return result

    async def _project_id(self, project: str) -> str:
        return quote(project.strip("/"), safe="")

    async def _harvest_project(
        self,
        scan_id: int,
        project: str,
        extractor: RepoExtractor,
        result: HarvestResult,
    ) -> None:
        project_id = await self._project_id(project)
        base = f"{GITLAB_API}/projects/{project_id}"
        status, data = await self._get_json(base, result)
        if status != 200 or not isinstance(data, dict):
            result.note(f"{project}: cannot read project metadata (HTTP {status})")
            return
        if data.get("archived"):
            return
        branch = data.get("default_branch")
        if not isinstance(branch, str) or not branch:
            branch = "main"
        head_commit = await self._head_commit(base, branch, result)
        paths = await self._manifest_paths(base, branch, result)
        cap = max(0, self.scope.gitlab.max_files_per_project)
        if len(paths) > cap:
            result.note(f"{project}: manifest file cap reached ({cap})")
            paths = paths[:cap]

        for path in paths:
            if result.rate_limited or self.budget <= 0:
                break
            if self.db.has_repo_file(scan_id, project, path, branch):
                result.skipped += 1
                continue
            content = await self._file_content(base, path, branch, result)
            if content is None:
                result.skipped += 1
                continue
            outcome = extractor.process(
                source="gitlab",
                repo=project,
                path=path,
                ref=branch,
                source_url=self._blob_url(project, head_commit or branch, path),
                commit=head_commit,
                content=content,
            )
            self._apply_outcome(outcome, result)

        if self.scope.gitlab.include_history and not result.rate_limited and self.budget > 0:
            await self._history(scan_id, base, project, branch, head_commit, paths, extractor, result)

    async def _history(
        self,
        scan_id: int,
        base: str,
        project: str,
        branch: str,
        head_commit: str | None,
        paths: list[str],
        extractor: RepoExtractor,
        result: HarvestResult,
    ) -> None:
        worthy = [path for path in paths if history_worthy(path)][:HISTORY_FILE_CAP]
        per_file = max(1, min(50, self.scope.gitlab.history_commits_per_file))
        for path in worthy:
            if result.rate_limited or self.budget <= 0:
                break
            url = (
                f"{base}/repository/commits?path={quote(path, safe='')}"
                f"&ref_name={quote(branch, safe='')}&per_page={per_file}"
            )
            status, data = await self._get_json(url, result)
            if status != 200 or not isinstance(data, list):
                continue
            for entry in data[:per_file]:
                if result.rate_limited or self.budget <= 0:
                    break
                commit = entry.get("id") if isinstance(entry, dict) else None
                if not isinstance(commit, str) or commit == head_commit:
                    continue
                if self.db.has_repo_file(scan_id, project, path, commit):
                    continue
                content = await self._file_content(base, path, commit, result)
                if content is None:
                    continue
                outcome = extractor.process(
                    source="gitlab",
                    repo=project,
                    path=path,
                    ref=commit,
                    source_url=self._blob_url(project, commit, path),
                    commit=commit,
                    content=content,
                )
                self._apply_outcome(outcome, result)

    async def _manifest_paths(self, base: str, branch: str, result: HarvestResult) -> list[str]:
        paths: set[str] = set()
        page = 1
        while page <= 50:
            url = (
                f"{base}/repository/tree?ref={quote(branch, safe='')}"
                f"&recursive=true&per_page=100&page={page}"
            )
            status, data = await self._get_json(url, result, max_bytes=16 * 1024 * 1024)
            if status != 200:
                if status not in {None, 404}:
                    result.note(f"cannot read GitLab tree (HTTP {status})")
                break
            if not isinstance(data, list):
                break
            for entry in data:
                if not isinstance(entry, dict) or entry.get("type") != "blob":
                    continue
                path = entry.get("path")
                if isinstance(path, str) and is_repo_manifest(path):
                    paths.add(path)
            if len(data) < 100:
                break
            page += 1
        return sorted(paths)

    async def _head_commit(self, base: str, branch: str, result: HarvestResult) -> str | None:
        url = f"{base}/repository/commits?ref_name={quote(branch, safe='')}&per_page=1"
        status, data = await self._get_json(url, result)
        if status == 200 and isinstance(data, list) and data:
            commit = data[0].get("id") if isinstance(data[0], dict) else None
            return commit if isinstance(commit, str) else None
        return None

    async def _file_content(
        self,
        base: str,
        path: str,
        ref: str,
        result: HarvestResult,
    ) -> bytes | None:
        url = f"{base}/repository/files/{quote(path, safe='')}/raw?ref={quote(ref, safe='')}"
        if not self._consume(result):
            return None
        try:
            response = await self.http.get(
                url,
                headers={**self.headers, "Accept": "text/plain, */*"},
                max_bytes=self.max_file_bytes,
            )
        except (NetworkError, ScopeViolation) as exc:
            result.errors += 1
            result.note(f"request failed: {exc}")
            return None
        self._check_limits(response, result)
        if response.status != 200:
            if response.status not in {404, 403, 429}:
                result.errors += 1
                result.note(f"GitLab HTTP {response.status} for {path}")
            return None
        if response.truncated and len(response.body) >= self.max_file_bytes:
            return None
        return response.body

    async def _get_json(
        self,
        url: str,
        result: HarvestResult,
        *,
        max_bytes: int = 8 * 1024 * 1024,
    ) -> tuple[int | None, Any]:
        if not self._consume(result):
            return None, None
        try:
            response = await self.http.get(url, headers=self.headers, max_bytes=max_bytes)
        except (NetworkError, ScopeViolation) as exc:
            result.errors += 1
            result.note(f"request failed: {exc}")
            return None, None
        self._check_limits(response, result)
        if response.status != 200:
            if response.status == 401:
                result.rate_limited = True
                result.note("GitLab authentication failed (HTTP 401)")
            elif response.status not in {404, 403, 429}:
                result.errors += 1
                result.note(f"GitLab API HTTP {response.status} for {url}")
            elif response.status == 403:
                result.errors += 1
            return response.status, None
        try:
            return response.status, json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            result.errors += 1
            result.note(f"invalid JSON from GitLab for {url}")
            return response.status, None

    def _consume(self, result: HarvestResult) -> bool:
        if self.budget <= 0:
            result.budget_exhausted = True
            return False
        self.budget -= 1
        result.requests += 1
        return True

    def _check_limits(self, response: HttpResponse, result: HarvestResult) -> None:
        if response.status == 429:
            result.rate_limited = True
        if response.status == 403:
            body = response.text().lower()
            if "rate limit" in body or "too many requests" in body:
                result.rate_limited = True
            if response.headers.get("ratelimit-remaining", "").strip() == "0":
                result.rate_limited = True

    def _apply_outcome(self, outcome: Any, result: HarvestResult) -> None:
        if outcome.status == "PARSED":
            result.files += 1
            result.parsed += 1
            result.dependencies += outcome.dependencies
            result.config_facts += outcome.config_facts
            result.warnings += outcome.warnings
        elif outcome.status in {"DEDUPED", "EXISTS"}:
            result.skipped += 1

    def _blob_url(self, project: str, ref: str, path: str) -> str:
        return f"https://gitlab.com/{project}/-/blob/{ref}/{path}"
