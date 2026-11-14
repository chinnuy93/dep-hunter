from __future__ import annotations

import base64
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

GITHUB_API = "https://api.github.com"
HISTORY_FILE_CAP = 10


class GitHubHarvester:
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
        self.default_budget = request_budget if request_budget is not None else (1200 if token else 50)
        self.budget = self.default_budget
        self.max_file_bytes = max_file_bytes
        self.log = logger or log
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def harvest(self, scan_id: int) -> HarvestResult:
        result = HarvestResult()
        if not self.scope.github.enabled:
            return result
        self.budget = self.default_budget
        repos = await self._collect_repos(result)
        extractor = RepoExtractor(self.db, scan_id, evidence=self.evidence, logger=self.log)
        for repo in repos:
            if result.rate_limited or self.budget <= 0:
                if self.budget <= 0:
                    result.budget_exhausted = True
                    result.note("GitHub request budget exhausted")
                break
            await self._harvest_repo(scan_id, repo, extractor, result)
            result.repos += 1
        if result.rate_limited:
            result.note("GitHub API rate limit or authentication failure; harvest stopped")
        return result

    async def _collect_repos(self, result: HarvestResult) -> list[dict[str, Any]]:
        collected: dict[str, dict[str, Any]] = {}
        max_repos = max(0, self.scope.github.max_repos)
        for org in self.scope.github.orgs:
            page = 1
            while len(collected) < max_repos and page <= 20:
                url = (
                    f"{GITHUB_API}/orgs/{quote(org, safe='')}/repos"
                    f"?type=public&per_page=100&page={page}&sort=updated"
                )
                status, data = await self._get_json(url, result)
                if status != 200 or not isinstance(data, list):
                    if status not in {None, 404}:
                        result.note(f"cannot list repositories for org {org} (HTTP {status})")
                    break
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    repo = self._repo_entry(entry)
                    if repo is None:
                        continue
                    collected.setdefault(repo["full_name"].lower(), repo)
                    if len(collected) >= max_repos:
                        break
                if len(data) < 100:
                    break
                page += 1

        for full_name in self.scope.github.repos:
            if len(collected) >= max_repos:
                break
            if full_name.lower() in collected:
                continue
            if not self.policy.github_repo_allowed(full_name):
                continue
            status, data = await self._get_json(
                f"{GITHUB_API}/repos/{quote(full_name, safe='/')}", result
            )
            if status == 200 and isinstance(data, dict):
                repo = self._repo_entry(data)
                if repo is not None:
                    collected[repo["full_name"].lower()] = repo
            elif status not in {None, 404}:
                result.note(f"cannot read repository metadata for {full_name} (HTTP {status})")
        return list(collected.values())

    def _repo_entry(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        full_name = entry.get("full_name")
        if not isinstance(full_name, str) or "/" not in full_name:
            return None
        if entry.get("private") or entry.get("disabled"):
            return None
        if entry.get("fork") and not self.scope.github.include_forks:
            return None
        if entry.get("archived") and not self.scope.github.include_archived:
            return None
        if not self.policy.github_repo_allowed(full_name):
            return None
        branch = entry.get("default_branch")
        return {
            "full_name": full_name,
            "default_branch": branch if isinstance(branch, str) and branch else "main",
        }

    async def _harvest_repo(
        self,
        scan_id: int,
        repo: dict[str, Any],
        extractor: RepoExtractor,
        result: HarvestResult,
    ) -> None:
        full_name = repo["full_name"]
        branch = repo["default_branch"]
        head_commit = await self._head_commit(full_name, branch, result)
        paths = await self._manifest_paths(full_name, branch, result)
        cap = max(0, self.scope.github.max_files_per_repo)
        if len(paths) > cap:
            result.note(f"{full_name}: manifest file cap reached ({cap})")
            paths = paths[:cap]

        for path in paths:
            if result.rate_limited or self.budget <= 0:
                break
            if self.db.has_repo_file(scan_id, full_name, path, branch):
                result.skipped += 1
                continue
            content = await self._file_content(full_name, path, branch, result)
            if content is None:
                result.skipped += 1
                continue
            outcome = extractor.process(
                source="github",
                repo=full_name,
                path=path,
                ref=branch,
                source_url=self._blob_url(full_name, head_commit or branch, path),
                commit=head_commit,
                content=content,
            )
            self._apply_outcome(outcome, result)

        if self.scope.github.include_history and not result.rate_limited and self.budget > 0:
            await self._history(scan_id, full_name, branch, head_commit, paths, extractor, result)

    async def _history(
        self,
        scan_id: int,
        full_name: str,
        branch: str,
        head_commit: str | None,
        paths: list[str],
        extractor: RepoExtractor,
        result: HarvestResult,
    ) -> None:
        worthy = [path for path in paths if history_worthy(path)][:HISTORY_FILE_CAP]
        per_file = max(1, min(50, self.scope.github.history_commits_per_file))
        for path in worthy:
            if result.rate_limited or self.budget <= 0:
                break
            url = (
                f"{GITHUB_API}/repos/{quote(full_name, safe='/')}/commits"
                f"?path={quote(path, safe='')}&sha={quote(branch, safe='')}&per_page={per_file}"
            )
            status, data = await self._get_json(url, result)
            if status != 200 or not isinstance(data, list):
                continue
            for entry in data[:per_file]:
                if result.rate_limited or self.budget <= 0:
                    break
                sha = entry.get("sha") if isinstance(entry, dict) else None
                if not isinstance(sha, str) or sha == head_commit:
                    continue
                if self.db.has_repo_file(scan_id, full_name, path, sha):
                    continue
                content = await self._file_content(full_name, path, sha, result)
                if content is None:
                    continue
                outcome = extractor.process(
                    source="github",
                    repo=full_name,
                    path=path,
                    ref=sha,
                    source_url=self._blob_url(full_name, sha, path),
                    commit=sha,
                    content=content,
                )
                self._apply_outcome(outcome, result)

    async def _manifest_paths(self, full_name: str, branch: str, result: HarvestResult) -> list[str]:
        url = (
            f"{GITHUB_API}/repos/{quote(full_name, safe='/')}/git/trees/"
            f"{quote(branch, safe='')}?recursive=1"
        )
        status, data = await self._get_json(url, result, max_bytes=16 * 1024 * 1024)
        if status != 200 or not isinstance(data, dict):
            if status not in {None, 404}:
                result.note(f"{full_name}: cannot read repository tree (HTTP {status})")
            return []
        if data.get("truncated"):
            result.note(f"{full_name}: repository tree truncated by GitHub")
        paths: set[str] = set()
        entries = data.get("tree")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("type") != "blob":
                    continue
                path = entry.get("path")
                size = entry.get("size")
                if not isinstance(path, str):
                    continue
                if isinstance(size, int) and size > self.max_file_bytes:
                    continue
                if is_repo_manifest(path):
                    paths.add(path)
        return sorted(paths)

    async def _head_commit(self, full_name: str, branch: str, result: HarvestResult) -> str | None:
        url = (
            f"{GITHUB_API}/repos/{quote(full_name, safe='/')}/commits"
            f"?sha={quote(branch, safe='')}&per_page=1"
        )
        status, data = await self._get_json(url, result)
        if status == 200 and isinstance(data, list) and data:
            sha = data[0].get("sha") if isinstance(data[0], dict) else None
            return sha if isinstance(sha, str) else None
        return None

    async def _file_content(
        self,
        full_name: str,
        path: str,
        ref: str,
        result: HarvestResult,
    ) -> bytes | None:
        url = (
            f"{GITHUB_API}/repos/{quote(full_name, safe='/')}/contents/"
            f"{quote(path, safe='/')}?ref={quote(ref, safe='')}"
        )
        status, data = await self._get_json(url, result)
        if status != 200 or not isinstance(data, dict):
            return None
        if data.get("type") != "file":
            return None
        content = data.get("content")
        encoding = data.get("encoding")
        if encoding != "base64" or not isinstance(content, str) or not content:
            if data.get("size"):
                result.note(f"{full_name}/{path} exceeds the contents API size limit")
            return None
        try:
            return base64.b64decode(content, validate=False)
        except (ValueError, TypeError):
            result.note(f"{full_name}/{path}: invalid base64 content from GitHub")
            return None

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
                result.note("GitHub authentication failed (HTTP 401)")
            elif response.status not in {404, 403, 429}:
                result.errors += 1
                result.note(f"GitHub API HTTP {response.status} for {url}")
            elif response.status == 403:
                result.errors += 1
            return response.status, None
        try:
            return response.status, json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            result.errors += 1
            result.note(f"invalid JSON from GitHub for {url}")
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
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining is not None and remaining.strip() == "0":
            result.rate_limited = True
        if response.status == 403:
            body = response.text().lower()
            if "rate limit" in body or "secondary rate limit" in body:
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

    def _blob_url(self, repo: str, ref: str, path: str) -> str:
        return f"https://github.com/{repo}/blob/{ref}/{path}"
