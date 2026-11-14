from __future__ import annotations

import logging
from dataclasses import dataclass

from dephunter.core.evidence import EvidenceStore
from dephunter.core.util import sha256_bytes
from dephunter.database.db import Database
from dephunter.extractors import extract, find_extractor
from dephunter.extractors.base import ExtractContext

log = logging.getLogger(__name__)

_EXCLUDED_DIRS = {
    ".git", "node_modules", "bower_components", "vendor", "third_party", "site-packages",
    ".venv", "venv", "env", ".tox", ".nox", "__pycache__", ".mypy_cache", ".pytest_cache",
    "dist", "build", "target", "coverage", ".gradle", ".m2", "pods", ".bundle",
    "tmp", "temp", ".terraform", "obj", "bin",
}
_HISTORY_SKIP_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pipfile.lock", "poetry.lock", "uv.lock", "composer.lock", "cargo.lock",
    "gemfile.lock", "packages.lock.json", "gradle.lockfile", "go.sum", "mix.lock",
}


def is_repo_manifest(path: str) -> bool:
    parts = [part.lower() for part in path.strip("/").split("/")[:-1]]
    if any(part in _EXCLUDED_DIRS for part in parts):
        return False
    extractor = find_extractor(path)
    if extractor is None:
        return False
    if extractor.role == "js":
        return False
    return True


def history_worthy(path: str) -> bool:
    from pathlib import PurePosixPath

    name = PurePosixPath(path).name.lower()
    if name in _HISTORY_SKIP_NAMES or name.endswith(".lock"):
        return False
    return True


@dataclass(slots=True)
class RepoProcessResult:
    status: str
    dependencies: int = 0
    config_facts: int = 0
    warnings: int = 0


class RepoExtractor:
    """Shared extraction path for fetched repository files."""

    def __init__(
        self,
        db: Database,
        scan_id: int,
        *,
        evidence: EvidenceStore | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.db = db
        self.scan_id = scan_id
        self.evidence = evidence
        self.log = logger or log
        self.seen_hashes: set[str] = set()

    def process(
        self,
        *,
        source: str,
        repo: str,
        path: str,
        ref: str,
        source_url: str,
        commit: str | None,
        content: bytes,
    ) -> RepoProcessResult:
        if self.db.has_repo_file(self.scan_id, repo, path, ref):
            return RepoProcessResult(status="EXISTS")
        digest = sha256_bytes(content)
        if digest in self.seen_hashes:
            self.db.add_repo_file(
                self.scan_id,
                source,
                repo,
                path,
                ref,
                source_url,
                commit=commit,
                sha256=digest,
                status="SKIPPED",
                error="duplicate content already extracted",
            )
            return RepoProcessResult(status="DEDUPED")
        ctx = ExtractContext(
            origin=source,
            source_url=source_url,
            file_path=path,
            commit=commit,
            repo=repo,
        )
        extraction = extract(path, content, ctx)
        deps_added = self.db.add_dependencies(self.scan_id, extraction.dependencies)
        facts_added = self.db.add_config_facts(self.scan_id, extraction.config_facts)
        inserted = self.db.add_repo_file(
            self.scan_id,
            source,
            repo,
            path,
            ref,
            source_url,
            commit=commit,
            sha256=digest,
            status="PARSED",
        )
        if inserted:
            self.seen_hashes.add(digest)
            if self.evidence is not None:
                try:
                    self.evidence.store(content)
                except OSError:
                    self.log.debug("could not store repository evidence for %s", path)
        for warning in extraction.warnings[:5]:
            self.log.debug("extractor warning for %s/%s: %s", repo, path, warning)
        return RepoProcessResult(
            status="PARSED",
            dependencies=deps_added,
            config_facts=facts_added,
            warnings=len(extraction.warnings),
        )
