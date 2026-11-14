from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ScanStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class ScanPhase(StrEnum):
    INIT = "init"
    CRAWL = "crawl"
    GITHUB = "github"
    GITLAB = "gitlab"
    ANALYZE = "analyze"
    REPORT = "report"


class RegistryStatus(StrEnum):
    EXISTS = "EXISTS"
    MISSING = "MISSING"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class Confidence(StrEnum):
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CANDIDATE = "CANDIDATE"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    CONFIRMED = "CONFIRMED"


CONFIDENCE_ORDER: dict[str, int] = {
    Confidence.INSUFFICIENT_EVIDENCE: 0,
    Confidence.CANDIDATE: 1,
    Confidence.HIGH_CONFIDENCE: 2,
    Confidence.CONFIRMED: 3,
}


@dataclass(slots=True)
class Artifact:
    source_url: str
    file_path: str | None
    content: bytes
    sha256: str
    content_type: str = ""
    commit: str | None = None
    repo: str | None = None
    source_kind: str = "web"


@dataclass(slots=True)
class DependencyRef:
    ecosystem: str
    name: str
    normalized: str
    version: str | None
    source_kind: str
    source_url: str
    file_path: str | None = None
    line: int | None = None
    commit: str | None = None
    repo: str | None = None
    resolved_url: str | None = None
    explicit_source: bool = False
    direct: bool = True
    groups: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_lockfile(self) -> bool:
        return "lockfile" in self.source_kind or "lock" in self.source_kind

    def dedupe_key(self) -> str:
        import hashlib
        import json

        payload = json.dumps(
            [
                self.ecosystem,
                self.normalized,
                self.version,
                self.source_kind,
                self.source_url,
                self.file_path,
                self.line,
                self.commit,
                self.resolved_url,
                self.explicit_source,
            ],
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(slots=True)
class ConfigFact:
    ecosystem: str
    fact_type: str
    value: str
    source_kind: str
    source_url: str
    file_path: str | None = None
    line: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> str:
        import hashlib

        payload = "\x00".join(
            [
                self.ecosystem,
                self.fact_type,
                self.value,
                self.source_url,
                self.file_path or "",
                str(self.line or ""),
            ]
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(slots=True)
class ExtractionResult:
    dependencies: list[DependencyRef] = field(default_factory=list)
    config_facts: list[ConfigFact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    names_local_to_project: set[str] = field(default_factory=set)


@dataclass(slots=True)
class RegistryResult:
    ecosystem: str
    name: str
    status: RegistryStatus
    exists: bool | None = None
    latest_version: str | None = None
    versions_count: int | None = None
    publisher: str | None = None
    publisher_url: str | None = None
    repository_url: str | None = None
    first_published: str | None = None
    last_published: str | None = None
    url: str | None = None
    http_status: int | None = None
    error: str | None = None
    checked_at: str = ""
    raw_summary: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "status": self.status.value,
            "exists": self.exists,
            "latest_version": self.latest_version,
            "versions_count": self.versions_count,
            "publisher": self.publisher,
            "publisher_url": self.publisher_url,
            "repository_url": self.repository_url,
            "first_published": self.first_published,
            "last_published": self.last_published,
            "url": self.url,
            "http_status": self.http_status,
            "error": self.error,
            "checked_at": self.checked_at,
            "raw_summary": self.raw_summary,
        }


@dataclass(slots=True)
class ResolutionAssessment:
    public_routing: bool | None = None
    private_routing: bool | None = None
    public_resolution_evidence: bool = False
    private_resolution_evidence: bool = False
    mixed_provenance: bool = False
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "public_routing": self.public_routing,
            "private_routing": self.private_routing,
            "public_resolution_evidence": self.public_resolution_evidence,
            "private_resolution_evidence": self.private_resolution_evidence,
            "mixed_provenance": self.mixed_provenance,
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class Assessment:
    ecosystem: str
    name: str
    normalized: str
    classification: Confidence
    score: int
    reasons: list[str]
    missing_evidence: list[str]
    refs: list[DependencyRef]
    facts: list[ConfigFact]
    registry: RegistryResult | None
    resolution: ResolutionAssessment
    intent: bool = False
    publisher_relation: str = "UNKNOWN"
    title: str = ""
    cwe_primary: str = "CWE-427"
    cwe_secondary: str = "CWE-829"


@dataclass(slots=True)
class RepoFileSummary:
    repo: str
    path: str
    ref: str
    source_url: str
    commit: str | None = None
    sha256: str = ""
    kind: str = ""
