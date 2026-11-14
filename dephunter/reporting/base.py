from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dephunter import __version__
from dephunter.core.models import CONFIDENCE_ORDER, Confidence
from dephunter.core.util import utc_iso
from dephunter.database.db import Database
from dephunter.verification.engine import FindingVerification, verify_scan

_SECRET_PATTERNS = [
    re.compile(r"(?i)((?:authorization|token|secret|password|apikey|api_key|_auth)\s*[:=]\s*)(\S+)"),
    re.compile(r"(?i)\b(?:ghp_|gho_|glpat-|npm_|pypi-|AKIA)[A-Za-z0-9_\-]{8,}\b"),
]


def redact_text(value: str) -> str:
    text = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    return value


@dataclass(slots=True)
class ReportContext:
    scan: dict[str, Any]
    findings: list[dict[str, Any]]
    stats: dict[str, Any]
    generated_at: str
    tool_version: str = __version__
    verifications: dict[str, FindingVerification] = field(default_factory=dict)

    @property
    def program(self) -> str:
        return str(self.scan.get("program") or "unknown program")

    @property
    def scan_id(self) -> int:
        return int(self.scan.get("id") or 0)

    def verification_for(self, finding: dict[str, Any]) -> FindingVerification | None:
        key = f"{finding.get('ecosystem')}:{finding.get('normalized') or finding.get('name')}"
        return self.verifications.get(key)

    def sorted_findings(self) -> list[dict[str, Any]]:
        return sorted(
            self.findings,
            key=lambda item: (
                CONFIDENCE_ORDER.get(str(item.get("classification")), -1),
                int(item.get("score") or 0),
            ),
            reverse=True,
        )

    def confidence_counts(self) -> dict[str, int]:
        counts = {confidence.value: 0 for confidence in Confidence}
        for finding in self.findings:
            classification = str(finding.get("classification"))
            if classification in counts:
                counts[classification] += 1
        return counts

    def verification_counts(self) -> dict[str, int]:
        counts = {"READY_FOR_REVIEW": 0, "NEEDS_REVIEW": 0, "INVALID": 0}
        for verification in self.verifications.values():
            if verification.verdict in counts:
                counts[verification.verdict] += 1
        return counts

    @property
    def runtime(self) -> dict[str, Any]:
        value = self.stats.get("runtime")
        return value if isinstance(value, dict) else {}

    @property
    def phase_seconds(self) -> dict[str, float]:
        value = self.runtime.get("phase_seconds")
        return {str(key): float(seconds) for key, seconds in value.items()} if isinstance(value, dict) else {}

    @property
    def progress_percent(self) -> int:
        value = self.runtime.get("progress_percent")
        if isinstance(value, (int, float)):
            return max(0, min(100, int(value)))
        status = str(self.scan.get("status") or "")
        return 100 if status in {"COMPLETED", "PARTIAL"} else 0


def build_context(db: Database, scan_id: int, *, min_classification: str | None = None) -> ReportContext:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise KeyError(f"scan {scan_id} not found")
    findings = db.load_findings(scan_id, min_classification=min_classification)
    summary = verify_scan(db, scan_id)
    verifications = {item.finding_key: item for item in summary.results}
    stats = db.stats(scan_id)
    persisted = scan.get("stats") if isinstance(scan.get("stats"), dict) else {}
    if isinstance(persisted.get("runtime"), dict):
        stats["runtime"] = persisted["runtime"]
    return ReportContext(
        scan=scan,
        findings=findings,
        stats=stats,
        generated_at=utc_iso(),
        verifications=verifications,
    )


def slugify(value: str, fallback: str = "scan") -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-._").lower()
    return text[:60] or fallback


def report_basename(context: ReportContext) -> str:
    timestamp = context.generated_at.replace(":", "").replace("-", "").split(".")[0]
    return f"dep-hunter-{slugify(context.program)}-{context.scan_id}-{timestamp}"


def md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def display_ref_location(ref: dict[str, Any]) -> str:
    file_path = ref.get("file_path") or ""
    line = ref.get("line")
    if file_path and line:
        return f"{file_path}:{line}"
    if file_path:
        return str(file_path)
    url = urlparse(str(ref.get("source_url") or ""))
    return url.path or str(ref.get("source_url") or "")


def to_jsonable(value: Any) -> Any:
    return json.loads(json.dumps(redact(value), default=str))


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_text(content), encoding="utf-8")
