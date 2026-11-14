from __future__ import annotations

import asyncio
import json
from pathlib import Path

from dephunter.analysis.engine import AnalysisEngine
from dephunter.core.models import RegistryStatus
from dephunter.reporting.base import redact, redact_text, write_text
from dephunter.reporting.manager import ReportManager
from dephunter.verification.engine import verify_scan
from tests.conftest import make_fact, make_ref, registry


class FakeManager:
    async def lookup_many(self, pairs, *, progress=None):
        return [
            registry(ecosystem, name, status=RegistryStatus.MISSING, http_status=404)
            for ecosystem, name in pairs
        ]


def _scan_with_finding(db, scope):
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("Demo Program", None, {"authorization": "Authorized test ref"})
    db.add_dependencies(
        scan,
        [
            make_ref(
                "pypi",
                "acme-internal-lib",
                file_path="requirements.txt",
                source_url="https://github.com/acme/app/requirements.txt",
            )
        ],
    )
    db.add_config_facts(
        scan,
        [
            make_fact(
                "pypi",
                "pip_extra_index_url",
                "https://pypi.acme.example/simple",
                file_path="requirements.txt",
            )
        ],
    )
    asyncio.run(AnalysisEngine(db, scope, FakeManager()).analyze(scan))
    db.update_scan(
        scan,
        status="COMPLETED",
        phase="report",
        stats={
            "runtime": {
                "duration_seconds": 12.3,
                "progress_percent": 100,
                "phase_seconds": {"crawl": 1.2, "analyze": 8.0, "report": 0.3},
            }
        },
    )
    return scan


def test_redaction() -> None:
    assert "secret" not in redact_text("token=secret-value")
    assert redact({"nested": ["password=abc", "ok"]}) == {"nested": ["password=[REDACTED]", "ok"]}
    assert redact_text("ghp_abcdefghijklmnop") == "[REDACTED]"


def test_write_text_redacts(tmp_path: Path) -> None:
    path = tmp_path / "out.txt"
    write_text(path, "authorization: Bearer ghp_abcdefghijklmnop")
    assert "ghp_abcdefghijklmnop" not in path.read_text()


def test_reports_and_verification(db, scope, tmp_path: Path) -> None:
    scan = _scan_with_finding(db, scope)
    summary = verify_scan(db, scan)
    assert summary.total == 1
    assert summary.ready == 1
    paths = ReportManager(db).generate(scan, output_dir=tmp_path)
    extensions = {path.suffix for path in paths}
    assert extensions == {".md", ".html", ".json"}
    markdown = paths[0].read_text(encoding="utf-8")
    assert "Potential dependency confusion" in markdown
    assert "Static verification" in markdown and "READY_FOR_REVIEW" in markdown
    assert "Target-side confirmation" in markdown
    assert "## Execution" in markdown
    assert "Run time:" in markdown
    assert "12s" in markdown
    html_report = next(path for path in paths if path.suffix == ".html").read_text()
    assert "Dependency confusion report" in html_report
    assert "100% complete" in html_report
    payload = json.loads(next(path for path in paths if path.suffix == ".json").read_text())
    assert payload["runtime"]["duration_seconds"] == 12.3
    assert payload["progress_percent"] == 100
    assert payload["findings"][0]["verification"]["verdict"] == "READY_FOR_REVIEW"
    assert payload["findings"][0]["evidence"]["registry"]["status"] == "MISSING"
    assert "Authorization" not in json.dumps(payload["findings"][0])


def test_min_classification_report_filter(db, scope, tmp_path: Path) -> None:
    scan = _scan_with_finding(db, scope)
    paths = ReportManager(db).generate(scan, formats=["json"], output_dir=tmp_path, min_classification="CONFIRMED")
    payload = json.loads(paths[0].read_text())
    assert payload["findings"] == []
