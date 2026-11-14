from __future__ import annotations

import argparse
import io

from dephunter.cli.main import _scan_phases
from dephunter.cli.progress import ProgressRenderer
from dephunter.core.progress import ProgressUpdate
from dephunter.core.util import format_duration


def _args(phase=None, no_report=False) -> argparse.Namespace:
    return argparse.Namespace(phase=phase, no_report=no_report)


def test_default_phases_include_report() -> None:
    assert _scan_phases(_args()) == ["crawl", "github", "gitlab", "analyze", "report"]


def test_no_report_removes_report_from_default_phases() -> None:
    assert _scan_phases(_args(no_report=True)) == ["crawl", "github", "gitlab", "analyze"]


def test_all_phase_respects_no_report() -> None:
    assert "report" not in _scan_phases(_args(["all"], no_report=True))
    assert "report" in _scan_phases(_args(["all"]))


def test_report_adds_analysis() -> None:
    phases = _scan_phases(_args(["report"]))
    assert phases == ["analyze", "report"]


def test_format_duration() -> None:
    assert format_duration(0) == "0s"
    assert format_duration(12.4) == "12s"
    assert format_duration(65) == "1m 05s"
    assert format_duration(3661) == "1h 01m 01s"


def test_progress_renderer_tracks_percentage() -> None:
    stream = io.StringIO()
    renderer = ProgressRenderer(["crawl", "analyze"], stream=stream)
    renderer.update(ProgressUpdate("crawl", 0.0, message="starting"))
    renderer.update(ProgressUpdate("crawl", 0.5, completed=5, total=10))
    renderer.update(ProgressUpdate("crawl", 1.0, done=True))
    renderer.update(ProgressUpdate("analyze", 0.5, completed=5, total=10))
    renderer.finish("COMPLETED")
    assert renderer.percent == 71
    assert "COMPLETED" in stream.getvalue()
    assert "100%" in stream.getvalue()
