from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from dephunter.database.db import Database
from dephunter.reporting import html, json_report, markdown
from dephunter.reporting.base import ReportContext, build_context, report_basename, write_text

log = logging.getLogger(__name__)

FORMATS = {
    "md": ("md", markdown.render),
    "markdown": ("md", markdown.render),
    "html": ("html", html.render),
    "json": ("json", json_report.render),
}


class ReportManager:
    def __init__(self, db: Database, *, logger: logging.Logger | None = None) -> None:
        self.db = db
        self.log = logger or log

    def generate(
        self,
        scan_id: int,
        *,
        formats: Iterable[str] = ("md", "html", "json"),
        output_dir: str | Path = "reports",
        min_classification: str | None = None,
    ) -> list[Path]:
        context = build_context(self.db, scan_id, min_classification=min_classification)
        return self.render(context, formats=formats, output_dir=output_dir)

    def render(
        self,
        context: ReportContext,
        *,
        formats: Iterable[str] = ("md", "html", "json"),
        output_dir: str | Path = "reports",
    ) -> list[Path]:
        directory = Path(output_dir).expanduser()
        basename = report_basename(context)
        written: list[Path] = []
        for requested in formats:
            key = (requested or "").strip().lower()
            entry = FORMATS.get(key)
            if entry is None:
                raise ValueError(f"unknown report format: {requested}")
            extension, renderer = entry
            path = directory / f"{basename}.{extension}"
            write_text(path, renderer(context))
            written.append(path)
        return written
