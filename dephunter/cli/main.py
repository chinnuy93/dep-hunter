from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Sequence

from dephunter import __version__
from dephunter.cli.progress import ProgressRenderer
from dephunter.cli.theme import banner, configure, theme
from dephunter.core.config import Settings, load_settings
from dephunter.core.errors import ConfigError, ScopeViolation
from dephunter.core.logging import setup_logging
from dephunter.core.pipeline import PHASES, ScanPipeline
from dephunter.core.scope import load_scope
from dephunter.core.util import format_duration
from dephunter.database.db import Database
from dephunter.reporting.manager import ReportManager
from dephunter.setup.manager import (
    SetupError,
    doctor,
    setup_environment,
    update_environment,
)

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-hunter",
        description="Passive dependency-confusion discovery for authorized security research.",
    )
    parser.add_argument("--version", action="version", version=f"dep-hunter {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run a scan from a scope file")
    scan.add_argument("scope", help="path to the scope YAML file")
    scan.add_argument("--scan-id", type=int, help="resume an existing scan")
    scan.add_argument(
        "--phase",
        action="append",
        choices=[*PHASES, "all"],
        help="run only the selected phase (repeatable); default includes report",
    )
    scan.add_argument("--no-report", action="store_true", help="skip report generation")
    scan.add_argument("--format", action="append", dest="formats", help="report format: md, html, json")
    scan.add_argument("--output-dir", help="report output directory")
    _settings_args(scan)
    _logging_args(scan)

    analyze = subparsers.add_parser("analyze", help="re-run analysis for an existing scan")
    analyze.add_argument("scope", help="path to the scope YAML file")
    analyze.add_argument("--scan-id", type=int, required=True)
    analyze.add_argument("--report", action="store_true", help="also generate reports")
    analyze.add_argument("--format", action="append", dest="formats")
    analyze.add_argument("--output-dir")
    _settings_args(analyze)
    _logging_args(analyze)

    report = subparsers.add_parser("report", help="render reports from stored scan data")
    report.add_argument("--scan-id", type=int, required=True)
    report.add_argument("--format", action="append", dest="formats", help="md, html, json (repeatable)")
    report.add_argument("--output-dir")
    report.add_argument("--min-classification", choices=["CANDIDATE", "HIGH_CONFIDENCE", "CONFIRMED"])
    _settings_args(report)
    _logging_args(report)

    scans = subparsers.add_parser("scans", help="list recent scans")
    scans.add_argument("--limit", type=int, default=20)
    scans.add_argument("--json", action="store_true")
    _settings_args(scans)
    _logging_args(scans)

    show = subparsers.add_parser("show", help="show one scan and its findings")
    show.add_argument("--scan-id", type=int, required=True)
    show.add_argument("--json", action="store_true")
    _settings_args(show)
    _logging_args(show)

    doctor_parser = subparsers.add_parser("doctor", help="check the local environment")
    doctor_parser.add_argument("--json", action="store_true")
    _settings_args(doctor_parser)
    _logging_args(doctor_parser)

    setup = subparsers.add_parser("setup", help="create a virtual environment and install Dep-Hunter")
    setup.add_argument("--yes", action="store_true", help="do not prompt")
    setup.add_argument("--dev", action="store_true", help="install test dependencies")
    setup.add_argument("--venv", help="virtual environment path")
    _settings_args(setup)
    _logging_args(setup)

    update = subparsers.add_parser("update", help="upgrade the virtual-environment installation")
    update.add_argument("--yes", action="store_true")
    update.add_argument("--git", action="store_true", help="also run git pull --ff-only")
    update.add_argument("--venv", help="virtual environment path")
    _settings_args(update)
    _logging_args(update)

    return parser


def _settings_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to config.toml")
    parser.add_argument("--data-dir", help="override data directory")
    parser.add_argument("--reports-dir", help="override reports directory")
    parser.add_argument("--contact", help="contact string for the HTTP user agent")
    parser.add_argument("--github-token", help="GitHub API token (not persisted)")
    parser.add_argument("--gitlab-token", help="GitLab API token (not persisted)")


def _logging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default=None)
    parser.add_argument("--log-json", action="store_true")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours and the banner palette")


def _load(args: argparse.Namespace) -> Settings:
    return load_settings(
        Path(args.config).expanduser() if args.config else None,
        data_dir=Path(args.data_dir).expanduser() if args.data_dir else None,
        reports_dir=Path(args.reports_dir).expanduser() if args.reports_dir else None,
        github_token=args.github_token,
        user_agent_contact=args.contact,
        log_level=args.log_level,
        log_json=args.log_json,
    )


def _configure_logging(settings: Settings) -> None:
    setup_logging(settings.log_level, settings.log_json, settings.log_file)


def _formats(values: Sequence[str] | None, default: Sequence[str]) -> list[str]:
    if not values:
        return list(default)
    formats: list[str] = []
    for value in values:
        for item in str(value).split(","):
            item = item.strip().lower()
            if item and item not in formats:
                formats.append(item)
    return formats or list(default)


def _confirm(assume_yes: bool):
    def confirm(prompt: str) -> bool:
        print(prompt)
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            print("Non-interactive session: re-run with --yes to proceed.", file=sys.stderr)
            return False
        answer = input("Proceed? [y/N] ").strip().lower()
        return answer in {"y", "yes"}

    return confirm


def _scan_phases(args: argparse.Namespace) -> list[str]:
    if not args.phase:
        selected = {phase for phase in PHASES if phase != "report"}
        if not args.no_report:
            selected.add("report")
        return [phase for phase in PHASES if phase in selected]
    selected: set[str] = set()
    for raw in args.phase:
        value = (raw or "").strip().lower()
        if value in {"all", "scan"}:
            selected.update(PHASES)
        elif value in PHASES:
            selected.add(value)
        else:
            raise ValueError(f"unknown phase: {raw}")
    if args.no_report:
        selected.discard("report")
    if "report" in selected:
        selected.add("analyze")
    return [phase for phase in PHASES if phase in selected]


def _show_banner() -> None:
    print(banner(__version__), file=sys.stderr)


def _print_outcome(outcome: Any) -> None:
    print()
    print(
        f"{theme.paint(f'Scan #{outcome.scan_id}', 'bold')}  "
        f"{theme.status(outcome.status)}  "
        f"{theme.paint('· ' + format_duration(outcome.elapsed_seconds), 'dim')}"
    )
    print(f"  {theme.paint('progress    ', 'dim')} {theme.paint('100%', 'green', 'bold')}")
    if outcome.analysis:
        analysis = outcome.analysis
        print(
            f"  {theme.paint('dependencies', 'dim')} {analysis.dependencies}   "
            f"{theme.paint('queried', 'dim')} {analysis.queried}   "
            f"{theme.paint('findings', 'dim')} {theme.paint(analysis.findings, 'yellow', 'bold')}   "
            f"{theme.paint('skipped_by_limit', 'dim')} {analysis.skipped_by_limit}"
        )
    if outcome.crawl:
        print(
            f"  {theme.paint('crawl       ', 'dim')} fetched={outcome.crawl.fetched} "
            f"parsed={outcome.crawl.parsed} errors={outcome.crawl.errors}"
        )
    for label, harvest in (("github", outcome.github), ("gitlab", outcome.gitlab)):
        if harvest:
            print(
                f"  {theme.paint(f'{label:<12}', 'dim')} repos={harvest.repos} files={harvest.files} "
                f"parsed={harvest.parsed} errors={harvest.errors}"
            )
    for note in outcome.notes:
        print(f"  {theme.paint('note', 'yellow')} {note}")
    for path in outcome.reports:
        print(f"  {theme.paint('report      ', 'dim')} {theme.paint(path, 'cyan')}")


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _load(args)
    _configure_logging(settings)
    scope = load_scope(args.scope)
    scope.validate_for_scan()
    settings.ensure_dirs()
    phases = _scan_phases(args)
    _show_banner()
    renderer = ProgressRenderer(phases)
    db = Database(settings.db_path)
    try:
        pipeline = ScanPipeline(settings, scope, db, on_progress=renderer.update)
        try:
            outcome = asyncio.run(
                pipeline.run(
                    args.scan_id,
                    phases=phases,
                    report_formats=_formats(args.formats, ("md", "html", "json")),
                    output_dir=args.output_dir or settings.reports_dir,
                )
            )
        except Exception:
            renderer.finish("FAILED")
            raise
        renderer.finish(outcome.status, outcome.elapsed_seconds)
        _print_outcome(outcome)
        return 0
    finally:
        db.close()


def cmd_analyze(args: argparse.Namespace) -> int:
    settings = _load(args)
    _configure_logging(settings)
    scope = load_scope(args.scope)
    scope.validate_for_scan()
    settings.ensure_dirs()
    phases = ["analyze"]
    if args.report:
        phases.append("report")
    _show_banner()
    renderer = ProgressRenderer(phases)
    db = Database(settings.db_path)
    try:
        pipeline = ScanPipeline(settings, scope, db, on_progress=renderer.update)
        try:
            outcome = asyncio.run(
                pipeline.run(
                    args.scan_id,
                    phases=phases,
                    report_formats=_formats(args.formats, ("md", "html", "json")),
                    output_dir=args.output_dir or settings.reports_dir,
                )
            )
        except Exception:
            renderer.finish("FAILED")
            raise
        renderer.finish(outcome.status, outcome.elapsed_seconds)
        _print_outcome(outcome)
        return 0
    finally:
        db.close()


def cmd_report(args: argparse.Namespace) -> int:
    settings = _load(args)
    _configure_logging(settings)
    settings.ensure_dirs()
    _show_banner()
    db = Database(settings.db_path)
    try:
        paths = ReportManager(db).generate(
            args.scan_id,
            formats=_formats(args.formats, ("md", "html", "json")),
            output_dir=args.output_dir or settings.reports_dir,
            min_classification=args.min_classification,
        )
        for path in paths:
            print(theme.paint(path, "cyan"))
        return 0
    finally:
        db.close()


def cmd_scans(args: argparse.Namespace) -> int:
    settings = _load(args)
    db = Database(settings.db_path)
    try:
        rows = db.list_scans(limit=max(1, args.limit))
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        if not rows:
            print("No scans.")
            return 0
        print(
            theme.paint(
                f"{'ID':>5}  {'STATUS':<10} {'PHASE':<9} {'FINDINGS':>8}  PROGRAM",
                "bold",
            )
        )
        for row in rows:
            findings = (row.get("stats", {}).get("findings") or {}).get("total", 0)
            print(
                f"{row['id']:>5}  {theme.status(row['status'], 10)} {row['phase']:<9} "
                f"{findings:>8}  {row['program']}"
            )
        return 0
    finally:
        db.close()


def cmd_show(args: argparse.Namespace) -> int:
    settings = _load(args)
    db = Database(settings.db_path)
    try:
        scan = db.get_scan(args.scan_id)
        if scan is None:
            print(f"error: scan {args.scan_id} not found", file=sys.stderr)
            return 2
        findings = db.load_findings(args.scan_id)
        payload = {"scan": scan, "stats": db.stats(args.scan_id), "findings": findings}
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
            return 0
        scan_label = f"Scan #{scan['id']}"
        print(f"{theme.paint(scan_label, 'bold')} — {scan['program']}")
        print(f"Status: {theme.status(scan['status'])}  Phase: {theme.paint(scan['phase'], 'magenta')}")
        print(f"Created: {scan['created_at']}  Updated: {scan['updated_at']}")
        runtime = (scan.get("stats") or {}).get("runtime")
        if isinstance(runtime, dict):
            print(
                f"Run time: {format_duration(runtime.get('duration_seconds'))}  "
                f"Progress: {runtime.get('progress_percent', 100)}%"
            )
        if scan.get("error"):
            print(f"Error: {scan['error']}")
        stats = payload["stats"]
        print(
            f"Dependencies: {stats.get('dependencies', 0)}  "
            f"Config facts: {stats.get('config_facts', 0)}  "
            f"Findings: {(stats.get('findings') or {}).get('total', 0)}"
        )
        if findings:
            print()
            print(theme.paint(f"{'CLASS':<20} {'ECO':<9} {'SCORE':>5}  PACKAGE", "bold"))
            for finding in findings:
                print(
                    f"{theme.classification(finding['classification'], 20)} {finding['ecosystem']:<9} "
                    f"{finding['score']:>5}  {finding['name']}"
                )
        return 0
    finally:
        db.close()


def cmd_doctor(args: argparse.Namespace) -> int:
    settings = _load(args)
    report = doctor(settings)
    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print(f"dep-hunter {report.tool_version} on {report.platform}")
        print(f"Python: {report.python_version}")
        print(f"Data:   {report.data_dir} ({'writable' if report.data_dir_writable else 'NOT writable'})")
        print(f"DB:     {report.database_path}")
        for check in report.checks:
            print(f"[{theme.check(check['status'], 4)}] {check['name']}: {check['detail']}")
        print("Optional tools:")
        for tool in report.tools:
            state = tool.version if tool.found else tool.note
            print(f"  {tool.name:<8} {state}")
        print(theme.paint("healthy", "green", "bold") if report.healthy else theme.paint("unhealthy", "red", "bold"))
    return 0 if report.healthy else 1


def cmd_setup(args: argparse.Namespace) -> int:
    settings = _load(args)
    _configure_logging(settings)
    report = setup_environment(
        settings,
        venv_path=Path(args.venv).expanduser() if args.venv else None,
        install_dev=args.dev,
        confirm=_confirm(args.yes),
        logger=lambda message: print(f"=> {message}"),
    )
    for action in report.actions:
        state = "ok" if action.get("returncode") == 0 else "failed"
        print(f"[{theme.paint(state, 'green' if state == 'ok' else 'red')}] {action.get('label')}")
    if not report.ok:
        print(f"error: {report.error}", file=sys.stderr)
        return 1
    print(f"Installed into {report.venv_path}")
    print(f"Activate with: source {report.venv_path}/bin/activate")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    settings = _load(args)
    _configure_logging(settings)
    report = update_environment(
        settings,
        venv_path=Path(args.venv).expanduser() if args.venv else None,
        pull_git=args.git,
        confirm=_confirm(args.yes),
        logger=lambda message: print(f"=> {message}"),
    )
    for action in report.actions:
        state = "ok" if action.get("returncode") == 0 else "failed"
        print(f"[{theme.paint(state, 'green' if state == 'ok' else 'red')}] {action.get('label')}")
    if not report.ok:
        print(f"error: {report.error}", file=sys.stderr)
        return 1
    print("Update complete.")
    return 0


COMMANDS = {
    "scan": cmd_scan,
    "analyze": cmd_analyze,
    "report": cmd_report,
    "scans": cmd_scans,
    "show": cmd_show,
    "doctor": cmd_doctor,
    "setup": cmd_setup,
    "update": cmd_update,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure(no_color=bool(getattr(args, "no_color", False)))
    handler = COMMANDS[args.command]
    try:
        return handler(args)
    except (ConfigError, ScopeViolation, SetupError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.getLogger(__name__).exception("command failed")
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
