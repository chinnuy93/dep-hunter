from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from dephunter import __version__
from dephunter.core.config import Settings


class SetupError(RuntimeError):
    pass


@dataclass(slots=True)
class ToolInfo:
    name: str
    command: str
    required: bool = False
    found: bool = False
    version: str = ""
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "required": self.required,
            "found": self.found,
            "version": self.version,
            "note": self.note,
        }


@dataclass(slots=True)
class DoctorReport:
    healthy: bool
    tool_version: str
    python_version: str
    platform: str
    data_dir: str
    data_dir_writable: bool
    reports_dir: str
    reports_dir_writable: bool
    database_path: str
    runtime_dependencies: dict[str, str]
    tools: list[ToolInfo] = field(default_factory=list)
    checks: list[dict[str, str]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "tool_version": self.tool_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "data_dir": self.data_dir,
            "data_dir_writable": self.data_dir_writable,
            "reports_dir": self.reports_dir,
            "reports_dir_writable": self.reports_dir_writable,
            "database_path": self.database_path,
            "runtime_dependencies": self.runtime_dependencies,
            "tools": [tool.to_json() for tool in self.tools],
            "checks": self.checks,
        }


@dataclass(slots=True)
class SetupAction:
    label: str
    command: list[str]


@dataclass(slots=True)
class SetupReport:
    ok: bool
    venv_path: str
    python: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "venv_path": self.venv_path,
            "python": self.python,
            "actions": self.actions,
            "error": self.error,
        }


_TOOL_COMMANDS: list[tuple[str, str, bool]] = [
    ("git", "git", False),
    ("node", "node", False),
    ("npm", "npm", False),
    ("java", "java", False),
    ("ruby", "ruby", False),
    ("cargo", "cargo", False),
    ("go", "go", False),
    ("dotnet", "dotnet", False),
    ("docker", "docker", False),
]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _version_command(tool: str) -> list[str]:
    if tool == "go":
        return ["go", "version"]
    if tool == "java":
        return ["java", "-version"]
    if tool == "dotnet":
        return ["dotnet", "--version"]
    return [tool, "--version"]


def _detect_tool(name: str, command: str, required: bool) -> ToolInfo:
    path = shutil.which(command)
    if not path:
        return ToolInfo(name=name, command=command, required=required, note="not found on PATH")
    try:
        proc = subprocess.run(
            _version_command(command),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolInfo(name=name, command=command, required=required, found=True, note=str(exc)[:200])
    output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    version = output.splitlines()[0][:160] if output else ""
    return ToolInfo(
        name=name,
        command=command,
        required=required,
        found=True,
        version=version,
        note="" if proc.returncode == 0 else "version command failed",
    )


def detect_tools() -> list[ToolInfo]:
    return [_detect_tool(name, command, required) for name, command, required in _TOOL_COMMANDS]


def _writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".dep-hunter-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def doctor(settings: Settings) -> DoctorReport:
    checks: list[dict[str, str]] = []
    python_ok = sys.version_info >= (3, 11)
    checks.append(
        {
            "name": "python_version",
            "status": "PASS" if python_ok else "FAIL",
            "detail": platform.python_version(),
        }
    )
    runtime: dict[str, str] = {}
    try:
        import aiohttp

        runtime["aiohttp"] = aiohttp.__version__
        checks.append({"name": "aiohttp", "status": "PASS", "detail": aiohttp.__version__})
    except Exception as exc:
        runtime["aiohttp"] = "missing"
        checks.append({"name": "aiohttp", "status": "FAIL", "detail": str(exc)[:200]})
    try:
        import yaml

        runtime["PyYAML"] = yaml.__version__
        checks.append({"name": "PyYAML", "status": "PASS", "detail": yaml.__version__})
    except Exception as exc:
        runtime["PyYAML"] = "missing"
        checks.append({"name": "PyYAML", "status": "FAIL", "detail": str(exc)[:200]})

    data_writable = _writable_dir(settings.data_dir)
    reports_writable = _writable_dir(settings.reports_dir)
    checks.append(
        {
            "name": "data_dir_writable",
            "status": "PASS" if data_writable else "FAIL",
            "detail": str(settings.data_dir),
        }
    )
    checks.append(
        {
            "name": "reports_dir_writable",
            "status": "PASS" if reports_writable else "FAIL",
            "detail": str(settings.reports_dir),
        }
    )
    if settings.config_path:
        checks.append(
            {
                "name": "config_file",
                "status": "PASS",
                "detail": str(settings.config_path),
            }
        )
    tools = detect_tools()
    healthy = python_ok and runtime.get("aiohttp") != "missing" and runtime.get("PyYAML") != "missing"
    healthy = healthy and data_writable and reports_writable
    return DoctorReport(
        healthy=healthy,
        tool_version=__version__,
        python_version=platform.python_version(),
        platform=platform.platform(),
        data_dir=str(settings.data_dir),
        data_dir_writable=data_writable,
        reports_dir=str(settings.reports_dir),
        reports_dir_writable=reports_writable,
        database_path=str(settings.db_path),
        runtime_dependencies=runtime,
        tools=tools,
        checks=checks,
    )


def _venv_python(venv_path: Path) -> Path:
    if os.name == "nt":
        return venv_path / "Scripts" / "python.exe"
    return venv_path / "bin" / "python"


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupError(f"command failed to start: {' '.join(command)}: {exc}") from exc
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-4000:],
        "stderr": (proc.stderr or "")[-4000:],
    }


def setup_environment(
    settings: Settings,
    *,
    venv_path: Path | None = None,
    install_dev: bool = False,
    confirm: Callable[[str], bool] | None = None,
    logger: Callable[[str], None] | None = None,
) -> SetupReport:
    root = project_root()
    if not (root / "pyproject.toml").exists():
        raise SetupError(f"pyproject.toml not found in project root {root}")
    venv = (venv_path or root / ".venv").expanduser().resolve()
    python = _venv_python(venv)
    actions: list[SetupAction] = []
    if not python.exists():
        actions.append(SetupAction("Create virtual environment", [sys.executable, "-m", "venv", str(venv)]))
    actions.append(SetupAction("Install Dep-Hunter", [str(python), "-m", "pip", "install", "-e", str(root)]))
    if install_dev:
        actions.append(
            SetupAction(
                "Install development dependencies",
                [str(python), "-m", "pip", "install", "-e", f"{root}[dev]"],
            )
        )
    actions.append(SetupAction("Verify installed dependencies", [str(python), "-m", "pip", "check"]))
    plan = "\n".join(f"  - {action.label}: {' '.join(action.command)}" for action in actions)
    if confirm is not None and not confirm(f"Dep-Hunter setup will run:\n{plan}\nProceed?"):
        raise SetupError("setup cancelled by user")
    report = SetupReport(ok=False, venv_path=str(venv), python=str(python))
    for action in actions:
        if action.label.startswith("Create"):
            venv.parent.mkdir(parents=True, exist_ok=True)
        if logger:
            logger(action.label)
        result = _run(action.command, cwd=root)
        report.actions.append({"label": action.label, **result})
        if result["returncode"] != 0:
            report.error = result["stderr"] or result["stdout"] or f"exit {result['returncode']}"
            _write_report(settings, report)
            return report
    report.ok = True
    _write_report(settings, report)
    return report


def update_environment(
    settings: Settings,
    *,
    venv_path: Path | None = None,
    pull_git: bool = False,
    confirm: Callable[[str], bool] | None = None,
    logger: Callable[[str], None] | None = None,
) -> SetupReport:
    root = project_root()
    venv = (venv_path or root / ".venv").expanduser().resolve()
    python = _venv_python(venv)
    if not python.exists():
        raise SetupError(f"virtual environment not found at {venv}; run setup first")
    actions: list[SetupAction] = []
    if pull_git:
        actions.append(SetupAction("Update source checkout", ["git", "-C", str(root), "pull", "--ff-only"]))
    actions.extend(
        [
            SetupAction("Upgrade package installation", [str(python), "-m", "pip", "install", "--upgrade", "-e", str(root)]),
            SetupAction("Verify installed dependencies", [str(python), "-m", "pip", "check"]),
        ]
    )
    plan = "\n".join(f"  - {action.label}: {' '.join(action.command)}" for action in actions)
    if confirm is not None and not confirm(f"Dep-Hunter update will run:\n{plan}\nProceed?"):
        raise SetupError("update cancelled by user")
    report = SetupReport(ok=False, venv_path=str(venv), python=str(python))
    for action in actions:
        if logger:
            logger(action.label)
        result = _run(action.command, cwd=root)
        report.actions.append({"label": action.label, **result})
        if result["returncode"] != 0:
            report.error = result["stderr"] or result["stdout"] or f"exit {result['returncode']}"
            _write_report(settings, report)
            return report
    report.ok = True
    _write_report(settings, report)
    return report


def _write_report(settings: Settings, report: SetupReport) -> None:
    try:
        settings.ensure_dirs()
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_version": __version__,
            **report.to_json(),
        }
        (settings.data_dir / "setup-report.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
