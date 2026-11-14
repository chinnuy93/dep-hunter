from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dephunter import __version__
from dephunter.core.errors import ConfigError

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "dep-hunter" / "config.toml"
DEFAULT_DATA_DIRNAME = "dep-hunter-data"
DEFAULT_REPORTS_DIRNAME = "reports"
DEFAULT_MAX_BODY = 8 * 1024 * 1024


@dataclass(slots=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path.cwd() / DEFAULT_DATA_DIRNAME)
    reports_dir: Path = field(default_factory=lambda: Path.cwd() / DEFAULT_REPORTS_DIRNAME)
    config_path: Path | None = None
    github_token: str | None = None
    gitlab_token: str | None = None
    user_agent_contact: str = "not-configured"
    http_timeout: float = 20.0
    http_concurrency: int = 8
    registry_concurrency: int = 4
    evidence_max_bytes: int = DEFAULT_MAX_BODY
    log_level: str = "INFO"
    log_json: bool = False
    log_file: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "dep-hunter.sqlite3"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def user_agent(self) -> str:
        return (
            f"dep-hunter/{__version__} "
            f"(passive dependency-confusion research; contact: {self.user_agent_contact})"
        )

    def ensure_dirs(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            self.reports_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError(f"cannot create data directories: {exc}") from exc


def _read_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config {path} must be a TOML table")
    return data


def _coerce_path(value: Any, field_name: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ConfigError(f"config field {field_name} must be a path string")
    return Path(value).expanduser()


def load_settings(
    config_path: Path | None = None,
    *,
    data_dir: Path | None = None,
    reports_dir: Path | None = None,
    github_token: str | None = None,
    user_agent_contact: str | None = None,
    log_level: str | None = None,
    log_json: bool = False,
) -> Settings:
    path = Path(config_path).expanduser() if config_path else DEFAULT_CONFIG_PATH
    raw = _read_config_file(path)

    settings = Settings(config_path=path if path.exists() else None)
    if raw:
        if "data_dir" in raw:
            settings.data_dir = _coerce_path(raw["data_dir"], "data_dir")
        if "reports_dir" in raw:
            settings.reports_dir = _coerce_path(raw["reports_dir"], "reports_dir")
        if isinstance(raw.get("github_token"), str):
            settings.github_token = raw["github_token"].strip() or None
        if isinstance(raw.get("gitlab_token"), str):
            settings.gitlab_token = raw["gitlab_token"].strip() or None
        if isinstance(raw.get("user_agent_contact"), str):
            settings.user_agent_contact = raw["user_agent_contact"].strip()
        for field_name in ("http_timeout",):
            value = raw.get(field_name)
            if value is not None and not isinstance(value, (int, float)):
                raise ConfigError(f"config field {field_name} must be numeric")
            if isinstance(value, (int, float)):
                setattr(settings, field_name, float(value))
        for field_name in (
            "http_concurrency",
            "registry_concurrency",
            "evidence_max_bytes",
        ):
            value = raw.get(field_name)
            if value is not None and not isinstance(value, int):
                raise ConfigError(f"config field {field_name} must be an integer")
            if isinstance(value, int) and value > 0:
                setattr(settings, field_name, value)
        if isinstance(raw.get("log_level"), str):
            settings.log_level = raw["log_level"]
        if isinstance(raw.get("log_file"), str) and raw["log_file"].strip():
            settings.log_file = Path(raw["log_file"]).expanduser()

    env_data = os.environ.get("DEPHUNTER_DATA_DIR")
    env_reports = os.environ.get("DEPHUNTER_REPORTS_DIR")
    env_contact = os.environ.get("DEPHUNTER_CONTACT")
    env_github = os.environ.get("DEPHUNTER_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
    env_gitlab = os.environ.get("DEPHUNTER_GITLAB_TOKEN") or os.environ.get("GITLAB_TOKEN")

    if env_data:
        settings.data_dir = Path(env_data).expanduser()
    if env_reports:
        settings.reports_dir = Path(env_reports).expanduser()
    if env_contact:
        settings.user_agent_contact = env_contact.strip()
    if env_github:
        settings.github_token = env_github.strip()
    if env_gitlab:
        settings.gitlab_token = env_gitlab.strip()

    if data_dir is not None:
        settings.data_dir = Path(data_dir).expanduser()
    if reports_dir is not None:
        settings.reports_dir = Path(reports_dir).expanduser()
    if github_token:
        settings.github_token = github_token.strip()
    if user_agent_contact:
        settings.user_agent_contact = user_agent_contact.strip()
    if log_level:
        settings.log_level = log_level
    if log_json:
        settings.log_json = True

    if settings.http_concurrency < 1 or settings.http_concurrency > 64:
        raise ConfigError("http_concurrency must be between 1 and 64")
    if settings.registry_concurrency < 1 or settings.registry_concurrency > 32:
        raise ConfigError("registry_concurrency must be between 1 and 32")
    if settings.user_agent_contact == "not-configured":
        os.environ.setdefault("DEPHUNTER_CONTACT_MISSING", "1")
    return settings
