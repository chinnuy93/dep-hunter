from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"npm_[A-Za-z0-9]{20,}"), "npm_[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "gh*_[REDACTED]"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "glpat-[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{10,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(_authToken|_auth|_password|password|passwd|secret|token)\s*[=:]\s*[^\s,;\"']+"), r"\1=[REDACTED]"),
    (re.compile(r'(?i)(ClearTextPassword|Password)"\s+value="[^"]*"'), r'\1" value="[REDACTED]"'),
]


def redact(value: str) -> str:
    result = value
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            record.exc_info = None
            record.msg += f" | exception: {redact(str(exc_value))}"
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str = "INFO", json_mode: bool = False, log_file: Path | None = None) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter: logging.Formatter
    if json_mode:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")

    redactor = RedactingFilter()
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    stream.addFilter(redactor)
    root.addHandler(stream)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redactor)
        root.addHandler(file_handler)

    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
