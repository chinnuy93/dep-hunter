from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.nz", "net.nz", "org.nz", "co.in",
    "net.in", "org.in", "com.br", "net.br", "org.br", "com.mx", "com.tr",
    "com.cn", "net.cn", "org.cn", "co.za", "com.sg", "com.hk", "com.tw",
    "co.il", "com.ar", "com.co", "com.pe", "com.ec", "com.uy", "co.kr",
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_iso(dt: datetime | None = None) -> str:
    return (dt or utc_now()).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _remove_dot_segments(path: str) -> str:
    if not path:
        return "/"
    normalized = posixpath.normpath(path)
    if path.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def canonical_url(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = _remove_dot_segments(parsed.path)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode(sorted(query_pairs), doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_same_site(host_a: str, host_b: str) -> bool:
    return registrable_domain(host_a) == registrable_domain(host_b)


def is_global_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_global


def gzip_write(path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb", compresslevel=6) as fh:
        fh.write(data)


def gzip_read(path) -> bytes:
    with gzip.open(path, "rb") as fh:
        return fh.read()


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def format_duration(seconds: float | int | None) -> str:
    value = max(0.0, float(seconds or 0.0))
    total = int(round(value))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s"


def safe_json_loads(data: bytes | str, *, max_bytes: int = 8 * 1024 * 1024) -> Any:
    if isinstance(data, str):
        if len(data) > max_bytes:
            raise ValueError("JSON content exceeds size limit")
        return json.loads(data)
    if len(data) > max_bytes:
        raise ValueError("JSON content exceeds size limit")
    return json.loads(data.decode("utf-8", "replace"))


def assert_safe_xml(text: str) -> None:
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("XML documents with DOCTYPE/ENTITY declarations are rejected")


def bounded(text: str, limit: int = 400) -> str:
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def semverish(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    match = re.search(r"(\d+(?:\.\d+){0,3})", value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def format_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(widths):
                widths[idx] = max(widths[idx], len(cell))
    def fmt(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row))
    lines = [fmt(headers), fmt(["-" * w for w in widths])]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


class LineLocator:
    """Approximate sequential line lookup for formats without line info."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0

    def find(self, token: str) -> int | None:
        if not token:
            return None
        index = self.text.find(token, self.position)
        if index < 0:
            index = self.text.find(token)
        if index < 0:
            return None
        self.position = index + len(token)
        return self.text.count("\n", 0, index) + 1

    def find_any(self, tokens: Iterable[str]) -> int | None:
        best: tuple[int, int] | None = None
        for token in tokens:
            index = self.text.find(token, self.position)
            if index >= 0 and (best is None or index < best[0]):
                best = (index, len(token))
        if best is None:
            return None
        self.position = best[0] + best[1]
        return self.text.count("\n", 0, best[0]) + 1


@dataclass(slots=True)
class UrlScan:
    url: str
    host: str
    site: str
    path: str
