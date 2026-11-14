from __future__ import annotations

import fnmatch
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable

from dephunter.core.models import ConfigFact, DependencyRef, ExtractionResult
from dephunter.core.names import normalize_package_name
from dephunter.core.util import LineLocator, assert_safe_xml, decode_text, safe_json_loads

MAX_MANIFEST_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class ExtractContext:
    origin: str = "web"
    source_url: str = ""
    file_path: str | None = None
    commit: str | None = None
    repo: str | None = None

    def kind(self, role: str) -> str:
        return f"{self.origin}_{role}"


@dataclass(slots=True)
class ExtractJob:
    extractor: "BaseExtractor"
    name: str


def basename(path: str) -> str:
    return PurePosixPath(path).name


class BaseExtractor:
    ecosystem: str = ""
    filenames: tuple[str, ...] = ()
    globs: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()
    role: str = "manifest"

    def matches(self, path: str) -> bool:
        name = basename(path).lower()
        path_lower = path.lower()
        if name in {f.lower() for f in self.filenames}:
            return True
        if any(name.endswith(suffix.lower()) for suffix in self.suffixes):
            return True
        for pattern in self.globs:
            pattern_lower = pattern.lower()
            if fnmatch.fnmatch(path_lower, pattern_lower) or fnmatch.fnmatch(name, pattern_lower):
                return True
        return False

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        raise NotImplementedError


def decode_manifest(content: bytes) -> str:
    if len(content) > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    return decode_text(content)


def parse_json(content: bytes) -> tuple[object, str]:
    text = decode_manifest(content)
    data = safe_json_loads(text, max_bytes=MAX_MANIFEST_BYTES)
    return data, text


def parse_xml(content: bytes) -> tuple[ET.Element, str]:
    text = decode_manifest(content)
    assert_safe_xml(text)
    return ET.fromstring(text), text


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if local_name(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def sanitize_url_credentials(value: str) -> str:
    from urllib.parse import urlparse, urlunparse

    try:
        parsed = urlparse(value)
    except ValueError:
        return value
    if not parsed.username and not parsed.password:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse((parsed.scheme, host, parsed.path, parsed.params, parsed.query, parsed.fragment))


def make_dep(
    ctx: ExtractContext,
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    role: str = "manifest",
    line: int | None = None,
    resolved_url: str | None = None,
    explicit_source: bool = False,
    direct: bool = True,
    groups: Iterable[str] | None = None,
    extra: dict | None = None,
) -> DependencyRef:
    checksum = None
    if extra and isinstance(extra.get("checksum"), str):
        checksum = extra["checksum"]
    payload = dict(extra or {})
    if checksum:
        payload.setdefault("checksum", checksum)
    return DependencyRef(
        ecosystem=ecosystem,
        name=name,
        normalized=normalize_package_name(ecosystem, name),
        version=version,
        source_kind=ctx.kind(role),
        source_url=ctx.source_url,
        file_path=ctx.file_path,
        line=line,
        commit=ctx.commit,
        repo=ctx.repo,
        resolved_url=sanitize_url_credentials(resolved_url) if resolved_url else None,
        explicit_source=explicit_source,
        direct=direct,
        groups=list(groups or []),
        extra=payload,
    )


def make_fact(
    ctx: ExtractContext,
    ecosystem: str,
    fact_type: str,
    value: str,
    *,
    role: str = "config",
    line: int | None = None,
    extra: dict | None = None,
) -> ConfigFact:
    return ConfigFact(
        ecosystem=ecosystem,
        fact_type=fact_type,
        value=sanitize_url_credentials(value)[:1000],
        source_kind=ctx.kind(role),
        source_url=ctx.source_url,
        file_path=ctx.file_path,
        line=line,
        extra=dict(extra or {}),
    )


def locator(text: str) -> LineLocator:
    return LineLocator(text)


def toml_loads(text: str):
    import tomllib

    return tomllib.loads(text)


def yaml_load_safe(text: str):
    import yaml

    return yaml.safe_load(text)


def version_keys(name: str) -> list[str]:
    return [name, f"'{name}'", f'"{name}"', name.replace("/", "%2f")]
