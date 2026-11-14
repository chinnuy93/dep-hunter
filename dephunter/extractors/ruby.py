from __future__ import annotations

import re

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    make_fact,
)

_GEM_LINE = re.compile(r"^\s*gem\s+(['\"])(?P<name>[^'\"]+)\1(?P<rest>.*)$")
_SOURCE_LINE = re.compile(r"^\s*source\s+(['\"])(?P<url>[^'\"]+)\1(?P<rest>.*)$")
_OPTION = re.compile(r"(\w+):\s*(?:(['\"])(.*?)\2|([^,\s]+))")
_VERSION_ARG = re.compile(r"^\s*,\s*(['\"])(?P<version>[^'\"]+)\1")


class GemfileExtractor(BaseExtractor):
    ecosystem = "rubygems"
    filenames = ("Gemfile",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        loc = locator(text)
        source_stack: list[str | None] = []
        current_source: str | None = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            source_match = _SOURCE_LINE.match(raw)
            if source_match:
                url = source_match.group("url")
                is_block = " do" in source_match.group("rest")
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "rubygems",
                        "gem_source",
                        url,
                        line=loc.find(url),
                        extra={"block": is_block},
                    )
                )
                if is_block:
                    source_stack.append(current_source)
                    current_source = url
                continue
            gem_match = _GEM_LINE.match(raw)
            if gem_match:
                name = gem_match.group("name")
                rest = gem_match.group("rest")
                version_match = _VERSION_ARG.match(rest)
                version = version_match.group("version") if version_match else None
                options = _parse_options(rest)
                explicit = any(key in options for key in ("git", "github", "path", "file"))
                if "source" in options:
                    options["explicit_source_url"] = options["source"]
                group_name = options.get("group")
                groups = ["runtime"]
                if group_name:
                    groups = [f"group:{g}" for g in re.split(r"[,:\s]+", group_name.strip(":")) if g]
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "rubygems",
                        name,
                        version,
                        line=loc.find(name),
                        explicit_source=explicit,
                        direct=True,
                        groups=groups,
                        extra={
                            "options": {k: v[:200] for k, v in options.items()},
                            "source_block": current_source,
                        },
                    )
                )
                continue
            if re.match(r"^\s*source\b", raw):
                continue
            if re.match(r"^\s*end\b", raw) and source_stack:
                current_source = source_stack.pop()
        return result


def _parse_options(rest: str) -> dict[str, str]:
    options: dict[str, str] = {}
    for match in _OPTION.finditer(rest):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4)
        if value is not None:
            options[key] = value
    return options


class GemfileLockExtractor(BaseExtractor):
    ecosystem = "rubygems"
    filenames = ("Gemfile.lock",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        loc = locator(text)
        section: str | None = None
        remote: str | None = None
        direct_names: set[str] = set()
        in_specs = False
        for raw in text.splitlines():
            if not raw.strip():
                in_specs = False
                continue
            if not raw.startswith((" ", "\t")):
                section = raw.strip()
                remote = None
                in_specs = False
                continue
            stripped = raw.strip()
            if stripped.startswith("remote:"):
                remote = stripped.split(":", 1)[1].strip()
                continue
            if stripped == "specs:":
                in_specs = True
                continue
            if section == "DEPENDENCIES" and not raw.startswith((" ", "\t\t")) and stripped:
                name = stripped.split(" ", 1)[0].rstrip("!")
                if name:
                    direct_names.add(name)
                continue
            if in_specs and section in {"GEM", "GIT", "PATH"}:
                indent = len(raw) - len(raw.lstrip(" "))
                if indent == 4:
                    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s+\(([^)]+)\)$", stripped)
                    if match:
                        name, version = match.group(1), match.group(2)
                        explicit = section in {"GIT", "PATH"}
                        if section == "GEM" and remote and "rubygems.org" not in remote:
                            explicit = False
                        result.dependencies.append(
                            make_dep(
                                ctx,
                                "rubygems",
                                name,
                                version,
                                role="lockfile",
                                line=loc.find(f"{name} ("),
                                resolved_url=remote if section == "GEM" else None,
                                explicit_source=explicit,
                                direct=name in direct_names,
                                groups=["runtime"],
                                extra={
                                    "lockfile_section": section,
                                    "registry": remote,
                                },
                            )
                        )
        return result
