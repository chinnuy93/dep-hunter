from __future__ import annotations

import re
from typing import Any

from dephunter.core.models import ExtractionResult
from dephunter.core.names import is_explicit_safe_python_spec, split_python_spec
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    make_fact,
    sanitize_url_credentials,
    toml_loads,
)

_EGG = re.compile(r"#egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_VERSION_START = re.compile(r"^\s*(===|==|~=|>=|<=|!=|>|<|\^|~|\*|@|;)")


class RequirementsExtractor(BaseExtractor):
    ecosystem = "pypi"
    globs = ("requirements*.txt", "*-requirements.txt", "requirements/*.txt", "constraints*.txt")
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        logical: list[tuple[int, str]] = []
        buffer = ""
        start_line = 0
        for idx, raw in enumerate(text.splitlines(), 1):
            if not buffer:
                start_line = idx
            line = raw.rstrip()
            if line.endswith("\\"):
                buffer += line[:-1] + " "
                continue
            logical.append((start_line, buffer + line))
            buffer = ""
        if buffer:
            logical.append((start_line, buffer))

        for line_no, raw in logical:
            line = _strip_comment(raw).strip()
            if not line:
                continue
            if line.startswith("-"):
                _handle_option(line, line_no, result, ctx)
                continue
            editable = line.startswith(("-e ", "--editable "))
            if editable:
                line = line.split(" ", 1)[1].strip()
            spec_name, version, _extras = split_python_spec(line)
            if not spec_name:
                egg = _EGG.search(line)
                if egg:
                    result.dependencies.append(
                        make_dep(ctx, "pypi", egg.group(1), line[:200], explicit_source=True, direct=True, groups=["runtime"])
                    )
                continue
            explicit = editable or is_explicit_safe_python_spec(version) or " @ " in line
            groups = ["runtime"]
            result.dependencies.append(
                make_dep(
                    ctx,
                    "pypi",
                    spec_name,
                    (version or "").strip() or None,
                    line=line_no,
                    explicit_source=explicit,
                    direct=True,
                    groups=groups,
                    extra={"raw": line[:300]},
                )
            )
        return result


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    result = []
    quote: str | None = None
    for idx, char in enumerate(line):
        if char in {"'", '"'}:
            quote = None if quote == char else (char if quote is None else quote)
        if char == "#" and quote is None and (idx == 0 or line[idx - 1].isspace()):
            break
        result.append(char)
    return "".join(result)


def _handle_option(line: str, line_no: int, result: ExtractionResult, ctx: ExtractContext) -> None:
    parts = line.split(None, 1)
    option = parts[0]
    value = parts[1].strip() if len(parts) > 1 else ""
    if option.startswith("--") and "=" in option:
        option, value = option.split("=", 1)
    aliases = {
        "-i": "pip_index_url",
        "--index-url": "pip_index_url",
        "--extra-index-url": "pip_extra_index_url",
        "--no-index": "pip_no_index",
        "--trusted-host": "pip_trusted_host",
        "-f": "pip_find_links",
        "--find-links": "pip_find_links",
        "-r": "pip_requirements_include",
        "--requirement": "pip_requirements_include",
        "-c": "pip_constraints_include",
        "--constraint": "pip_constraints_include",
        "--only-binary": "pip_only_binary",
        "--platform": "pip_platform",
        "--python-version": "pip_python_version",
        "--implementation": "pip_implementation",
        "--abi": "pip_abi",
    }
    fact_type = aliases.get(option)
    if not fact_type:
        if option in {"--hash"}:
            return
        return
    if fact_type in {"pip_index_url", "pip_extra_index_url", "pip_find_links"}:
        value = sanitize_url_credentials(value)
        if "://" not in value:
            value = "https://" + value
    result.config_facts.append(
        make_fact(ctx, "pypi", fact_type, value or "true", line=line_no, extra={"raw_option": option})
    )


class PipfileExtractor(BaseExtractor):
    ecosystem = "pypi"
    filenames = ("Pipfile",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            data = toml_loads(decode_manifest(content))
        except Exception as exc:
            result.warnings.append(f"invalid Pipfile: {exc}")
            return result
        loc = locator(decode_manifest(content))
        sources = data.get("source")
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, dict) and isinstance(source.get("url"), str):
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "pypi",
                            "pipfile_source",
                            sanitize_url_credentials(source["url"]),
                            line=loc.find(str(source.get("name") or "source")),
                            extra={"name": source.get("name"), "verify_ssl": source.get("verify_ssl")},
                        )
                    )
        for section, groups in (("packages", ["runtime"]), ("dev-packages", ["dev"])):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if not isinstance(name, str):
                    continue
                version = None
                explicit = False
                extra: dict[str, Any] = {"section": section}
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version") if isinstance(spec.get("version"), str) else None
                    if any(key in spec for key in ("git", "path", "file", "editable")):
                        explicit = True
                        extra["explicit_source_spec"] = str(
                            spec.get("git") or spec.get("path") or spec.get("file")
                        )[:300]
                    if isinstance(spec.get("index"), str):
                        extra["index"] = spec["index"]
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "pypi",
                        name,
                        version,
                        line=loc.find(f'"{name}"'),
                        explicit_source=explicit,
                        direct=True,
                        groups=groups,
                        extra=extra,
                    )
                )
        return result


class PyprojectExtractor(BaseExtractor):
    ecosystem = "pypi"
    filenames = ("pyproject.toml",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        try:
            data = toml_loads(text)
        except Exception as exc:
            result.warnings.append(f"invalid pyproject.toml: {exc}")
            return result
        loc = locator(text)
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for spec in deps:
                if isinstance(spec, str):
                    _add_pep508(spec, result, ctx, loc, ["runtime"])
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, specs in optional.items():
                if isinstance(specs, list):
                    for spec in specs:
                        if isinstance(spec, str):
                            _add_pep508(spec, result, ctx, loc, [f"optional:{group}"])

        poetry = _nested(data, "tool", "poetry")
        if isinstance(poetry, dict):
            _add_poetry_group(poetry.get("dependencies"), result, ctx, loc, ["runtime"], "poetry")
            _add_poetry_group(poetry.get("dev-dependencies"), result, ctx, loc, ["dev"], "poetry")
            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_cfg in groups.items():
                    if isinstance(group_cfg, dict):
                        _add_poetry_group(
                            group_cfg.get("dependencies"),
                            result,
                            ctx,
                            loc,
                            [f"poetry-group:{group_name}"],
                            "poetry",
                        )
            sources = poetry.get("source")
            if isinstance(sources, list):
                for source in sources:
                    if isinstance(source, dict) and isinstance(source.get("url"), str):
                        result.config_facts.append(
                            make_fact(
                                ctx,
                                "pypi",
                                "poetry_source",
                                sanitize_url_credentials(source["url"]),
                                line=loc.find("url"),
                                extra={
                                    "name": source.get("name"),
                                    "priority": source.get("priority"),
                                },
                            )
                        )
        pdm = _nested(data, "tool", "pdm")
        if isinstance(pdm, dict):
            dev_groups = pdm.get("dev-dependencies")
            if isinstance(dev_groups, dict):
                for group, specs in dev_groups.items():
                    if isinstance(specs, list):
                        for spec in specs:
                            if isinstance(spec, str):
                                _add_pep508(spec, result, ctx, loc, [f"pdm-dev:{group}"])
        uv = _nested(data, "tool", "uv")
        if isinstance(uv, dict):
            dev = uv.get("dev-dependencies")
            if isinstance(dev, list):
                for spec in dev:
                    if isinstance(spec, str):
                        _add_pep508(spec, result, ctx, loc, ["uv-dev"])
        return result


def _add_pep508(spec: str, result: ExtractionResult, ctx: ExtractContext, loc, groups: list[str]) -> None:
    name, version, _extras = split_python_spec(spec)
    if not name:
        return
    explicit = is_explicit_safe_python_spec(version) or " @ " in spec
    result.dependencies.append(
        make_dep(
            ctx,
            "pypi",
            name,
            (version or "").strip() or None,
            line=loc.find(name),
            explicit_source=explicit,
            direct=True,
            groups=list(groups),
            extra={"raw": spec[:300]},
        )
    )


def _add_poetry_group(
    entries: Any,
    result: ExtractionResult,
    ctx: ExtractContext,
    loc,
    groups: list[str],
    manager: str,
) -> None:
    if not isinstance(entries, dict):
        return
    for name, spec in entries.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        version = None
        explicit = False
        extra: dict[str, Any] = {"manager": manager}
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            if isinstance(spec.get("version"), str):
                version = spec["version"]
            if any(key in spec for key in ("git", "path", "url", "file")):
                explicit = True
                extra["explicit_source_spec"] = str(
                    spec.get("git") or spec.get("path") or spec.get("url") or spec.get("file")
                )[:300]
            if spec.get("workspace") is True:
                explicit = True
                extra["explicit_source_spec"] = "workspace"
            if isinstance(spec.get("source"), str):
                extra["source"] = spec["source"]
        result.dependencies.append(
            make_dep(
                ctx,
                "pypi",
                name,
                version,
                line=loc.find(f'"{name}"'),
                explicit_source=explicit,
                direct=True,
                groups=list(groups),
                extra=extra,
            )
        )


class PipfileLockExtractor(BaseExtractor):
    ecosystem = "pypi"
    filenames = ("Pipfile.lock",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        from dephunter.extractors.base import parse_json

        result = ExtractionResult()
        try:
            data, _text = parse_json(content)
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"invalid Pipfile.lock: {exc}")
            return result
        if not isinstance(data, dict):
            return result
        for section, groups in (("default", ["runtime"]), ("develop", ["dev"])):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for name, info in entries.items():
                if not isinstance(name, str) or not isinstance(info, dict):
                    continue
                version = info.get("version") if isinstance(info.get("version"), str) else None
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "pypi",
                        name,
                        version,
                        role="lockfile",
                        direct=False,
                        groups=groups,
                        extra={"hashes": len(info.get("hashes") or [])},
                    )
                )
        return result


def _nested(data: dict, *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
