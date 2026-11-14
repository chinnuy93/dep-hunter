from __future__ import annotations

import re
from typing import Any

from dephunter.core.models import ExtractionResult
from dephunter.core.names import COMMON_PUBLIC_SCOPES, NPM_BUILTINS
from dephunter.extractors.base import BaseExtractor, ExtractContext, decode_manifest, make_dep, parse_json

_NODE_MODULES = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)")
_WEBPACK_SCOPED = re.compile(r"webpack://(?:\./)?(@[^/]+/[^/]+)")
_IMPORT = re.compile(
    r"(?:from\s*|require\s*\(\s*)['\"]([^'\"]+)['\"]"
)
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_JS_NOISE = {
    "app", "src", "index", "main", "vendor", "runtime", "polyfills", "scripts",
    "static", "assets", "dist", "build", "webpack", "bootstrap", "external",
    "node_modules", "undefined", "null", "true", "false", "this", "module",
    "exports", "window", "document", "global", "self", "process", "require",
}


class JavaScriptExtractor(BaseExtractor):
    ecosystem = "npm"
    suffixes = (".js", ".mjs", ".cjs", ".js.map")
    role = "js"

    def role_for(self, path: str) -> str:
        return "sourcemap" if path.lower().endswith(".map") else "js"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        role = self.role_for(ctx.file_path or ctx_name)
        names: dict[str, str | None] = {}
        if role == "sourcemap":
            _extract_sourcemap(text, names, result)
        else:
            _extract_js(text, names)
        for name, version in sorted(names.items()):
            result.dependencies.append(
                make_dep(
                    ctx,
                    "npm",
                    name,
                    version,
                    role=role,
                    direct=False,
                    groups=["sourcemap" if role == "sourcemap" else "bundle"],
                    extra={"discovered_by": "javascript"},
                )
            )
        return result


def _extract_sourcemap(text: str, names: dict[str, str | None], result: ExtractionResult) -> None:
    try:
        data = parse_json(text.encode("utf-8"))[0]
    except (ValueError, TypeError) as exc:
        result.warnings.append(f"invalid source map: {exc}")
        return
    if not isinstance(data, dict):
        return
    sources = data.get("sources")
    if not isinstance(sources, list):
        return
    contents = data.get("sourcesContent")
    versions: dict[str, str] = {}
    if isinstance(contents, list):
        for index, source in enumerate(sources):
            if not isinstance(source, str) or not source.endswith("package.json"):
                continue
            if index >= len(contents) or not isinstance(contents[index], str):
                continue
            try:
                pkg = parse_json(contents[index].encode("utf-8"))[0]
            except (ValueError, TypeError):
                continue
            if isinstance(pkg, dict) and isinstance(pkg.get("name"), str) and isinstance(pkg.get("version"), str):
                versions.setdefault(pkg["name"], pkg["version"])
    for source in sources[:5000]:
        if not isinstance(source, str):
            continue
        for name in _packages_from_source(source):
            if _acceptable(name):
                names.setdefault(name, versions.get(name))
    for name, version in versions.items():
        if _acceptable(name):
            names.setdefault(name, version)


def _extract_js(text: str, names: dict[str, str | None]) -> None:
    for match in _NODE_MODULES.finditer(text):
        candidate = match.group(1).strip("/")
        if _acceptable(candidate):
            names.setdefault(candidate, None)
    for match in _WEBPACK_SCOPED.finditer(text):
        candidate = match.group(1).strip("/")
        if _acceptable(candidate):
            names.setdefault(candidate, None)
    for match in _IMPORT.finditer(text):
        spec = match.group(1)
        if not spec or spec[0] in {".", "/", "~", "#"} or spec.startswith(("http:", "https:", "data:")):
            continue
        candidate = spec
        if candidate.startswith("node:"):
            continue
        parts = candidate.split("/")
        if candidate.startswith("@"):
            candidate = "/".join(parts[:2])
        else:
            candidate = parts[0]
        if candidate in NPM_BUILTINS or candidate in _JS_NOISE:
            continue
        if _acceptable(candidate):
            names.setdefault(candidate, None)
    if len(names) > 2000:
        names = dict(list(names.items())[:2000])


def _packages_from_source(source: str) -> list[str]:
    result: list[str] = []
    for match in _NODE_MODULES.finditer(source):
        candidate = match.group(1).strip("/")
        if candidate and candidate not in result:
            result.append(candidate)
    return result


def _acceptable(name: str) -> bool:
    if not name or len(name) > 120:
        return False
    if name.startswith((".", "_", "~")):
        return False
    if name in NPM_BUILTINS or name in _JS_NOISE:
        return False
    if name.startswith(".pnpm"):
        return False
    if "%" in name or "\\" in name or "?" in name:
        return False
    if name.startswith("@") and "/" in name:
        scope = name.split("/", 1)[0].lstrip("@")
        if scope in _JS_NOISE:
            return False
        return bool(_NPM_NAME.match(name))
    return bool(_NPM_NAME.match(name)) and "/" not in name
