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

_CONFIGS = (
    "implementation|api|compile|compileOnly|runtimeOnly|testImplementation|"
    "testCompileOnly|testRuntimeOnly|androidTestImplementation|debugImplementation|"
    "releaseImplementation|kapt|ksp|annotationProcessor|classpath|platform|"
    "enforcedPlatform"
)
_STRING_DEP = re.compile(
    rf"\b(?P<config>{_CONFIGS})\s*(?:\(\s*)?[\"'](?P<coord>[^\"'\s]+)[\"']"
)
_NAMED_DEP = re.compile(
    rf"\b(?P<config>{_CONFIGS})\s*\(\s*group\s*:\s*[\"'](?P<group>[^\"']+)[\"']\s*,\s*"
    r"name\s*:\s*[\"'](?P<name>[^\"']+)[\"']"
    r"(?:\s*,\s*version\s*:\s*[\"'](?P<version>[^\"']+)[\"'])?"
)
_REPO_URL = re.compile(r"maven\s*\{\s*(?:url\s*=\s*)?(?:uri\s*\(\s*)?[\"']([^\"']+)[\"']")
_DYNAMIC_VERSION = re.compile(r"(?:\+|\bSNAPSHOT\b|\blatest\.(?:release|integration)\b|\]|\[|\()")


class GradleExtractor(BaseExtractor):
    ecosystem = "maven"
    globs = ("*.gradle", "*.gradle.kts", "gradle/libs.versions.toml")
    filenames = ("settings.gradle", "settings.gradle.kts", "gradle.properties")
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        if ctx_name.endswith("libs.versions.toml"):
            _parse_version_catalog(text, result, ctx)
            return result
        if ctx_name.endswith("gradle.properties"):
            return result
        loc = locator(text)
        for match in _NAMED_DEP.finditer(text):
            group = match.group("group")
            name = match.group("name")
            version = match.group("version")
            _emit(result, ctx, group, name, version, match.group("config"), loc, match.start())
        for match in _STRING_DEP.finditer(text):
            coord = match.group("coord")
            if ":" not in coord or coord.startswith("project("):
                continue
            parts = coord.split(":")
            if len(parts) < 2:
                continue
            group, name = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else None
            if any(p.startswith("$") or p.startswith("libs.") for p in parts):
                result.warnings.append(f"unresolved Gradle coordinate: {coord}")
            _emit(result, ctx, group, name, version, match.group("config"), loc, match.start())
        if "libs." in text and re.search(r"\blibs\.[A-Za-z0-9_.]+", text):
            result.warnings.append(
                "Gradle version catalog references (libs.*) require gradle/libs.versions.toml; "
                "aliases without a direct coordinate are not resolved"
            )
        if re.search(r"\bmavenCentral\s*\(", text):
            result.config_facts.append(
                make_fact(ctx, "maven", "gradle_repository", "https://repo1.maven.org/maven2/", line=loc.find("mavenCentral"))
            )
        if re.search(r"\bgoogle\s*\(", text):
            result.config_facts.append(
                make_fact(ctx, "maven", "gradle_repository", "https://dl.google.com/dl/android/maven2/", line=loc.find("google()"))
            )
        if re.search(r"\bgradlePluginPortal\s*\(", text):
            result.config_facts.append(
                make_fact(ctx, "maven", "gradle_repository", "https://plugins.gradle.org/m2/", line=loc.find("gradlePluginPortal"))
            )
        if re.search(r"\bmavenLocal\s*\(", text):
            result.config_facts.append(
                make_fact(ctx, "maven", "gradle_repository", "mavenLocal", line=loc.find("mavenLocal"))
            )
        for match in _REPO_URL.finditer(text):
            result.config_facts.append(
                make_fact(
                    ctx,
                    "maven",
                    "gradle_repository",
                    match.group(1),
                    line=text.count("\n", 0, match.start()) + 1,
                )
            )
        return result


def _emit(result: ExtractionResult, ctx: ExtractContext, group: str, name: str, version: str | None, config: str, loc, position: int) -> None:
    if not group or not name:
        return
    groups = ["runtime"]
    if config.startswith("test") or config in {"androidTestImplementation", "kapt", "ksp", "annotationProcessor"}:
        groups = ["test" if config.startswith("test") else "build"]
    if config == "compileOnly":
        groups = ["compile-only"]
    dynamic = bool(version and _DYNAMIC_VERSION.search(version))
    line = (loc.text.count("\n", 0, position) + 1) if position >= 0 else None
    result.dependencies.append(
        make_dep(
            ctx,
            "maven",
            f"{group}:{name}",
            version,
            line=line,
            direct=True,
            groups=groups,
            extra={
                "configuration": config,
                "version_dynamic": dynamic,
                "project_local": False,
            },
        )
    )
    if dynamic:
        result.config_facts.append(
            make_fact(
                ctx,
                "maven",
                "gradle_dynamic_version",
                f"{group}:{name}:{version}",
                line=line,
            )
        )


def _parse_version_catalog(text: str, result: ExtractionResult, ctx: ExtractContext) -> None:
    from dephunter.extractors.base import toml_loads

    try:
        data = toml_loads(text)
    except Exception as exc:
        result.warnings.append(f"invalid Gradle version catalog: {exc}")
        return
    libraries = data.get("libraries")
    if not isinstance(libraries, dict):
        return
    from dephunter.core.util import LineLocator

    loc = LineLocator(text)
    for alias, spec in libraries.items():
        group = name = version = None
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) >= 2:
                group, name = parts[0], parts[1]
                version = parts[2] if len(parts) > 2 else None
        elif isinstance(spec, dict):
            group = spec.get("group")
            name = spec.get("name") or str(alias).replace("-", "_")
            version = spec.get("version")
            if isinstance(version, dict):
                version = version.get("ref") or version.get("require")
        if isinstance(group, str) and isinstance(name, str):
            result.dependencies.append(
                make_dep(
                    ctx,
                    "maven",
                    f"{group}:{name}",
                    str(version) if version else None,
                    line=loc.find(str(alias)),
                    direct=True,
                    groups=["runtime"],
                    extra={"catalog_alias": str(alias), "catalog": True},
                )
            )
