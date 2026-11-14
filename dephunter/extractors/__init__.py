from __future__ import annotations

import logging

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import BaseExtractor, ExtractContext, basename
from dephunter.extractors.ci import CIExtractor
from dephunter.extractors.cargo import CargoLockExtractor, CargoManifestExtractor
from dephunter.extractors.composer import ComposerLockExtractor, ComposerManifestExtractor
from dephunter.extractors.docker import DockerComposeExtractor, DockerfileExtractor
from dephunter.extractors.gomod import GoModExtractor
from dephunter.extractors.gradle import GradleExtractor
from dephunter.extractors.javascript import JavaScriptExtractor
from dephunter.extractors.maven import MavenPomExtractor
from dephunter.extractors.npm import (
    NpmConfigExtractor,
    NpmLockExtractor,
    NpmManifestExtractor,
    PnpmLockExtractor,
    YarnLockExtractor,
)
from dephunter.extractors.nuget import (
    NugetConfigExtractor,
    NugetPackagesConfigExtractor,
    NugetProjectExtractor,
)
from dephunter.extractors.python import (
    PipfileExtractor,
    PipfileLockExtractor,
    PyprojectExtractor,
    RequirementsExtractor,
)
from dephunter.extractors.ruby import GemfileExtractor, GemfileLockExtractor

log = logging.getLogger(__name__)

EXTRACTORS: tuple[BaseExtractor, ...] = (
    NpmManifestExtractor(),
    NpmLockExtractor(),
    NpmConfigExtractor(),
    YarnLockExtractor(),
    PnpmLockExtractor(),
    RequirementsExtractor(),
    PyprojectExtractor(),
    PipfileExtractor(),
    PipfileLockExtractor(),
    MavenPomExtractor(),
    GradleExtractor(),
    NugetProjectExtractor(),
    NugetPackagesConfigExtractor(),
    NugetConfigExtractor(),
    GoModExtractor(),
    GemfileExtractor(),
    GemfileLockExtractor(),
    ComposerManifestExtractor(),
    ComposerLockExtractor(),
    CargoManifestExtractor(),
    CargoLockExtractor(),
    DockerfileExtractor(),
    DockerComposeExtractor(),
    JavaScriptExtractor(),
    CIExtractor(),
)

_WHITELIST_SUFFIXES = (".json", ".toml", ".xml", ".gradle", ".kts", ".csproj", ".fsproj", ".vbproj", ".yaml", ".yml")


def find_extractor(path: str) -> BaseExtractor | None:
    for extractor in EXTRACTORS:
        if extractor.matches(path):
            return extractor
    return None


def is_manifest_path(path: str) -> bool:
    return find_extractor(path) is not None


def manifest_role(path: str) -> str:
    extractor = find_extractor(path)
    if extractor is None:
        return "asset"
    role_for = getattr(extractor, "role_for", None)
    if callable(role_for):
        return str(role_for(path))
    return extractor.role


def extract(path: str, content: bytes, ctx: ExtractContext) -> ExtractionResult:
    extractor = find_extractor(path)
    if extractor is None:
        return ExtractionResult(warnings=[f"no extractor for {path}"])
    try:
        result = extractor.extract(content, basename(path), ctx)
    except Exception as exc:
        log.warning("extractor failed for %s: %s", path, exc)
        return ExtractionResult(warnings=[f"extractor failure for {path}: {exc}"])
    return result


def supported_manifest_hints() -> list[str]:
    hints: list[str] = []
    for extractor in EXTRACTORS:
        hints.extend(extractor.filenames)
        hints.extend(extractor.globs)
    return sorted(set(hints))
