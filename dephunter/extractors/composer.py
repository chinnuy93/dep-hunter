from __future__ import annotations

from typing import Any

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    make_fact,
    parse_json,
    sanitize_url_credentials,
)

_PLATFORM_PREFIXES = ("php", "ext-", "lib-", "composer-", "hhvm")


class ComposerManifestExtractor(BaseExtractor):
    ecosystem = "packagist"
    filenames = ("composer.json",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            data, text = parse_json(content)
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"invalid composer.json: {exc}")
            return result
        if not isinstance(data, dict):
            return result
        loc = locator(text)
        for section, groups in (("require", ["runtime"]), ("require-dev", ["dev"])):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if not isinstance(name, str) or not isinstance(spec, str):
                    continue
                if name.startswith(_PLATFORM_PREFIXES) or "/" not in name:
                    continue
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "packagist",
                        name,
                        spec,
                        line=loc.find(f'"{name}"'),
                        direct=True,
                        groups=groups,
                        extra={"section": section},
                    )
                )
        repositories = data.get("repositories")
        if isinstance(repositories, list):
            for repo in repositories:
                if isinstance(repo, dict):
                    _add_repository_fact(repo, result, ctx, loc)
                elif isinstance(repo, str):
                    result.config_facts.append(
                        make_fact(ctx, "packagist", "composer_repository", sanitize_url_credentials(repo), line=loc.find(repo))
                    )
        config = data.get("config")
        if isinstance(config, dict):
            if config.get("secure-http") is False:
                result.config_facts.append(
                    make_fact(ctx, "packagist", "composer_secure_http_disabled", "true", line=loc.find("secure-http"))
                )
            if isinstance(config.get("platform"), dict):
                result.config_facts.append(
                    make_fact(ctx, "packagist", "composer_platform_pins", "configured", line=loc.find("platform"))
                )
        return result


def _add_repository_fact(repo: dict[str, Any], result: ExtractionResult, ctx: ExtractContext, loc) -> None:
    repo_type = str(repo.get("type") or "")
    url = repo.get("url")
    if isinstance(url, str):
        extra = {"type": repo_type, "canonical": repo.get("canonical")}
        if repo.get("canonical") is False:
            result.config_facts.append(
                make_fact(
                    ctx,
                    "packagist",
                    "composer_canonical_false",
                    url,
                    line=loc.find(url),
                    extra=extra,
                )
            )
        result.config_facts.append(
            make_fact(
                ctx,
                "packagist",
                "composer_repository",
                f"{repo_type}:{sanitize_url_credentials(url)}",
                line=loc.find(url),
                extra=extra,
            )
        )
    if repo.get("packagist.org") is False:
        result.config_facts.append(
            make_fact(ctx, "packagist", "composer_packagist_disabled", "true", line=loc.find("packagist.org"))
        )
    if repo_type == "path":
        result.config_facts.append(
            make_fact(ctx, "packagist", "composer_path_repository", str(url or ""), line=loc.find("path"))
        )


class ComposerLockExtractor(BaseExtractor):
    ecosystem = "packagist"
    filenames = ("composer.lock",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            data, _text = parse_json(content)
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"invalid composer.lock: {exc}")
            return result
        if not isinstance(data, dict):
            return result
        for section, groups in (("packages", ["runtime"]), ("packages-dev", ["dev"])):
            entries = data.get(section)
            if not isinstance(entries, list):
                continue
            for package in entries:
                if not isinstance(package, dict):
                    continue
                name = package.get("name")
                if not isinstance(name, str):
                    continue
                version = package.get("version") if isinstance(package.get("version"), str) else None
                dist = package.get("dist") if isinstance(package.get("dist"), dict) else {}
                source = package.get("source") if isinstance(package.get("source"), dict) else {}
                resolved = dist.get("url") or source.get("url")
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "packagist",
                        name,
                        version,
                        role="lockfile",
                        resolved_url=str(resolved) if resolved else None,
                        direct=False,
                        groups=groups,
                        extra={
                            "dist_type": dist.get("type"),
                            "source_type": source.get("type"),
                        },
                    )
                )
        return result
