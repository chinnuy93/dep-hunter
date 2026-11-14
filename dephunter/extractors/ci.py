from __future__ import annotations

import re
from urllib.parse import urlparse

from dephunter.core.logging import redact
from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import BaseExtractor, ExtractContext, decode_manifest, make_fact, parse_json

_INSTALL_COMMAND = re.compile(
    r"\b(?P<command>"
    r"npm\s+(?:ci|install|i)\b[^\n]*|"
    r"yarn\s+(?:install|add)\b[^\n]*|"
    r"pnpm\s+(?:install|i|add)\b[^\n]*|"
    r"pip3?\s+install\b[^\n]*|"
    r"pipenv\s+(?:install|sync)\b[^\n]*|"
    r"poetry\s+(?:install|add)\b[^\n]*|"
    r"bundle\s+install\b[^\n]*|"
    r"composer\s+install\b[^\n]*|"
    r"nuget\s+restore\b[^\n]*|"
    r"dotnet\s+restore\b[^\n]*|"
    r"(?:mvn|mvnw|gradle|gradlew)\b[^\n]*|"
    r"cargo\s+(?:build|fetch|install)\b[^\n]*"
    r")",
    re.I,
)
_URL = re.compile(r"https?://[^\s\"'`,)]+")
_REGISTRY_HINTS = (
    "registry", "artifactory", "nexus", "verdaccio", "pypi", "npm", "nuget",
    "maven", "gems", "rubygems", "packagist", "crates", "repo", "/simple",
)
_ENV_FACT = {
    "NPM_CONFIG_REGISTRY": ("npm", "env_npm_registry"),
    "npm_config_registry": ("npm", "env_npm_registry"),
    "PIP_INDEX_URL": ("pypi", "env_pip_index_url"),
    "PIP_EXTRA_INDEX_URL": ("pypi", "env_pip_extra_index_url"),
    "GOPRIVATE": ("go", "go_private"),
    "GONOSUMDB": ("go", "go_private"),
    "GOPROXY": ("go", "go_proxy"),
    "NUGET_PACKAGES": ("nuget", "nuget_packages_dir"),
    "MAVEN_OPTS": ("maven", "maven_opts"),
}


class CIExtractor(BaseExtractor):
    ecosystem = "ci"
    filenames = ("Jenkinsfile", ".gitlab-ci.yml", "renovate.json", ".renovaterc")
    globs = (
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".circleci/config.yml",
        "renovate.json5",
        ".renovaterc.json",
    )
    role = "config"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        if ctx_name.lower().startswith("renovate") or "renovaterc" in ctx_name.lower():
            _extract_renovate(text, result, ctx)
            return result
        _scan_text(text, result, ctx)
        return result


def _scan_text(text: str, result: ExtractionResult, ctx: ExtractContext) -> None:
    seen: set[str] = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for match in _INSTALL_COMMAND.finditer(line):
            command = redact(match.group("command").strip())[:250]
            key = f"{line_no}:{command}"
            if key in seen:
                continue
            seen.add(key)
            result.config_facts.append(
                make_fact(
                    ctx,
                    "ci",
                    "ci_install_command",
                    command,
                    line=line_no,
                    extra={"ecosystem": _guess_ecosystem(command)},
                )
            )
        for url_match in _URL.finditer(line):
            url = url_match.group(0).rstrip(".,;")
            if any(hint in url.lower() for hint in _REGISTRY_HINTS):
                result.config_facts.append(
                    make_fact(ctx, "ci", "generic_registry_url", url, line=line_no)
                )
        for env_name, (ecosystem, fact_type) in _ENV_FACT.items():
            pattern = re.compile(rf"\b{re.escape(env_name)}\b\s*[:=]\s*(?P<value>\S+)")
            env_match = pattern.search(line)
            if env_match:
                result.config_facts.append(
                    make_fact(
                        ctx,
                        ecosystem,
                        fact_type,
                        env_match.group("value").strip("\"'"),
                        line=line_no,
                        extra={"env": env_name},
                    )
                )
        if re.search(r"\bnpm\s+install\b", line, re.I) and "--ignore-scripts" not in line:
            result.config_facts.append(
                make_fact(ctx, "npm", "ci_npm_install_without_lock", "true", line=line_no)
            )


def _extract_renovate(text: str, result: ExtractionResult, ctx: ExtractContext) -> None:
    try:
        data, _ = parse_json(text.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        result.warnings.append(f"renovate config is not strict JSON (JSON5 unsupported): {exc}")
        return
    if not isinstance(data, dict):
        return
    urls = data.get("registryUrls")
    if isinstance(urls, list):
        for url in urls:
            if isinstance(url, str):
                result.config_facts.append(make_fact(ctx, "ci", "renovate_registry_url", url))
    host_rules = data.get("hostRules")
    if isinstance(host_rules, list):
        for rule in host_rules:
            if isinstance(rule, dict):
                host = rule.get("matchHost")
                if isinstance(host, str):
                    result.config_facts.append(
                        make_fact(ctx, "ci", "renovate_host_rule", host, extra={"matchHost": host})
                    )
    npmrc = data.get("npmrc")
    if isinstance(npmrc, str):
        for line in npmrc.splitlines():
            if "registry" in line.lower():
                result.config_facts.append(
                    make_fact(ctx, "ci", "renovate_npmrc", redact(line.strip())[:300])
                )
    package_rules = data.get("packageRules")
    if isinstance(package_rules, list):
        for rule in package_rules:
            if not isinstance(rule, dict):
                continue
            for key in ("matchPackageNames", "matchDepNames"):
                names = rule.get(key)
                if isinstance(names, list):
                    for name in names:
                        if isinstance(name, str) and name:
                            result.config_facts.append(
                                make_fact(ctx, "ci", "renovate_package_reference", name[:200])
                            )


def _guess_ecosystem(command: str) -> str:
    lowered = command.lower()
    if lowered.startswith(("npm", "yarn", "pnpm")):
        return "npm"
    if lowered.startswith(("pip", "pipenv", "poetry")):
        return "pypi"
    if lowered.startswith(("bundle",)):
        return "rubygems"
    if lowered.startswith(("composer",)):
        return "packagist"
    if lowered.startswith(("nuget", "dotnet")):
        return "nuget"
    if lowered.startswith(("mvn", "gradle")):
        return "maven"
    if lowered.startswith(("cargo",)):
        return "crates"
    return "unknown"
