from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from dephunter.core.errors import ConfigError, ScopeViolation
from dephunter.core.names import is_public_registry_host
from dephunter.core.util import canonical_url, is_same_site, registrable_domain

REGISTRY_HOSTS: dict[str, tuple[str, ...]] = {
    "npm": ("registry.npmjs.org",),
    "pypi": ("pypi.org", "files.pythonhosted.org"),
    "maven": ("search.maven.org", "repo1.maven.org"),
    "nuget": ("api.nuget.org", "azuresearch-usnc.nuget.org"),
    "go": ("proxy.golang.org",),
    "rubygems": ("rubygems.org",),
    "packagist": ("packagist.org", "repo.packagist.org"),
    "crates": ("crates.io",),
    "docker": ("hub.docker.com",),
}
GITHUB_API_HOSTS = ("api.github.com",)
GITLAB_API_HOSTS = ("gitlab.com",)

CONFIDENCE_NAMES = ("INSUFFICIENT_EVIDENCE", "CANDIDATE", "HIGH_CONFIDENCE", "CONFIRMED")


@dataclass(slots=True)
class WebTarget:
    url: str
    include_subdomains: bool = False

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()

    @property
    def site(self) -> str:
        return registrable_domain(self.host)


@dataclass(slots=True)
class CrawlSettings:
    max_depth: int = 3
    max_urls: int = 500
    concurrency: int = 6
    requests_per_second: float = 2.0
    respect_robots: bool = True
    source_maps: bool = True
    probe_manifests: bool = False
    exclude_paths: list[str] = field(default_factory=list)
    probe_paths: list[str] = field(
        default_factory=lambda: [
            "/package.json",
            "/package-lock.json",
            "/.npmrc",
            "/requirements.txt",
            "/pyproject.toml",
            "/pom.xml",
            "/go.mod",
            "/Gemfile",
            "/composer.json",
            "/Cargo.toml",
            "/Dockerfile",
        ]
    )


@dataclass(slots=True)
class GitHubSettings:
    orgs: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    include_history: bool = True
    history_commits_per_file: int = 20
    max_repos: int = 50
    max_files_per_repo: int = 200
    include_forks: bool = False
    include_archived: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.orgs or self.repos)


@dataclass(slots=True)
class GitLabSettings:
    projects: list[str] = field(default_factory=list)
    include_history: bool = False
    max_files_per_project: int = 200
    history_commits_per_file: int = 10

    @property
    def enabled(self) -> bool:
        return bool(self.projects)


@dataclass(slots=True)
class RegistrySettings:
    enabled: list[str] = field(
        default_factory=lambda: [
            "npm", "pypi", "maven", "nuget", "go", "rubygems", "packagist", "crates", "docker",
        ]
    )
    query_limit: int = 400
    cache_ttl_hours: int = 24
    requests_per_second: float = 5.0


@dataclass(slots=True)
class AnalysisSettings:
    org_patterns: list[str] = field(default_factory=list)
    internal_keywords: list[str] = field(
        default_factory=lambda: [
            "internal", "private", "corp", "platform", "shared", "libs", "infra",
            "backend", "service", "auth", "core",
        ]
    )
    min_classification: str = "CANDIDATE"


@dataclass(slots=True)
class ScopeConfig:
    program: str
    authorization: str
    contact: str = ""
    allow_private_hosts: bool = False
    web: list[WebTarget] = field(default_factory=list)
    crawl: CrawlSettings = field(default_factory=CrawlSettings)
    github: GitHubSettings = field(default_factory=GitHubSettings)
    gitlab: GitLabSettings = field(default_factory=GitLabSettings)
    registries: RegistrySettings = field(default_factory=RegistrySettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    source_path: Path | None = None

    @property
    def enabled_ecosystems(self) -> list[str]:
        return [e for e in self.registries.enabled if e in REGISTRY_HOSTS]

    def org_patterns(self) -> list[str]:
        patterns = list(self.analysis.org_patterns)
        for target in self.web:
            host = target.host
            if not host:
                continue
            labels = host.split(".")
            for label in labels[:-1]:
                if label and label not in {"www", "app", "api", "dev", "staging", "prod"} and len(label) >= 3:
                    patterns.append(label)
        for repo in self.github.repos:
            owner = repo.split("/", 1)[0]
            if owner:
                patterns.append(owner)
        patterns.extend(self.github.orgs)
        seen: set[str] = set()
        result = []
        for p in patterns:
            p = p.strip()
            if p and p.lower() not in seen:
                seen.add(p.lower())
                result.append(p)
        return result

    def validate_for_scan(self) -> None:
        if not self.program.strip():
            raise ConfigError("scope 'program' is required")
        if len(self.authorization.strip()) < 10:
            raise ConfigError(
                "scope 'authorization' must describe the authorization basis "
                "(program policy, ticket, or engagement reference)"
            )
        if not (self.web or self.github.enabled or self.gitlab.enabled):
            raise ConfigError("scope must define at least one web target, GitHub org/repo, or GitLab project")
        if "INSUFFICIENT_EVIDENCE" == self.analysis.min_classification:
            raise ConfigError("min_classification must be CANDIDATE, HIGH_CONFIDENCE, or CONFIRMED")
        if self.analysis.min_classification not in CONFIDENCE_NAMES:
            raise ConfigError("min_classification has an unknown value")
        for target in self.web:
            parsed = urlparse(target.url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ConfigError(f"invalid web target URL: {target.url}")
        for repo in self.github.repos:
            if "/" not in repo or len(repo.split("/", 1)[1]) == 0:
                raise ConfigError(f"invalid GitHub repo (expected owner/name): {repo}")
        for project in self.gitlab.projects:
            if not project.strip():
                raise ConfigError("invalid empty GitLab project")

    def snapshot(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "authorization": self.authorization,
            "contact": self.contact,
            "web": [{"url": t.url, "include_subdomains": t.include_subdomains} for t in self.web],
            "github": {
                "orgs": list(self.github.orgs),
                "repos": list(self.github.repos),
                "include_history": self.github.include_history,
            },
            "gitlab": {"projects": list(self.gitlab.projects)},
            "registries": {
                "enabled": list(self.registries.enabled),
                "query_limit": self.registries.query_limit,
            },
            "analysis": {
                "org_patterns": self.org_patterns(),
                "min_classification": self.analysis.min_classification,
            },
        }


class ScopePolicy:
    """Enforces the declared authorization scope for every outbound request."""

    def __init__(self, scope: ScopeConfig) -> None:
        self.scope = scope
        self._web_hosts: list[tuple[str, bool, str]] = []
        self._web_ports: set[int] = {80, 443}
        self._exclusions = list(scope.crawl.exclude_paths)
        for target in scope.web:
            host = target.host
            if host:
                self._web_hosts.append((host, target.include_subdomains, target.site))
            port = urlparse(target.url).port
            if port:
                self._web_ports.add(port)

    @property
    def allow_private_hosts(self) -> bool:
        return self.scope.allow_private_hosts

    @property
    def registry_hosts(self) -> set[str]:
        hosts: set[str] = set()
        for eco in self.scope.enabled_ecosystems:
            hosts.update(REGISTRY_HOSTS.get(eco, ()))
        return hosts

    def web_host_allowed(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        for allowed, include_subdomains, _site in self._web_hosts:
            if host == allowed:
                return True
            if include_subdomains and host.endswith("." + allowed):
                return True
        return False

    def path_excluded(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._exclusions if prefix)

    def category(self, url: str) -> str | None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        try:
            port = parsed.port
        except ValueError:
            return None
        if port not in (None, 80, 443) and not self.scope.allow_private_hosts and port not in self._web_ports:
            return None
        if host in self.registry_hosts:
            return "registry"
        if host in GITHUB_API_HOSTS and self.scope.github.enabled:
            return "github"
        if host in GITLAB_API_HOSTS and self.scope.gitlab.enabled:
            return "gitlab"
        if self.web_host_allowed(host):
            if self.path_excluded(parsed.path or "/"):
                return None
            return "web"
        return None

    def is_url_allowed(self, url: str) -> bool:
        try:
            self.check_url(url)
            return True
        except ScopeViolation:
            return False

    def check_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            raise ScopeViolation("URLs with embedded credentials are not permitted")
        category = self.category(url)
        if category is None:
            host = parsed.hostname or "<none>"
            raise ScopeViolation(
                f"URL outside authorized scope: {host}{parsed.path or '/'} "
                f"(not a configured web host, GitHub/GitLab API, or enabled registry)"
            )
        return category

    def check_web_url(self, url: str) -> None:
        if self.category(url) != "web":
            raise ScopeViolation(f"not an authorized web URL: {url}")

    def github_repo_allowed(self, repo: str) -> bool:
        owner, _, name = repo.partition("/")
        if not owner or not name:
            return False
        repo_lower = f"{owner}/{name}".lower()
        if any(r.lower() == repo_lower for r in self.scope.github.repos):
            return True
        return any(org.lower() == owner.lower() for org in self.scope.github.orgs)

    def gitlab_project_allowed(self, project: str) -> bool:
        return any(p.strip("/").lower() == project.strip("/").lower() for p in self.scope.gitlab.projects)

    def same_site_web(self, url_or_host: str) -> bool:
        host = urlparse(url_or_host).hostname if "://" in url_or_host else url_or_host
        if not host:
            return False
        if self.web_host_allowed(host):
            return True
        site = registrable_domain(host.lower())
        return any(site == s for _h, _sub, s in self._web_hosts)

    def canonical(self, url: str) -> str:
        return canonical_url(url)


def load_scope(path: str | Path) -> ScopeConfig:
    scope_path = Path(path).expanduser()
    if not scope_path.exists():
        raise ConfigError(f"scope file not found: {scope_path}")
    try:
        raw = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read scope file {scope_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("scope file must be a YAML mapping")

    program = str(raw.get("program") or "").strip()
    authorization = str(raw.get("authorization") or "").strip()
    contact = str(raw.get("contact") or "").strip()
    allow_private = bool(raw.get("allow_private_hosts", False))

    web_raw = raw.get("web") or []
    if not isinstance(web_raw, list):
        raise ConfigError("scope 'web' must be a list")
    web: list[WebTarget] = []
    for entry in web_raw:
        if isinstance(entry, str):
            web.append(WebTarget(url=entry.strip(), include_subdomains=False))
        elif isinstance(entry, dict) and entry.get("url"):
            web.append(
                WebTarget(
                    url=str(entry["url"]).strip(),
                    include_subdomains=bool(entry.get("include_subdomains", False)),
                )
            )
        else:
            raise ConfigError("each web entry must be a URL string or a mapping with 'url'")

    crawl_raw = raw.get("crawl") or {}
    if not isinstance(crawl_raw, dict):
        raise ConfigError("scope 'crawl' must be a mapping")
    crawl = CrawlSettings()
    for name in ("max_depth", "max_urls", "concurrency"):
        if name in crawl_raw:
            value = crawl_raw[name]
            if not isinstance(value, int) or value < 0:
                raise ConfigError(f"crawl.{name} must be a non-negative integer")
            setattr(crawl, name, value)
    for name in ("requests_per_second",):
        if name in crawl_raw:
            value = crawl_raw[name]
            if not isinstance(value, (int, float)) or value < 0:
                raise ConfigError(f"crawl.{name} must be a non-negative number")
            setattr(crawl, name, float(value))
    for name in ("respect_robots", "source_maps", "probe_manifests"):
        if name in crawl_raw:
            setattr(crawl, name, bool(crawl_raw[name]))
    if isinstance(crawl_raw.get("exclude_paths"), list):
        crawl.exclude_paths = [str(p) for p in crawl_raw["exclude_paths"]]
    if isinstance(crawl_raw.get("probe_paths"), list):
        crawl.probe_paths = [str(p) for p in crawl_raw["probe_paths"]]

    github_raw = raw.get("github") or {}
    if not isinstance(github_raw, dict):
        raise ConfigError("scope 'github' must be a mapping")
    github = GitHubSettings()
    if isinstance(github_raw.get("orgs"), list):
        github.orgs = [str(o).strip() for o in github_raw["orgs"] if str(o).strip()]
    if isinstance(github_raw.get("repos"), list):
        github.repos = [str(r).strip() for r in github_raw["repos"] if str(r).strip()]
    for name in ("include_history", "include_forks", "include_archived"):
        if name in github_raw:
            setattr(github, name, bool(github_raw[name]))
    for name in ("history_commits_per_file", "max_repos", "max_files_per_repo"):
        if name in github_raw and isinstance(github_raw[name], int) and github_raw[name] >= 0:
            setattr(github, name, github_raw[name])

    gitlab_raw = raw.get("gitlab") or {}
    if not isinstance(gitlab_raw, dict):
        raise ConfigError("scope 'gitlab' must be a mapping")
    gitlab = GitLabSettings()
    if isinstance(gitlab_raw.get("projects"), list):
        gitlab.projects = [str(p).strip() for p in gitlab_raw["projects"] if str(p).strip()]
    if "include_history" in gitlab_raw:
        gitlab.include_history = bool(gitlab_raw["include_history"])
    if isinstance(gitlab_raw.get("max_files_per_project"), int):
        gitlab.max_files_per_project = int(gitlab_raw["max_files_per_project"])

    reg_raw = raw.get("registries") or {}
    if not isinstance(reg_raw, dict):
        raise ConfigError("scope 'registries' must be a mapping")
    registries = RegistrySettings()
    if isinstance(reg_raw.get("enabled"), list):
        registries.enabled = [str(e).lower() for e in reg_raw["enabled"]]
        unknown = [e for e in registries.enabled if e not in REGISTRY_HOSTS]
        if unknown:
            raise ConfigError(f"unsupported registries: {', '.join(unknown)}")
    if isinstance(reg_raw.get("query_limit"), int):
        if reg_raw["query_limit"] < 1:
            raise ConfigError("registries.query_limit must be >= 1")
        registries.query_limit = reg_raw["query_limit"]
    if isinstance(reg_raw.get("cache_ttl_hours"), int) and reg_raw["cache_ttl_hours"] >= 0:
        registries.cache_ttl_hours = reg_raw["cache_ttl_hours"]
    if isinstance(reg_raw.get("requests_per_second"), (int, float)) and reg_raw["requests_per_second"] > 0:
        registries.requests_per_second = float(reg_raw["requests_per_second"])

    analysis_raw = raw.get("analysis") or {}
    if not isinstance(analysis_raw, dict):
        raise ConfigError("scope 'analysis' must be a mapping")
    analysis = AnalysisSettings()
    if isinstance(analysis_raw.get("org_patterns"), list):
        analysis.org_patterns = [str(p).strip() for p in analysis_raw["org_patterns"] if str(p).strip()]
    if isinstance(analysis_raw.get("internal_keywords"), list):
        analysis.internal_keywords = [
            str(k).strip() for k in analysis_raw["internal_keywords"] if str(k).strip()
        ]
    if isinstance(analysis_raw.get("min_classification"), str):
        analysis.min_classification = analysis_raw["min_classification"].upper()

    scope = ScopeConfig(
        program=program,
        authorization=authorization,
        contact=contact,
        allow_private_hosts=allow_private,
        web=web,
        crawl=crawl,
        github=github,
        gitlab=gitlab,
        registries=registries,
        analysis=analysis,
        source_path=scope_path,
    )
    for target in scope.web:
        if "://" not in target.url:
            raise ConfigError(f"web target must include scheme: {target.url}")
    return scope
