from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

from dephunter.core.models import ConfigFact, DependencyRef, ResolutionAssessment
from dephunter.core.names import is_public_registry_host, normalize_pattern, parse_scoped_npm
from dephunter.core.util import registrable_domain

PUBLIC_REGISTRY_HOSTS = {
    "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "repo1.maven.org", "repo.maven.apache.org", "maven.google.com", "dl.google.com",
    "plugins.gradle.org", "jcenter.bintray.com",
    "api.nuget.org", "nuget.org",
    "proxy.golang.org", "sum.golang.org",
    "rubygems.org", "index.rubygems.org",
    "packagist.org", "repo.packagist.org",
    "crates.io", "index.crates.io", "static.crates.io",
    "hub.docker.com", "registry-1.docker.io",
}
_URL_RE = re.compile(r"(?:(?:sparse|git)\+)?(?:https?|ssh|git)://[^\s,;'\"()<>]+", re.I)
_BARE_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?", re.I)

REGISTRY_FACT_TYPES: dict[str, set[str]] = {
    "npm": {
        "npm_default_registry", "npm_scope_registry", "yarn_registry", "env_npm_registry",
    },
    "pypi": {
        "pip_index_url", "pip_extra_index_url", "pipfile_source", "poetry_source",
        "env_pip_index_url", "env_pip_extra_index_url", "pip_trusted_host", "pip_no_index",
    },
    "maven": {"maven_repository", "gradle_repository"},
    "nuget": {
        "nuget_package_source", "nuget_clear_sources", "nuget_disabled_source",
        "nuget_source_mapping",
    },
    "rubygems": {"gem_source"},
    "packagist": {
        "composer_repository", "composer_canonical_false", "composer_packagist_disabled",
    },
    "crates": {"cargo_registry", "cargo_source_replace", "cargo_source_registry"},
    "go": {"go_proxy", "go_private"},
    "docker": set(),
}


@dataclass(slots=True)
class HostClassification:
    public: bool = False
    private: bool = False
    unknown: bool = False
    hosts: list[str] = field(default_factory=list)

    def merge(self, other: "HostClassification") -> None:
        self.public = self.public or other.public
        self.private = self.private or other.private
        self.unknown = self.unknown or other.unknown
        for host in other.hosts:
            if host not in self.hosts:
                self.hosts.append(host)


def is_public_host(host: str) -> bool:
    value = (host or "").lower().strip(".")
    if not value:
        return False
    if value in PUBLIC_REGISTRY_HOSTS:
        return True
    return any(value.endswith("." + known) for known in PUBLIC_REGISTRY_HOSTS)


def extract_hosts(value: str) -> list[str]:
    hosts: list[str] = []
    for raw in _URL_RE.findall(value or ""):
        candidate = raw
        for prefix in ("sparse+", "git+"):
            if candidate.lower().startswith(prefix):
                candidate = candidate[len(prefix):]
        parsed = urlparse(candidate if "://" in candidate else "https://" + candidate)
        host = (parsed.hostname or "").lower()
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        for match in _BARE_HOST_RE.finditer(value or ""):
            host = match.group(1).lower()
            if host not in hosts:
                hosts.append(host)
    return hosts


def classify_registry_value(value: str) -> HostClassification:
    text = (value or "").strip()
    if not text:
        return HostClassification(unknown=True)
    result = HostClassification()
    hosts = extract_hosts(text)
    if not hosts:
        if text.lower() in {"mavenlocal", "local"}:
            result.private = True
        else:
            result.unknown = True
        return result
    for host in hosts:
        result.hosts.append(host)
        if is_public_host(host):
            result.public = True
        else:
            result.private = True
    return result


def registry_facts(ecosystem: str, facts: Iterable[ConfigFact]) -> list[ConfigFact]:
    allowed = REGISTRY_FACT_TYPES.get(ecosystem, set())
    return [fact for fact in facts if fact.ecosystem == ecosystem and fact.fact_type in allowed]


def resolved_url_class(ref: DependencyRef) -> HostClassification | None:
    if not ref.resolved_url:
        return None
    return classify_registry_value(ref.resolved_url)


def scope_key_for_url(url: str) -> str:
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if host == "github.com":
        parts = [part for part in path.split("/") if part]
        if len(parts) >= 2:
            return f"repo:{parts[0].lower()}/{parts[1].lower()}"
    if host in {"gitlab.com", "www.gitlab.com"}:
        prefix = path.split("/-/", 1)[0].strip("/")
        if prefix:
            return f"repo:{prefix.lower()}"
    if host:
        return f"host:{host}"
    return "unknown"


def ref_scope_key(ref: DependencyRef) -> str:
    if ref.repo:
        return f"repo:{ref.repo.strip('/').lower()}"
    return scope_key_for_url(ref.source_url)


def fact_scope_key(fact: ConfigFact) -> str:
    return scope_key_for_url(fact.source_url)


def _classify_facts(fact_list: Iterable[ConfigFact]) -> HostClassification:
    merged = HostClassification()
    for fact in fact_list:
        merged.merge(classify_registry_value(fact.value))
    return merged


def _resolution_from_refs(refs: Iterable[DependencyRef], res: ResolutionAssessment) -> None:
    for ref in refs:
        classification = resolved_url_class(ref)
        if classification is None:
            continue
        if classification.public:
            res.public_resolution_evidence = True
        if classification.private:
            res.private_resolution_evidence = True


def assess_resolution(
    ecosystem: str,
    name: str,
    refs: list[DependencyRef],
    facts: list[ConfigFact],
) -> ResolutionAssessment:
    res = ResolutionAssessment()
    _resolution_from_refs(refs, res)
    routing_facts = registry_facts(ecosystem, facts)

    if ecosystem == "npm":
        _route_npm(name, routing_facts, res)
    elif ecosystem == "pypi":
        _route_pypi(routing_facts, res)
    elif ecosystem == "maven":
        _route_maven(routing_facts, res)
    elif ecosystem == "nuget":
        _route_nuget(name, routing_facts, res)
    elif ecosystem == "rubygems":
        _route_rubygems(refs, routing_facts, res)
    elif ecosystem == "packagist":
        _route_packagist(routing_facts, res)
    elif ecosystem == "crates":
        _route_crates(name, refs, routing_facts, res)
    elif ecosystem == "go":
        _route_go(name, routing_facts, res)
    elif ecosystem == "docker":
        _route_docker(name, res)
    else:
        res.public_routing = None

    if res.public_resolution_evidence:
        res.public_routing = True
        if res.private_resolution_evidence:
            res.mixed_provenance = True
            res.notes.append("lockfile evidence contains both public and non-public resolution URLs")
    if res.private_routing and res.public_resolution_evidence:
        res.mixed_provenance = True
        res.notes.append("private registry configuration coexists with a public lockfile resolution URL")
    return res


def _route_npm(name: str, facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    scope, _bare = parse_scoped_npm(name) if name.startswith("@") else (None, name)
    scope_public = scope_private = False
    default_public = default_private = False
    unknown = False
    for fact in facts:
        classification = classify_registry_value(fact.value)
        unknown = unknown or classification.unknown
        if fact.fact_type == "npm_scope_registry":
            if scope and fact.extra.get("scope") == scope:
                scope_public = scope_public or classification.public
                scope_private = scope_private or classification.private
        else:
            default_public = default_public or classification.public
            default_private = default_private or classification.private
    if scope and (scope_public or scope_private):
        if scope_private and not scope_public:
            res.public_routing = False if not res.public_resolution_evidence else True
            res.private_routing = True
            res.notes.append(f"scope {scope} is pinned to a non-public npm registry")
        elif scope_public and not scope_private:
            res.public_routing = True
            res.private_routing = False
        else:
            res.public_routing = None
            res.private_routing = True
            res.notes.append(f"scope {scope} has conflicting public/private registry configuration")
        return
    if default_public and default_private:
        res.public_routing = None
        res.private_routing = True
        res.notes.append("multiple npm default registries configured; routing is ambiguous")
    elif default_private:
        res.public_routing = False
        res.private_routing = True
        res.notes.append("npm default registry is configured to a non-public host")
    elif default_public:
        res.public_routing = True
    else:
        res.public_routing = None if unknown else True
        if res.public_routing is True:
            res.notes.append("npm default public registry applies (no private registry configuration found)")


def _route_pypi(facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    no_index = any(fact.fact_type == "pip_no_index" and fact.value.lower() == "true" for fact in facts)
    index_urls = [fact for fact in facts if fact.fact_type == "pip_index_url"]
    source_urls = [
        fact for fact in facts
        if fact.fact_type in {"pipfile_source", "poetry_source", "pip_extra_index_url"}
    ]
    primary = _classify_facts(index_urls + [f for f in source_urls if f.fact_type in {"pipfile_source", "poetry_source"}])
    extras = _classify_facts([f for f in source_urls if f.fact_type == "pip_extra_index_url"])
    if no_index:
        res.public_routing = False
        res.private_routing = primary.private or extras.private
        res.notes.append("pip is configured with --no-index; no package index is reachable")
        return
    if index_urls:
        if primary.public:
            res.public_routing = True
        elif primary.private:
            res.public_routing = False
        else:
            res.public_routing = None
        res.private_routing = primary.private or extras.private
        if primary.private and not primary.public and extras.public:
            res.public_routing = True
            res.notes.append("private pip index is combined with a public extra index")
        elif primary.private and not primary.public:
            res.notes.append("pip index-url is non-public and no public index is configured")
    else:
        res.public_routing = True
        res.private_routing = extras.private
        if extras.private:
            res.notes.append("public PyPI remains the default index; a non-public extra index is also configured")
        elif primary.private:
            res.private_routing = True
            res.notes.append("a non-public package source is configured")
        else:
            res.notes.append("public PyPI is the default index (no index override found)")


def _route_maven(facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    classification = _classify_facts(facts)
    res.private_routing = classification.private
    if classification.public:
        res.public_routing = True
        res.notes.append("a public Maven repository is explicitly configured")
    elif classification.private:
        if any(fact.fact_type == "maven_repository" for fact in facts):
            res.public_routing = True
            res.notes.append("Maven Central remains a default repository while a private repository is configured")
        else:
            res.public_routing = None
            res.notes.append("only Gradle repositories were found; public repository availability is ambiguous")
    else:
        res.public_routing = True
        res.notes.append("Maven Central is assumed as the default repository")


def _nuget_match(name: str, pattern: str) -> bool:
    name_lower = name.lower()
    pattern_lower = pattern.strip().lower()
    if not pattern_lower:
        return False
    if pattern_lower.endswith("*"):
        return name_lower.startswith(pattern_lower[:-1])
    return fnmatch.fnmatch(name_lower, pattern_lower) or name_lower == pattern_lower


def _route_nuget(name: str, facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    source_facts = [fact for fact in facts if fact.fact_type == "nuget_package_source"]
    disabled = {
        fact.value.strip().lower()
        for fact in facts
        if fact.fact_type == "nuget_disabled_source" and fact.value.strip()
    }
    sources: dict[str, HostClassification] = {}
    for fact in source_facts:
        key, _, value = fact.value.partition("=")
        key = key.strip().lower()
        if not key or key in disabled:
            continue
        sources[key] = classify_registry_value(value)
    clear_sources = any(
        fact.fact_type == "nuget_clear_sources" and fact.value.lower() == "true" for fact in facts
    )
    source_public = any(item.public for item in sources.values())
    source_private = any(item.private for item in sources.values())

    mapping_class: HostClassification | None = None
    for fact in facts:
        if fact.fact_type != "nuget_source_mapping":
            continue
        pattern, _, source_keys = fact.value.partition("=")
        if not _nuget_match(name, pattern):
            continue
        mapped = [
            sources[key.strip().lower()]
            for key in re.split(r"[,;\s]+", source_keys)
            if key.strip().lower() in sources
        ]
        if mapped:
            mapping_class = HostClassification()
            for item in mapped:
                mapping_class.merge(item)

    if mapping_class is not None:
        res.public_routing = mapping_class.public and not mapping_class.private
        res.private_routing = mapping_class.private
        if mapping_class.private and not mapping_class.public:
            res.notes.append("NuGet packageSourceMapping pins this package ID to a non-public source")
        return
    res.private_routing = source_private
    if clear_sources and not source_public:
        res.public_routing = False
        res.notes.append("<clear/> removes nuget.org and no public NuGet source remains")
    elif source_public:
        res.public_routing = True
        res.notes.append("a public NuGet source is configured")
    else:
        res.public_routing = True
        res.notes.append("nuget.org remains a default source (sources were not cleared)")


def _route_rubygems(refs: list[DependencyRef], facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    global_class = _classify_facts(facts)
    ref_private = ref_public = False
    for ref in refs:
        block = ref.extra.get("source_block")
        if isinstance(block, str) and block:
            classification = classify_registry_value(block)
            ref_private = ref_private or classification.private
            ref_public = ref_public or classification.public
    res.private_routing = global_class.private or ref_private
    if ref_private and not ref_public and not res.public_resolution_evidence:
        res.public_routing = False
        res.notes.append("Gemfile source block pins this dependency to a non-public source")
    elif res.public_resolution_evidence:
        res.public_routing = True
    elif global_class.public or not facts:
        res.public_routing = True
        if not facts:
            res.notes.append("RubyGems.org is the default source (no source override found)")
    elif global_class.private:
        res.public_routing = False
        res.notes.append("only non-public gem sources are configured")
    else:
        res.public_routing = None


def _route_packagist(facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    repos = _classify_facts([fact for fact in facts if fact.fact_type == "composer_repository"])
    disabled = any(fact.fact_type == "composer_packagist_disabled" for fact in facts)
    fallback = any(
        fact.fact_type == "composer_canonical_false" or fact.value.lower() == "true"
        for fact in facts
        if fact.fact_type in {"composer_canonical_false", "composer_packagist_disabled"}
    )
    res.private_routing = repos.private
    if not disabled:
        res.public_routing = True
        res.notes.append("Packagist remains enabled for package resolution")
    elif fallback or repos.public:
        res.public_routing = True
        res.notes.append("Packagist fallback is enabled by canonical=false")
    else:
        res.public_routing = False
        res.notes.append("Packagist is disabled and only a non-public Composer repository is configured")


def _route_crates(
    name: str,
    refs: list[DependencyRef],
    facts: list[ConfigFact],
    res: ResolutionAssessment,
) -> None:
    registries: dict[str, HostClassification] = {}
    replacements: dict[str, str] = {}
    for fact in facts:
        if fact.fact_type == "cargo_registry":
            key, _, value = fact.value.partition("=")
            registries[key.strip().lower()] = classify_registry_value(value)
        elif fact.fact_type == "cargo_source_replace":
            source, _, target = fact.value.partition("=>")
            if source.strip().lower() == "crates-io":
                replacements["crates-io"] = target.strip().lower()
    replacement = replacements.get("crates-io")
    per_package_private = False
    for ref in refs:
        registry = ref.extra.get("registry")
        if isinstance(registry, str) and registry.strip():
            classification = registries.get(registry.strip().lower())
            if classification is not None:
                per_package_private = per_package_private or classification.private
    res.private_routing = per_package_private or any(item.private for item in registries.values())
    if per_package_private:
        res.public_routing = False
        res.notes.append("Cargo.toml pins this dependency to a non-public registry")
        return
    if replacement:
        classification = registries.get(replacement)
        if classification is None:
            res.public_routing = None
            res.private_routing = True
            res.notes.append("crates-io source replacement points at an unresolved registry")
        elif classification.private and not classification.public:
            res.public_routing = False
            res.private_routing = True
            res.notes.append("crates-io is replaced with a non-public registry")
        elif classification.public:
            res.public_routing = True
        else:
            res.public_routing = None
        return
    res.public_routing = True
    res.notes.append("crates.io is the default registry (no source replacement found)")


def _route_go(name: str, facts: list[ConfigFact], res: ResolutionAssessment) -> None:
    private_patterns: list[str] = []
    proxy_public = proxy_private = proxy_off = proxy_unknown = False
    for fact in facts:
        if fact.fact_type == "go_private":
            private_patterns.extend(p.strip() for p in fact.value.split(",") if p.strip())
        elif fact.fact_type == "go_proxy":
            for token in fact.value.split(","):
                token = token.strip()
                if not token:
                    continue
                if token.lower() == "off":
                    proxy_off = True
                else:
                    classification = classify_registry_value(token)
                    proxy_public = proxy_public or classification.public
                    proxy_private = proxy_private or classification.private
                    proxy_unknown = proxy_unknown or classification.unknown
    private_match = any(
        fnmatch.fnmatch(name.lower(), pattern.lower())
        or name.lower().startswith(pattern.rstrip("/").lower() + "/")
        for pattern in private_patterns
    )
    if private_match:
        res.public_routing = False
        res.private_routing = True
        res.notes.append("GOPRIVATE/GONOSUMDB matches this module path")
        return
    if proxy_off:
        res.public_routing = False
        res.private_routing = True
        res.notes.append("GOPROXY=off prevents module proxy resolution")
    elif proxy_public:
        res.public_routing = True
        res.private_routing = proxy_private
        res.notes.append("a public Go module proxy is configured")
    elif proxy_private:
        res.public_routing = False
        res.private_routing = True
    elif proxy_unknown:
        res.public_routing = None
    else:
        res.public_routing = True
        res.notes.append("proxy.golang.org is the default module proxy")


def _route_docker(name: str, res: ResolutionAssessment) -> None:
    value = name.strip()
    if value.startswith("docker.io/"):
        value = value[len("docker.io/"):]
    parts = value.split("/")
    if len(parts) >= 2:
        namespace = parts[0].lower()
        if namespace == "library":
            res.public_routing = None
            res.notes.append("official Docker Hub library images are not namespace-claimable")
        elif "." in namespace or ":" in namespace:
            res.public_routing = None
            res.notes.append("image is hosted outside Docker Hub")
        else:
            res.public_routing = True
            res.notes.append(f"Docker Hub namespace '{namespace}' participates in resolution")
    else:
        res.public_routing = None
        res.notes.append("unqualified image names resolve only to the official library namespace")


def docker_namespace_claimable(name: str) -> bool:
    value = name.strip()
    if value.startswith("docker.io/"):
        value = value[len("docker.io/"):]
    parts = value.split("/")
    if len(parts) < 2:
        return False
    namespace = parts[0].lower()
    return namespace != "library" and "." not in namespace and ":" not in namespace


def intent_signals(
    ecosystem: str,
    name: str,
    refs: list[DependencyRef],
    facts: list[ConfigFact],
    org_patterns: list[str],
    internal_keywords: list[str],
) -> tuple[bool, list[str]]:
    from dephunter.core.names import looks_internal

    intent, reasons = looks_internal(ecosystem, name, org_patterns, internal_keywords)
    reasons = list(reasons)

    for fact in facts:
        if fact.fact_type == "npm_private_package" and ecosystem == "npm":
            package = fact.extra.get("package")
            if isinstance(package, str) and normalize_pattern(package) == normalize_pattern(name):
                intent = True
                reasons.append("package is explicitly marked private in package.json")
        elif fact.fact_type == "nuget_source_mapping" and ecosystem == "nuget":
            pattern, _, source_keys = fact.value.partition("=")
            if _nuget_match(name, pattern) and source_keys.strip():
                intent = True
                reasons.append("NuGet packageSourceMapping treats this ID as internally sourced")
        elif fact.fact_type == "go_private" and ecosystem == "go":
            patterns = [p.strip() for p in fact.value.split(",") if p.strip()]
            if any(
                fnmatch.fnmatch(name.lower(), p.lower())
                or name.lower().startswith(p.rstrip("/").lower() + "/")
                for p in patterns
            ):
                intent = True
                reasons.append("GOPRIVATE/GONOSUMDB marks this module path as private")

    for ref in refs:
        classification = resolved_url_class(ref)
        if classification is not None and classification.private:
            host = classification.hosts[0] if classification.hosts else "non-public registry"
            intent = True
            reasons.append(f"lockfile resolved URL points to non-public host '{host}' (internal provenance)")
        block = ref.extra.get("source_block")
        if isinstance(block, str) and block:
            classification = classify_registry_value(block)
            if classification.private:
                intent = True
                reasons.append("Gemfile source block pins this dependency to a non-public source")
        registry = ref.extra.get("registry")
        if isinstance(registry, str) and registry.strip():
            for fact in facts:
                if fact.fact_type == "cargo_registry":
                    key, _, value = fact.value.partition("=")
                    if key.strip().lower() == registry.strip().lower():
                        classification = classify_registry_value(value)
                        if classification.private:
                            intent = True
                            reasons.append("Cargo.toml pins this dependency to a non-public registry")

    if ecosystem == "npm":
        scope, _bare = parse_scoped_npm(name) if name.startswith("@") else (None, name)
        if scope:
            for fact in facts:
                if fact.fact_type == "npm_scope_registry" and fact.extra.get("scope") == scope:
                    classification = classify_registry_value(fact.value)
                    if classification.private:
                        intent = True
                        reasons.append(f"scope {scope} is served by a configured non-public registry")
    return intent, list(dict.fromkeys(reasons))


def registrable_host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return registrable_domain(host) if host else ""


def is_public_registry_url(ecosystem: str, url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and (is_public_registry_host(host, ecosystem) or is_public_host(host))
