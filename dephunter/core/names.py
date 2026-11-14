from __future__ import annotations

import re
from urllib.parse import urlparse

from dephunter.core.models import RegistryResult

_SCOPED_NPM = re.compile(r"^(@[a-z0-9][a-z0-9._-]*)/([a-z0-9][a-z0-9._-]*)$", re.I)
_PY_SPEC = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\[(?P<extras>[^\]]*)\])?
    \s*
    (?P<spec>.*)
    $""",
    re.X,
)
_NORMALIZE_SEP = re.compile(r"[-_.]+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

NPM_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs",
    "http", "http2", "https", "inspector", "module", "net", "os", "path",
    "perf_hooks", "process", "punycode", "querystring", "readline", "repl",
    "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
}

COMMON_PUBLIC_SCOPES = {
    "babel", "typescript", "angular", "vue", "sentry", "sentry-internal",
    "eslint", "eslint-community", "rollup", "webpack", "vitejs", "swc",
    "storybook", "testing-library", "jest", "playwright", "puppeteer",
    "next", "vercel", "nuxt", "sveltejs", "emotion", "mui", "chakra-ui",
    "radix-ui", "headlessui", "heroicons", "tailwindcss", "floating-ui",
    "tanstack", "apollo", "graphql", "prisma", "supabase", "firebase",
    "aws-sdk", "aws-crypto", "smithy", "google-cloud", "googleapis",
    "azure", "microsoft", "opentelemetry", "grpc", "protobufjs", "popperjs",
    "isaacs", "npmcli", "pnpm", "yarnpkg", "octokit", "actions", "bazel",
    "capacitor", "ionic", "expo", "react-native", "react-native-community",
    "react-navigation", "reduxjs", "testing-library", "types", "tsconfig",
    "esbuild", "parcel", "rsbuild", "rspack", "module-federation",
}

INTERNAL_HEURISTIC_MIN_LEN = 3


def normalize_package_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if ecosystem == "npm":
        return value.lower()
    if ecosystem == "pypi":
        return _NORMALIZE_SEP.sub("-", value).lower()
    if ecosystem in {"nuget", "crates", "packagist", "docker"}:
        return value.lower()
    if ecosystem == "rubygems":
        return value.lower()
    if ecosystem == "maven":
        return value.lower()
    return value


def split_python_spec(spec: str) -> tuple[str, str | None, str | None]:
    """Return (name, version_requirement, extras). Returns empty name if unparseable."""
    s = spec.strip()
    if not s or s.startswith(("-", "#")):
        return "", None, None
    if " @ " in s:
        name_part, _, url_part = s.partition(" @ ")
        match = _PY_SPEC.match(name_part.strip())
        if not match:
            return "", None, None
        return match.group("name"), f"@ {url_part.strip()}", match.group("extras")
    match = _PY_SPEC.match(s)
    if not match:
        return "", None, None
    name = match.group("name")
    remainder = match.group("spec").strip()
    version = remainder or None
    return name, version, match.group("extras")


def npm_spec_info(spec: str) -> dict[str, str | bool | None]:
    value = (spec or "").strip()
    info: dict[str, str | bool | None] = {
        "explicit_source": False,
        "alias_target": None,
        "version": value or None,
    }
    lower = value.lower()
    if lower.startswith("npm:"):
        target = value[4:].strip()
        if target.startswith("@"):
            version_sep = target.rfind("@")
            if version_sep > 0:
                package = target[:version_sep]
                version = target[version_sep + 1:]
            else:
                package, version = target, None
        else:
            package, _, version = target.partition("@")
            version = version or None
        info["alias_target"] = f"{package}@{version}" if version else package
        info["version"] = version or "*"
        info["explicit_source"] = False
        return info
    for prefix in ("file:", "link:", "workspace:", "portal:", "git+", "git:", "github:", "http://", "https://", "ssh://"):
        if lower.startswith(prefix):
            info["explicit_source"] = True
            return info
    return info


def parse_scoped_npm(name: str) -> tuple[str | None, str]:
    match = _SCOPED_NPM.match(name)
    if not match:
        return None, name
    return match.group(1), match.group(2)


def package_tokens(name: str) -> list[str]:
    scope, bare = parse_scoped_npm(name) if name.startswith("@") else (None, name)
    tokens: list[str] = []
    if scope:
        tokens.extend(_NON_ALNUM.split(scope.lstrip("@").lower()))
    tokens.extend(_NON_ALNUM.split(bare.lower()))
    return [t for t in tokens if t]


def normalize_pattern(value: str) -> str:
    return _NON_ALNUM.sub("", value.lower())


def looks_internal(
    ecosystem: str,
    name: str,
    org_patterns: list[str],
    internal_keywords: list[str],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    norm_name = name.lower()
    scope, _bare = parse_scoped_npm(name) if ecosystem == "npm" else (None, None)
    tokens = package_tokens(name)
    joined_tokens = "".join(tokens)
    scope_norm = normalize_pattern(scope.lstrip("@")) if scope else ""

    for pattern in org_patterns:
        norm = normalize_pattern(pattern)
        if len(norm) < INTERNAL_HEURISTIC_MIN_LEN:
            continue
        if scope_norm and (scope_norm == norm or norm in scope_norm):
            reasons.append(f"scope '{scope}' matches organization pattern '{pattern}'")
            break
        if len(norm_name) <= 64 and (norm in joined_tokens or (len(norm) >= 4 and norm in normalize_pattern(norm_name))):
            reasons.append(f"package name matches organization pattern '{pattern}'")
            break

    keyword_hits = []
    token_set = set(tokens)
    for keyword in internal_keywords:
        norm = normalize_pattern(keyword)
        if not norm:
            continue
        if norm in token_set or (len(norm) >= 5 and norm in joined_tokens):
            keyword_hits.append(keyword)
    if keyword_hits:
        reasons.append("name contains internal keyword(s): " + ", ".join(sorted(set(keyword_hits))))

    if ecosystem == "npm" and scope and scope.lstrip("@").lower() not in COMMON_PUBLIC_SCOPES:
        if not reasons:
            reasons.append(f"non-vendor scoped package '{scope}/{_bare}'")
    if ecosystem == "docker":
        if "internal" in norm_name or "private" in norm_name:
            reasons.append("image name contains internal keyword")
    return bool(reasons), reasons


def relation_to_target(registry: RegistryResult | None, org_patterns: list[str]) -> str:
    """Classify whether public package metadata links the package to the target."""
    if registry is None or not registry.exists:
        return "UNKNOWN"
    haystack_parts = [
        registry.publisher or "",
        registry.publisher_url or "",
        registry.repository_url or "",
    ]
    haystack = " ".join(haystack_parts).lower()
    if not any(haystack_parts):
        return "UNKNOWN"
    for pattern in org_patterns:
        norm = normalize_pattern(pattern)
        if len(norm) < INTERNAL_HEURISTIC_MIN_LEN:
            continue
        if pattern.lower() in haystack or norm in normalize_pattern(haystack):
            return "OWN_LIKELY"
    repo = (registry.repository_url or "").lower()
    parsed = urlparse(repo) if repo else None
    if parsed and parsed.hostname and any(p.lower() in parsed.hostname for p in org_patterns if len(p) >= 4):
        return "OWN_LIKELY"
    return "UNRELATED"


def is_public_registry_host(host: str, ecosystem: str) -> bool:
    host = (host or "").lower()
    mapping = {
        "npm": "registry.npmjs.org",
        "pypi": "pypi.org",
        "rubygems": "rubygems.org",
        "crates": "crates.io",
        "packagist": "repo.packagist.org",
        "maven": "repo1.maven.org",
        "nuget": "api.nuget.org",
        "go": "proxy.golang.org",
        "docker": "registry-1.docker.io",
    }
    needle = mapping.get(ecosystem)
    if not needle:
        return False
    return host == needle or host.endswith("." + needle) or (needle == "pypi.org" and host == "files.pythonhosted.org")


def is_explicit_safe_python_spec(version: str | None) -> bool:
    if not version:
        return False
    lowered = version.lower()
    return lowered.startswith(("@ ", "-e ", "git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:"))


def is_explicit_safe_gem_source(options: list[str]) -> bool:
    joined = " ".join(options).lower()
    return any(x in joined for x in ("github:", "git:", "path:", "file:", "source:"))
