from __future__ import annotations

import re
from typing import Any

from dephunter.core.models import ExtractionResult
from dephunter.core.names import npm_spec_info, parse_scoped_npm
from dephunter.core.util import decode_text
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

_DEP_FIELDS = {
    "dependencies": ["runtime"],
    "devDependencies": ["dev"],
    "optionalDependencies": ["optional"],
    "peerDependencies": ["peer"],
}


class NpmManifestExtractor(BaseExtractor):
    ecosystem = "npm"
    filenames = ("package.json",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            data, text = parse_json(content)
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"invalid package.json: {exc}")
            return result
        if not isinstance(data, dict):
            result.warnings.append("package.json root is not an object")
            return result
        loc = locator(text)
        root_name = data.get("name")
        if isinstance(root_name, str) and root_name.strip():
            result.names_local_to_project.add(root_name.strip())
        for field_name, groups in _DEP_FIELDS.items():
            deps = data.get(field_name)
            if not isinstance(deps, dict):
                continue
            for raw_name, spec in deps.items():
                if not isinstance(raw_name, str) or not isinstance(spec, str):
                    continue
                info = npm_spec_info(spec)
                package_name = raw_name
                extra: dict[str, Any] = {"field": field_name}
                version = spec
                if info.get("alias_target"):
                    target = str(info["alias_target"])
                    if target.startswith("@"):
                        idx = target.rfind("@")
                        package_name = target[:idx] if idx > 0 else target
                        version = target[idx + 1:] if idx > 0 else "*"
                    else:
                        package_name = target.split("@", 1)[0]
                        version = target.split("@", 1)[1] if "@" in target else "*"
                    extra["alias_of"] = raw_name
                elif info.get("explicit_source"):
                    extra["explicit_source_spec"] = version
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "npm",
                        package_name,
                        version,
                        line=loc.find(f'"{raw_name}"'),
                        explicit_source=bool(info.get("explicit_source")),
                        direct=True,
                        groups=groups,
                        extra=extra,
                    )
                )
        for field_name in ("overrides", "resolutions"):
            overrides = data.get(field_name)
            if isinstance(overrides, dict):
                for name, spec in overrides.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        result.config_facts.append(
                            make_fact(
                                ctx,
                                "npm",
                                "npm_override",
                                f"{name}@{spec}"[:500],
                                line=loc.find(f'"{name}"'),
                                extra={"field": field_name},
                            )
                        )
        if data.get("private") is True:
            result.config_facts.append(
                make_fact(ctx, "npm", "npm_private_package", "true", extra={"package": root_name})
            )
        return result


class NpmLockExtractor(BaseExtractor):
    ecosystem = "npm"
    filenames = ("package-lock.json", "npm-shrinkwrap.json")
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            data, _text = parse_json(content)
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"invalid npm lockfile: {exc}")
            return result
        if not isinstance(data, dict):
            result.warnings.append("npm lockfile root is not an object")
            return result
        packages = data.get("packages")
        if isinstance(packages, dict):
            root = packages.get("") if isinstance(packages.get(""), dict) else {}
            direct_names: set[str] = set()
            for section in _DEP_FIELDS:
                entries = root.get(section)
                if isinstance(entries, dict):
                    direct_names.update(k for k in entries if isinstance(k, str))
            for path, info in packages.items():
                if not isinstance(info, dict) or not path:
                    continue
                if info.get("link") is True:
                    local_name = info.get("name")
                    if isinstance(local_name, str):
                        result.names_local_to_project.add(local_name)
                    continue
                name = info.get("name")
                if not isinstance(name, str):
                    name = _name_from_node_modules_path(path)
                if not name:
                    continue
                version = info.get("version") if isinstance(info.get("version"), str) else None
                resolved = info.get("resolved") if isinstance(info.get("resolved"), str) else None
                groups = []
                if info.get("dev"):
                    groups.append("dev")
                if info.get("optional"):
                    groups.append("optional")
                if info.get("peer"):
                    groups.append("peer")
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "npm",
                        name,
                        version,
                        role="lockfile",
                        resolved_url=sanitize_url_credentials(resolved) if resolved else None,
                        direct=name in direct_names,
                        groups=groups,
                        extra={"path": path, "integrity": info.get("integrity")},
                    )
                )
            return result
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            _walk_v1(dependencies, result, ctx, depth=0)
        return result


def _name_from_node_modules_path(path: str) -> str | None:
    segments = path.split("node_modules/")
    if len(segments) < 2:
        return None
    tail = segments[-1].strip("/")
    parts = tail.split("/")
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _walk_v1(dependencies: dict, result: ExtractionResult, ctx: ExtractContext, depth: int) -> None:
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version") if isinstance(info.get("version"), str) else None
        resolved = info.get("resolved") if isinstance(info.get("resolved"), str) else None
        dev = bool(info.get("dev"))
        result.dependencies.append(
            make_dep(
                ctx,
                "npm",
                name,
                version,
                role="lockfile",
                resolved_url=sanitize_url_credentials(resolved) if resolved else None,
                direct=depth == 0,
                groups=["dev"] if dev else [],
                extra={"v1_depth": depth},
            )
        )
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(nested, result, ctx, depth + 1)


class NpmConfigExtractor(BaseExtractor):
    ecosystem = "npm"
    filenames = (".npmrc", ".yarnrc", "pnpm-workspace.yaml")
    globs = (".yarnrc.yml",)
    role = "config"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        if ctx_name.lower().endswith((".yml", ".yaml")):
            _parse_yarn_yml(text, result, ctx)
            return result
        if ctx_name.lower().endswith("pnpm-workspace.yaml"):
            return result
        if ctx_name.lower() == ".yarnrc":
            for idx, raw in enumerate(text.splitlines(), 1):
                match = re.match(r"\s*registry\s+[\"']([^\"']+)[\"']", raw)
                if match:
                    result.config_facts.append(make_fact(ctx, "npm", "yarn_registry", match.group(1), line=idx))
            return result
        for idx, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            lower_key = key.lower()
            if lower_key == "registry":
                result.config_facts.append(
                    make_fact(ctx, "npm", "npm_default_registry", sanitize_url_credentials(value), line=idx)
                )
            elif lower_key.endswith(":registry"):
                scope = key.rsplit(":registry", 1)[0]
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "npm",
                        "npm_scope_registry",
                        sanitize_url_credentials(value),
                        line=idx,
                        extra={"scope": scope},
                    )
                )
            elif lower_key.endswith(":_authtoken") or lower_key.endswith(":_auth") or lower_key.endswith(":_password"):
                host = key.split("/", 1)[0].lstrip("/")
                result.config_facts.append(
                    make_fact(ctx, "npm", "npm_registry_auth_present", "[REDACTED]", line=idx, extra={"host": host})
                )
            elif lower_key == "always-auth":
                result.config_facts.append(make_fact(ctx, "npm", "npm_always_auth", value, line=idx))
        return result


def _parse_yarn_yml(text: str, result: ExtractionResult, ctx: ExtractContext) -> None:
    from dephunter.extractors.base import yaml_load_safe

    try:
        data = yaml_load_safe(text)
    except Exception as exc:
        result.warnings.append(f"invalid .yarnrc.yml: {exc}")
        return
    if not isinstance(data, dict):
        return
    loc = locator(text)
    server = data.get("npmRegistryServer")
    if isinstance(server, str):
        result.config_facts.append(
            make_fact(ctx, "npm", "yarn_registry", sanitize_url_credentials(server), line=loc.find("npmRegistryServer"))
        )
    scopes = data.get("npmScopes")
    if isinstance(scopes, dict):
        for scope, cfg in scopes.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("npmRegistryServer"), str):
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "npm",
                        "npm_scope_registry",
                        sanitize_url_credentials(cfg["npmRegistryServer"]),
                        line=loc.find(str(scope)),
                        extra={"scope": f"@{str(scope).lstrip('@')}", "manager": "yarn-berry"},
                    )
                )


class YarnLockExtractor(BaseExtractor):
    ecosystem = "npm"
    filenames = ("yarn.lock",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        current_names: list[str] = []
        current: dict[str, str] = {}
        for raw in text.splitlines() + [""]:
            if not raw.strip():
                if current_names:
                    for name in current_names:
                        result.dependencies.append(
                            make_dep(
                                ctx,
                                "npm",
                                name,
                                current.get("version"),
                                role="lockfile",
                                resolved_url=current.get("resolved"),
                                direct=False,
                                extra={"manager": "yarn-classic"},
                            )
                        )
                current_names, current = [], {}
                continue
            if not raw.startswith((" ", "\t")):
                header = raw.strip().rstrip(":")
                selectors = [s.strip().strip('"') for s in header.split(",")]
                current_names = []
                for selector in selectors:
                    name = _name_from_selector(selector)
                    if name and name not in current_names:
                        current_names.append(name)
                continue
            stripped = raw.strip()
            if stripped.startswith("version "):
                current["version"] = stripped.split(" ", 1)[1].strip().strip('"')
            elif stripped.startswith("resolved "):
                current["resolved"] = stripped.split(" ", 1)[1].strip().strip('"')
        return result


def _name_from_selector(selector: str) -> str | None:
    selector = selector.strip()
    if not selector:
        return None
    if selector.startswith("@"):
        at = selector.rfind("@")
        if at <= 0:
            return None
        name = selector[:at]
        _, bare = parse_scoped_npm(name)
        return name if bare else None
    name = selector.split("@", 1)[0]
    return name or None


class PnpmLockExtractor(BaseExtractor):
    ecosystem = "npm"
    filenames = ("pnpm-lock.yaml",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        from dephunter.extractors.base import yaml_load_safe

        result = ExtractionResult()
        try:
            data = yaml_load_safe(decode_text(content))
        except Exception as exc:
            result.warnings.append(f"invalid pnpm lockfile: {exc}")
            return result
        if not isinstance(data, dict):
            return result
        packages = data.get("packages")
        direct: set[str] = set()
        importers = data.get("importers")
        if isinstance(importers, dict):
            root = importers.get(".")
            if isinstance(root, dict):
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    entries = root.get(section)
                    if isinstance(entries, dict):
                        direct.update(entries.keys())
        if isinstance(packages, dict):
            for key, info in packages.items():
                if not isinstance(key, str) or not isinstance(info, dict):
                    continue
                parsed = _parse_pnpm_key(key)
                if not parsed:
                    continue
                name, version = parsed
                if info.get("dev") is True:
                    groups = ["dev"]
                else:
                    groups = []
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "npm",
                        name,
                        version,
                        role="lockfile",
                        direct=name in direct,
                        groups=groups,
                        extra={"manager": "pnpm", "pnpm_key": key[:200]},
                    )
                )
        return result


def _parse_pnpm_key(key: str) -> tuple[str, str | None] | None:
    value = key.lstrip("/")
    if not value:
        return None
    if value.startswith("@") or value.startswith("file:") or value.startswith("link:"):
        if value.startswith(("file:", "link:")):
            return None
        at = value.find("@", 1)
        if at < 0:
            return None
        name = value[:at]
        rest = value[at + 1:]
    else:
        name, _, rest = value.partition("@")
    if "(" in rest:
        rest = rest.split("(", 1)[0]
    version = rest or None
    if not name or name.startswith("."):
        return None
    return name, version
