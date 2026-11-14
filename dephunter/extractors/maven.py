from __future__ import annotations

import xml.etree.ElementTree as ET

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    child_text,
    locator,
    local_name,
    make_dep,
    make_fact,
    parse_xml,
    sanitize_url_credentials,
)

_SKIP_SCOPES = {"test", "provided", "import"}


class MavenPomExtractor(BaseExtractor):
    ecosystem = "maven"
    filenames = ("pom.xml",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            root, text = parse_xml(content)
        except (ValueError, ET.ParseError) as exc:
            result.warnings.append(f"invalid pom.xml: {exc}")
            return result
        loc = locator(text)
        properties: dict[str, str] = {}
        parent = _child(root, "parent")
        if parent is not None:
            for key in ("groupId", "version"):
                value = child_text(parent, key)
                if value:
                    properties[f"project.{key}"] = value
        group = child_text(root, "groupId")
        version = child_text(root, "version")
        artifact = child_text(root, "artifactId")
        if group:
            properties.setdefault("project.groupId", group)
        if version:
            properties.setdefault("project.version", version)
        props_el = _child(root, "properties")
        if props_el is not None:
            for child in props_el:
                key = local_name(child.tag)
                if child.text and child.text.strip():
                    properties[key] = child.text.strip()
        if group:
            properties.setdefault("project.parent.groupId", properties.get("project.groupId", group))
        if not group and parent is not None:
            group = child_text(parent, "groupId")
        if not version and parent is not None:
            version = child_text(parent, "version")
        managed: dict[str, str | None] = {}
        dep_mgmt = _child(root, "dependencyManagement")
        if dep_mgmt is not None:
            deps_el = _child(dep_mgmt, "dependencies")
            if deps_el is not None:
                for dep in _children(deps_el, "dependency"):
                    g = _resolve(child_text(dep, "groupId"), properties)
                    a = _resolve(child_text(dep, "artifactId"), properties)
                    v = _resolve(child_text(dep, "version"), properties)
                    if g and a:
                        managed[f"{g}:{a}"] = v

        dependencies: list[tuple[str, str, str | None, str, bool, bool, bool]] = []
        deps_el = _child(root, "dependencies")
        if deps_el is not None:
            for dep in _children(deps_el, "dependency"):
                g = _resolve(child_text(dep, "groupId"), properties)
                a = _resolve(child_text(dep, "artifactId"), properties)
                raw_version = child_text(dep, "version")
                v = _resolve(raw_version, properties)
                scope = (child_text(dep, "scope") or "compile").lower()
                dep_type = (child_text(dep, "type") or "jar").lower()
                optional = (child_text(dep, "optional") or "").lower() == "true"
                is_local = scope == "system"
                if scope == "import" or dep_type == "pom":
                    if g and a:
                        result.config_facts.append(
                            make_fact(
                                ctx,
                                "maven",
                                "maven_bom_import",
                                f"{g}:{a}:{v or ''}",
                                line=loc.find(f"<artifactId>{a}</artifactId>"),
                            )
                        )
                    continue
                if not g or not a:
                    continue
                managed_version = False
                if not v:
                    v = managed.get(f"{g}:{a}")
                    managed_version = v is not None
                dependencies.append((g, a, v, scope, is_local, managed_version, optional))

        for g, a, v, scope, is_local, managed_version, optional in dependencies:
            line = loc.find(f"<artifactId>{a}</artifactId>")
            groups = dependencies_groups(scope, is_local)
            if optional:
                groups.append("optional")
            result.dependencies.append(
                make_dep(
                    ctx,
                    "maven",
                    f"{g}:{a}",
                    v,
                    line=line,
                    explicit_source=is_local,
                    direct=True,
                    groups=groups,
                    extra={
                        "groupId": g,
                        "artifactId": a,
                        "resolved_version": bool(v),
                        "managed": managed_version,
                        "optional": optional,
                    },
                )
            )

        for repositories in ("repositories", "pluginRepositories"):
            repos_el = _child(root, repositories)
            if repos_el is None:
                continue
            for repo in _children(repos_el, "repository"):
                url = child_text(repo, "url")
                repo_id = child_text(repo, "id") or ""
                if url:
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "maven",
                            "maven_repository",
                            sanitize_url_credentials(url),
                            line=loc.find("<url>"),
                            extra={"id": repo_id, "releases": child_text(repo, "releases")},
                        )
                    )
        if group and artifact and version:
            result.names_local_to_project.add(f"{group}:{artifact}")
        return result


def dependencies_groups(scope: str, is_local: bool) -> list[str]:
    groups = ["runtime"]
    if scope in {"test", "provided"}:
        groups = [scope]
    if is_local:
        groups.append("system-local")
    return groups


def _resolve(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None
    current = value
    for _ in range(6):
        if "${" not in current:
            return current
        changed = False
        for key, replacement in properties.items():
            token = "${" + key + "}"
            if token in current:
                current = current.replace(token, replacement)
                changed = True
        if not changed:
            return None
    return current if "${" not in current else None


def _child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if local_name(child.tag) == name:
            return child
    return None


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if local_name(child.tag) == name]
