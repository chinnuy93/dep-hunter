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


class NugetProjectExtractor(BaseExtractor):
    ecosystem = "nuget"
    suffixes = (".csproj", ".fsproj", ".vbproj")
    filenames = ("Directory.Packages.props",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            root, text = parse_xml(content)
        except (ValueError, ET.ParseError) as exc:
            result.warnings.append(f"invalid NuGet project: {exc}")
            return result
        loc = locator(text)
        central = False
        for element in root.iter():
            if local_name(element.tag) == "ManagePackageVersionsCentrally":
                central = (element.text or "").strip().lower() == "true"
        if central:
            result.config_facts.append(
                make_fact(ctx, "nuget", "nuget_central_package_management", "true", line=loc.find("ManagePackageVersionsCentrally"))
            )
        for element in root.iter():
            tag = local_name(element.tag)
            if tag == "PackageReference":
                name = element.attrib.get("Include") or element.attrib.get("Update")
                if not name:
                    continue
                version = element.attrib.get("Version")
                if not version:
                    version = child_text(element, "Version")
                if not version:
                    version = element.attrib.get("VersionOverride")
                groups = ["runtime"]
                private_assets = child_text(element, "PrivateAssets") or element.attrib.get("PrivateAssets")
                if private_assets and "all" in private_assets.lower():
                    groups.append("private-assets")
                if (child_text(element, "Condition") or element.attrib.get("Condition") or "").lower().find("test") >= 0:
                    groups.append("test")
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "nuget",
                        name,
                        version,
                        line=loc.find(f'Include="{name}"') or loc.find(name),
                        direct=True,
                        groups=groups,
                        extra={"central_version": version is None},
                    )
                )
            elif tag == "PackageVersion":
                name = element.attrib.get("Include") or element.attrib.get("Update")
                version = element.attrib.get("Version") or child_text(element, "Version")
                if name:
                    result.dependencies.append(
                        make_dep(
                            ctx,
                            "nuget",
                            name,
                            version,
                            line=loc.find(f'Include="{name}"') or loc.find(name),
                            direct=True,
                            groups=["central-version"],
                            extra={"central_definition": True},
                        )
                    )
            elif tag == "ProjectReference":
                include = element.attrib.get("Include")
                if include:
                    stem = include.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
                    result.names_local_to_project.add(stem)
        return result


class NugetPackagesConfigExtractor(BaseExtractor):
    ecosystem = "nuget"
    filenames = ("packages.config",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            root, text = parse_xml(content)
        except (ValueError, ET.ParseError) as exc:
            result.warnings.append(f"invalid packages.config: {exc}")
            return result
        loc = locator(text)
        for element in root.iter():
            if local_name(element.tag) != "package":
                continue
            name = element.attrib.get("id")
            version = element.attrib.get("version")
            if name:
                result.dependencies.append(
                    make_dep(
                        ctx,
                        "nuget",
                        name,
                        version,
                        line=loc.find(f'id="{name}"'),
                        direct=True,
                        groups=["runtime"],
                        extra={"targetFramework": element.attrib.get("targetFramework")},
                    )
                )
        return result


class NugetConfigExtractor(BaseExtractor):
    ecosystem = "nuget"
    globs = ("nuget.config", "NuGet.config", "NuGet.Config", "*.nuget.config")
    filenames = ("nuget.config", "NuGet.config", "NuGet.Config")
    role = "config"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        try:
            root, text = parse_xml(content)
        except (ValueError, ET.ParseError) as exc:
            result.warnings.append(f"invalid nuget.config: {exc}")
            return result
        loc = locator(text)
        for element in root.iter():
            tag = local_name(element.tag)
            if tag == "add" and (element.attrib.get("key") or "").lower() in {"repositorypath"}:
                continue
            if tag == "packageSources":
                continue
            if tag == "add" and "value" in element.attrib:
                parent_tag = ""
                for ancestor in root.iter():
                    for child in ancestor:
                        if child is element:
                            parent_tag = local_name(ancestor.tag)
                key = element.attrib.get("key", "")
                value = element.attrib.get("value", "")
                if parent_tag == "packageSources" or value.startswith(("http://", "https://")):
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "nuget",
                            "nuget_package_source",
                            f"{key}={sanitize_url_credentials(value)}",
                            line=loc.find(f'key="{key}"'),
                            extra={"key": key},
                        )
                    )
            if tag == "clear" and local_name(_parent_of(root, element).tag) == "packageSources":
                result.config_facts.append(make_fact(ctx, "nuget", "nuget_clear_sources", "true", line=loc.find("<clear")))
            if tag == "packageSourceMapping":
                mappings: dict[str, list[str]] = {}
                for add in element.iter():
                    if local_name(add.tag) not in {"add", "package"}:
                        continue
                    if local_name(add.tag) == "add":
                        pattern = add.attrib.get("key", "")
                        source = add.attrib.get("value", "")
                    else:
                        pattern = add.attrib.get("pattern", "")
                        parent = _parent_of(root, add)
                        source = parent.attrib.get("key", "")
                    if pattern and source:
                        mappings.setdefault(pattern, [])
                        if source not in mappings[pattern]:
                            mappings[pattern].append(source)
                for pattern, sources in mappings.items():
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "nuget",
                            "nuget_source_mapping",
                            f"{pattern}={','.join(sources)}",
                            line=loc.find(f'pattern="{pattern}"') or loc.find(f'key="{pattern}"'),
                        )
                    )
            if tag in {"packageSourceCredentials", "ClearTextPassword"}:
                result.config_facts.append(
                    make_fact(ctx, "nuget", "nuget_credentials_present", "[REDACTED]", line=loc.find(tag))
                )
            if tag == "disabledPackageSources":
                for add in element.iter():
                    if local_name(add.tag) == "add" and add.attrib.get("key"):
                        result.config_facts.append(
                            make_fact(
                                ctx,
                                "nuget",
                                "nuget_disabled_source",
                                add.attrib.get("key", ""),
                                line=loc.find(f'key="{add.attrib.get("key")}"'),
                            )
                        )
        return result


def _parent_of(root: ET.Element, target: ET.Element) -> ET.Element:
    for parent in root.iter():
        for child in parent:
            if child is target:
                return parent
    return target
