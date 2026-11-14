from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient

MAVEN_ROOT = "https://repo1.maven.org/maven2"
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


class MavenRegistryClient(BaseRegistryClient):
    ecosystem = "maven"
    display_name = "Maven Central"
    api_root = MAVEN_ROOT

    def _split(self, name: str) -> tuple[str, str] | None:
        if ":" not in name:
            return None
        group, artifact = name.split(":", 1)
        if not _SAFE.match(group.replace(".", "")) or not _SAFE.match(artifact):
            return None
        return group, artifact

    def url_for(self, name: str) -> str:
        split = self._split(name)
        if not split:
            return ""
        group, artifact = split
        group_path = "/".join(quote(part, safe="") for part in group.split("."))
        return f"{MAVEN_ROOT}/{group_path}/{quote(artifact, safe='')}/maven-metadata.xml"

    async def lookup(self, name: str) -> RegistryResult:
        split = self._split(name)
        if not split:
            return self.error(name, "invalid Maven coordinate (expected groupId:artifactId)")
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/xml,text/xml"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="Maven Central returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        text = response.text()
        if "<metadata" not in text:
            return self.error(name, "Maven response is not maven-metadata.xml", url=url, http_status=response.status)
        try:
            from dephunter.core.util import assert_safe_xml

            assert_safe_xml(text)
            root = ET.fromstring(text)
        except (ValueError, ET.ParseError) as exc:
            return self.error(name, f"invalid Maven metadata XML: {exc}", url=url, http_status=response.status)
        versioning = root.find("versioning")
        latest = release = None
        versions: list[str] = []
        last_updated = None
        if versioning is not None:
            latest = _text(versioning, "latest")
            release = _text(versioning, "release")
            last_updated = _text(versioning, "lastUpdated")
            versions_el = versioning.find("versions")
            if versions_el is not None:
                versions = [(child.text or "").strip() for child in versions_el.findall("version") if child.text]
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=latest or release or (versions[-1] if versions else None),
            versions_count=len(versions),
            publisher=None,
            first_published=None,
            last_published=last_updated,
            raw_summary={
                "release": release,
                "version_sample": versions[-5:],
                "publisher_note": "Maven Central does not expose artifact ownership metadata",
            },
        )


def _text(parent: ET.Element, tag: str) -> str | None:
    child = parent.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None
