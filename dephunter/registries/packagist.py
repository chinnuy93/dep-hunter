from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url
from dephunter.registries.versions import version_sort_key

PACKAGIST_ROOT = "https://packagist.org"


class PackagistRegistryClient(BaseRegistryClient):
    ecosystem = "packagist"
    display_name = "Packagist"
    api_root = PACKAGIST_ROOT

    def url_for(self, name: str) -> str:
        vendor, _, package = name.partition("/")
        return f"{PACKAGIST_ROOT}/packages/{quote(vendor, safe='')}/{quote(package, safe='')}.json"

    async def lookup(self, name: str) -> RegistryResult:
        if "/" not in name:
            return self.error(name, "invalid Packagist package name (expected vendor/package)")
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="Packagist returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid Packagist JSON: {exc}", url=url, http_status=response.status)
        package = data.get("package") if isinstance(data, dict) else None
        if not isinstance(package, dict):
            return self.error(name, "Packagist response missing package data", url=url, http_status=response.status)
        versions = package.get("versions") if isinstance(package.get("versions"), dict) else {}
        version_names = [key for key in versions if isinstance(key, str)]
        latest = max(version_names, key=version_sort_key) if version_names else None
        latest_data = versions.get(latest, {}) if latest else {}
        if not isinstance(latest_data, dict):
            latest_data = {}
        times = []
        for entry in versions.values():
            if isinstance(entry, dict) and isinstance(entry.get("time"), str):
                times.append(entry["time"])
        maintainers = package.get("maintainers")
        publisher_names: list[str] = []
        publisher_url = None
        if isinstance(maintainers, list):
            for maintainer in maintainers[:5]:
                if isinstance(maintainer, dict) and isinstance(maintainer.get("name"), str):
                    publisher_names.append(maintainer["name"])
                    if not publisher_url and isinstance(maintainer.get("homepage"), str):
                        publisher_url = maintainer["homepage"]
        source = latest_data.get("source") if isinstance(latest_data.get("source"), dict) else {}
        repo_url = source.get("url") if isinstance(source.get("url"), str) else None
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=latest,
            versions_count=len(version_names),
            publisher=", ".join(publisher_names) if publisher_names else None,
            publisher_url=publisher_url,
            repository_url=clean_git_url(repo_url),
            first_published=min(times) if times else None,
            last_published=max(times) if times else None,
            raw_summary={
                "summary": (package.get("description") or "")[:300]
                if isinstance(package.get("description"), str)
                else "",
            },
        )
