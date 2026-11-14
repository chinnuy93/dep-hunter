from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url
from dephunter.registries.versions import version_sort_key

FLATCONTAINER_ROOT = "https://api.nuget.org/v3-flatcontainer"
SEARCH_URL = "https://azuresearch-usnc.nuget.org/query"


class NugetRegistryClient(BaseRegistryClient):
    ecosystem = "nuget"
    display_name = "NuGet"
    api_root = FLATCONTAINER_ROOT

    def url_for(self, name: str) -> str:
        return f"{FLATCONTAINER_ROOT}/{quote(name.lower(), safe='')}/index.json"

    async def lookup(self, name: str) -> RegistryResult:
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="NuGet flat container returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid NuGet JSON: {exc}", url=url, http_status=response.status)
        versions = [v for v in data.get("versions", []) if isinstance(v, str)] if isinstance(data, dict) else []
        latest = max(versions, key=version_sort_key) if versions else None

        publisher = None
        repository_url = None
        description = None
        search_url = f"{SEARCH_URL}?q=packageid:{quote(name)}&prerelease=true&take=1"
        meta = await self._get(name, search_url, {"Accept": "application/json"})
        if not isinstance(meta, RegistryResult) and meta.status == 200:
            try:
                payload = json.loads(meta.text())
                entries = payload.get("data") if isinstance(payload, dict) else None
                if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                    entry = entries[0]
                    authors = entry.get("authors")
                    if isinstance(authors, str):
                        publisher = authors.strip()[:300] or None
                    elif isinstance(authors, list):
                        publisher = ", ".join(str(a) for a in authors[:5])[:300] or None
                    repository_url = clean_git_url(entry.get("projectUrl"))
                    if isinstance(entry.get("description"), str):
                        description = entry["description"][:300]
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=latest,
            versions_count=len(versions),
            publisher=publisher,
            publisher_url=None,
            repository_url=repository_url,
            raw_summary={
                "versions_sample": versions[-5:],
                "summary": description,
                "publisher_note": "NuGet publishes package ownership via owners; authors field used as hint only",
            },
        )
