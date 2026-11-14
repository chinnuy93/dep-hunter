from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url

RUBYGEMS_ROOT = "https://rubygems.org"


class RubygemsRegistryClient(BaseRegistryClient):
    ecosystem = "rubygems"
    display_name = "RubyGems"
    api_root = RUBYGEMS_ROOT

    def url_for(self, name: str) -> str:
        return f"{RUBYGEMS_ROOT}/api/v1/gems/{quote(name, safe='')}.json"

    async def lookup(self, name: str) -> RegistryResult:
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="RubyGems returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid RubyGems JSON: {exc}", url=url, http_status=response.status)
        if not isinstance(data, dict):
            return self.error(name, "RubyGems returned unexpected JSON", url=url, http_status=response.status)
        authors = data.get("authors")
        publisher = authors.strip()[:300] if isinstance(authors, str) and authors.strip() else None
        repo_url = data.get("source_code_uri")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        if not repo_url:
            repo_url = metadata.get("source_code_uri")
        if not repo_url:
            repo_url = data.get("homepage_uri")
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=data.get("version") if isinstance(data.get("version"), str) else None,
            publisher=publisher,
            publisher_url=None,
            repository_url=clean_git_url(repo_url if isinstance(repo_url, str) else None),
            raw_summary={
                "downloads": data.get("downloads"),
                "summary": (data.get("info") or "")[:300] if isinstance(data.get("info"), str) else "",
                "project_uri": data.get("project_uri"),
            },
        )
