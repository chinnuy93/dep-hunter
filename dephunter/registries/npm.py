from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.http import HttpResponse
from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url

NPM_ROOT = "https://registry.npmjs.org"


class NpmRegistryClient(BaseRegistryClient):
    ecosystem = "npm"
    display_name = "npm"
    api_root = NPM_ROOT

    def url_for(self, name: str) -> str:
        encoded = quote(name, safe="@")
        return f"{NPM_ROOT}/{encoded}"

    async def lookup(self, name: str) -> RegistryResult:
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="npm registry returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid npm JSON: {exc}", url=url, http_status=response.status)
        if not isinstance(data, dict) or "error" in data:
            return self.error(name, "npm response missing package metadata", url=url, http_status=response.status)
        versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
        tags = data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
        latest = tags.get("latest") if isinstance(tags.get("latest"), str) else None
        maintainers = data.get("maintainers")
        publisher_names: list[str] = []
        if isinstance(maintainers, list):
            for maintainer in maintainers[:5]:
                if isinstance(maintainer, dict) and isinstance(maintainer.get("name"), str):
                    publisher_names.append(maintainer["name"])
        time_info = data.get("time") if isinstance(data.get("time"), dict) else {}
        repository = data.get("repository")
        repo_url = None
        if isinstance(repository, str):
            repo_url = repository
        elif isinstance(repository, dict) and isinstance(repository.get("url"), str):
            repo_url = repository["url"]
        publisher = ", ".join(publisher_names) if publisher_names else None
        publisher_url = f"https://www.npmjs.com/~{publisher_names[0]}" if publisher_names else None
        keyword_raw = data.get("keywords")
        keywords = [k for k in keyword_raw if isinstance(k, str)][:20] if isinstance(keyword_raw, list) else []
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=latest,
            versions_count=len(versions),
            publisher=publisher,
            publisher_url=publisher_url,
            repository_url=clean_git_url(repo_url),
            first_published=time_info.get("created") if isinstance(time_info.get("created"), str) else None,
            last_published=time_info.get("modified") if isinstance(time_info.get("modified"), str) else None,
            raw_summary={
                "dist_tags": {k: v for k, v in tags.items() if isinstance(k, str) and isinstance(v, str)},
                "maintainers": publisher_names,
                "keywords": keywords,
                "deprecated": data.get("deprecated"),
            },
        )
