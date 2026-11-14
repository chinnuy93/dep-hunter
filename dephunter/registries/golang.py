from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient
from dephunter.registries.versions import version_sort_key

GOPROXY_ROOT = "https://proxy.golang.org"


def escape_go_module(module: str) -> str:
    escaped = []
    for char in module:
        if char.isupper():
            escaped.append("!" + char.lower())
        else:
            escaped.append(char)
    return quote("".join(escaped), safe="/!")


def module_repository_url(module: str) -> str | None:
    parts = module.strip("/").split("/")
    if not parts or not parts[0]:
        return None
    host = parts[0]
    if host in {"github.com", "gitlab.com", "bitbucket.org"} and len(parts) >= 3:
        return f"https://{host}/{parts[1]}/{parts[2]}"
    if len(parts) >= 2 and "." in host:
        return f"https://{host}/{parts[1]}"
    return None


class GoRegistryClient(BaseRegistryClient):
    ecosystem = "go"
    display_name = "Go module proxy"
    api_root = GOPROXY_ROOT

    def url_for(self, name: str) -> str:
        return f"{GOPROXY_ROOT}/{escape_go_module(name)}/@latest"

    async def lookup(self, name: str) -> RegistryResult:
        latest_url = self.url_for(name)
        response = await self._get(name, latest_url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 200:
            try:
                data = json.loads(response.text())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return self.error(name, f"invalid Go proxy JSON: {exc}", url=latest_url, http_status=response.status)
            if not isinstance(data, dict):
                return self.error(name, "Go proxy returned unexpected JSON", url=latest_url, http_status=response.status)
            return self.exists(
                name,
                url=latest_url,
                http_status=response.status,
                latest_version=data.get("Version") if isinstance(data.get("Version"), str) else None,
                publisher=None,
                repository_url=module_repository_url(name),
                first_published=data.get("Time") if isinstance(data.get("Time"), str) else None,
                raw_summary={"origin": data.get("Origin") if isinstance(data.get("Origin"), dict) else None},
            )
        if response.status not in {404, 410}:
            return self.unexpected_status(name, response)

        list_url = f"{GOPROXY_ROOT}/{escape_go_module(name)}/@v/list"
        listing = await self._get(name, list_url, {"Accept": "text/plain"})
        if isinstance(listing, RegistryResult):
            return listing
        if listing.status in {404, 410}:
            return self.missing(
                name,
                url=latest_url,
                http_status=response.status,
                note="not known to proxy.golang.org; absence is not conclusive for private modules",
            )
        if listing.status != 200:
            return self.unexpected_status(name, listing)
        versions = [line.strip() for line in listing.text().splitlines() if line.strip()]
        if not versions:
            return self.error(
                name,
                "Go module proxy returned no versions; existence could not be determined",
                url=list_url,
                http_status=listing.status,
            )
        latest = max(versions, key=version_sort_key)
        return self.exists(
            name,
            url=latest_url,
            http_status=response.status,
            latest_version=latest,
            versions_count=len(versions),
            publisher=None,
            repository_url=module_repository_url(name),
            raw_summary={
                "versions_sample": versions[-5:],
                "note": "listed by Go module proxy but @latest was unavailable",
            },
        )
