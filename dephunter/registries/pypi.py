from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url

PYPI_ROOT = "https://pypi.org"


class PypiRegistryClient(BaseRegistryClient):
    ecosystem = "pypi"
    display_name = "PyPI"
    api_root = PYPI_ROOT

    def url_for(self, name: str) -> str:
        return f"{PYPI_ROOT}/pypi/{quote(name, safe='')}/json"

    async def lookup(self, name: str) -> RegistryResult:
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="PyPI returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid PyPI JSON: {exc}", url=url, http_status=response.status)
        info = data.get("info") if isinstance(data, dict) else None
        if not isinstance(info, dict):
            return self.error(name, "PyPI response missing info", url=url, http_status=response.status)
        releases = data.get("releases") if isinstance(data.get("releases"), dict) else {}
        project_urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
        repo_url = None
        for key in ("Source", "Source Code", "Repository", "Code", "Homepage", "homepage"):
            value = project_urls.get(key)
            if isinstance(value, str) and any(host in value for host in ("github.com", "gitlab.com", "bitbucket.org")):
                repo_url = value
                break
        if repo_url is None and isinstance(info.get("home_page"), str):
            repo_url = info["home_page"]
        publisher = info.get("maintainer") or info.get("author")
        if isinstance(publisher, str):
            publisher = publisher.strip()[:200] or None
        else:
            publisher = None
        first_published = None
        latest_files = data.get("urls") if isinstance(data.get("urls"), list) else []
        for file_info in latest_files[:5]:
            if isinstance(file_info, dict) and isinstance(file_info.get("upload_time_iso_8601"), str):
                first_published = file_info["upload_time_iso_8601"]
                break
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=info.get("version") if isinstance(info.get("version"), str) else None,
            versions_count=len(releases),
            publisher=publisher,
            publisher_url=None,
            repository_url=clean_git_url(repo_url),
            first_published=first_published,
            last_published=None,
            raw_summary={
                "summary": (info.get("summary") or "")[:300] if isinstance(info.get("summary"), str) else "",
                "requires_python": info.get("requires_python"),
                "yanked": bool(info.get("yanked", False)),
            },
        )
