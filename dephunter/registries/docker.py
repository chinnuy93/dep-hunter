from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient

DOCKER_HUB_ROOT = "https://hub.docker.com/v2/repositories"


class DockerRegistryClient(BaseRegistryClient):
    ecosystem = "docker"
    display_name = "Docker Hub"
    api_root = DOCKER_HUB_ROOT

    def _hub_path(self, name: str) -> str | None:
        value = name.strip()
        if value.startswith("docker.io/"):
            value = value[len("docker.io/"):]
        if not value:
            return None
        if "/" not in value:
            value = f"library/{value}"
        first = value.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            return None
        return value

    def url_for(self, name: str) -> str:
        path = self._hub_path(name) or ""
        return f"{DOCKER_HUB_ROOT}/{quote(path, safe='/')}/"

    async def lookup(self, name: str) -> RegistryResult:
        path = self._hub_path(name)
        if path is None:
            return self.skipped(name, "image is not hosted on Docker Hub; registry metadata not queried")
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json"})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="Docker Hub namespace or repository not found")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid Docker Hub JSON: {exc}", url=url, http_status=response.status)
        if not isinstance(data, dict) or not data.get("name"):
            return self.error(name, "Docker Hub response missing repository data", url=url, http_status=response.status)
        namespace = data.get("namespace")
        publisher = namespace if isinstance(namespace, str) else None
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=None,
            versions_count=None,
            publisher=publisher,
            publisher_url=f"https://hub.docker.com/u/{namespace}" if namespace else None,
            repository_url=None,
            first_published=data.get("date_registered") if isinstance(data.get("date_registered"), str) else None,
            last_published=data.get("last_updated") if isinstance(data.get("last_updated"), str) else None,
            raw_summary={
                "pull_count": data.get("pull_count"),
                "star_count": data.get("star_count"),
                "is_private": data.get("is_private"),
                "status": data.get("status"),
                "description": (data.get("description") or "")[:300]
                if isinstance(data.get("description"), str)
                else "",
            },
        )
