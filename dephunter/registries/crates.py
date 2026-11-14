from __future__ import annotations

import json
from urllib.parse import quote

from dephunter.core.http import HttpResponse
from dephunter.core.models import RegistryResult
from dephunter.registries.base import BaseRegistryClient, clean_git_url

CRATES_ROOT = "https://crates.io"


class CratesRegistryClient(BaseRegistryClient):
    ecosystem = "crates"
    display_name = "crates.io"
    api_root = CRATES_ROOT
    user_agent = "DepHunter/0.1 (authorized security review; passive registry metadata)"

    def url_for(self, name: str) -> str:
        return f"{CRATES_ROOT}/api/v1/crates/{quote(name, safe='')}"

    async def lookup(self, name: str) -> RegistryResult:
        url = self.url_for(name)
        response = await self._get(name, url, {"Accept": "application/json", "User-Agent": self.user_agent})
        if isinstance(response, RegistryResult):
            return response
        if response.status == 404:
            return self.missing(name, url=url, note="crates.io returned 404")
        if response.status != 200:
            return self.unexpected_status(name, response)
        try:
            data = json.loads(response.text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.error(name, f"invalid crates.io JSON: {exc}", url=url, http_status=response.status)
        crate = data.get("crate") if isinstance(data, dict) else None
        if not isinstance(crate, dict):
            return self.error(name, "crates.io response missing crate data", url=url, http_status=response.status)
        versions = data.get("versions") if isinstance(data.get("versions"), list) else []

        publisher = None
        owners_url = f"{url}/owners"
        owners = await self._get(name, owners_url, {"Accept": "application/json", "User-Agent": self.user_agent})
        if isinstance(owners, HttpResponse) and owners.status == 200:
            try:
                payload = json.loads(owners.text())
                owner_entries = payload.get("users") if isinstance(payload, dict) else None
                if isinstance(owner_entries, list):
                    names = [
                        entry.get("login") or entry.get("name")
                        for entry in owner_entries[:5]
                        if isinstance(entry, dict)
                    ]
                    publisher = ", ".join(str(n) for n in names if n) or None
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        latest = crate.get("max_version") or crate.get("newest_version")
        return self.exists(
            name,
            url=url,
            http_status=response.status,
            latest_version=latest if isinstance(latest, str) else None,
            versions_count=len(versions),
            publisher=publisher,
            publisher_url=f"https://crates.io/users/{quote(publisher.split(',')[0].strip())}"
            if publisher
            else None,
            repository_url=clean_git_url(crate.get("repository")),
            first_published=crate.get("created_at") if isinstance(crate.get("created_at"), str) else None,
            last_published=crate.get("updated_at") if isinstance(crate.get("updated_at"), str) else None,
            raw_summary={
                "downloads": crate.get("downloads"),
                "recent_downloads": crate.get("recent_downloads"),
                "summary": (crate.get("description") or "")[:300]
                if isinstance(crate.get("description"), str)
                else "",
            },
        )
