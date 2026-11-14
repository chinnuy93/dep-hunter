from __future__ import annotations

import logging
from typing import Any

from dephunter.core.errors import NetworkError, ScopeViolation
from dephunter.core.http import HttpResponse, SafeHttpClient
from dephunter.core.models import RegistryResult, RegistryStatus
from dephunter.core.util import utc_iso


class BaseRegistryClient:
    ecosystem: str = ""
    display_name: str = ""
    api_root: str = ""

    def __init__(self, http: SafeHttpClient, logger: logging.Logger | None = None) -> None:
        self.http = http
        self.log = logger or logging.getLogger(f"dephunter.registries.{self.ecosystem}")

    async def lookup(self, name: str) -> RegistryResult:
        raise NotImplementedError

    def url_for(self, name: str) -> str:
        raise NotImplementedError

    async def _get(
        self,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse | RegistryResult:
        try:
            return await self.http.get(url, headers=headers)
        except (NetworkError, ScopeViolation) as exc:
            return self.error(name=name, message=str(exc), url=url)

    def exists(
        self,
        name: str,
        *,
        url: str,
        http_status: int,
        latest_version: str | None = None,
        versions_count: int | None = None,
        publisher: str | None = None,
        publisher_url: str | None = None,
        repository_url: str | None = None,
        first_published: str | None = None,
        last_published: str | None = None,
        raw_summary: dict[str, Any] | None = None,
    ) -> RegistryResult:
        return RegistryResult(
            ecosystem=self.ecosystem,
            name=name,
            status=RegistryStatus.EXISTS,
            exists=True,
            latest_version=latest_version,
            versions_count=versions_count,
            publisher=publisher,
            publisher_url=publisher_url,
            repository_url=repository_url,
            first_published=first_published,
            last_published=last_published,
            url=url,
            http_status=http_status,
            checked_at=utc_iso(),
            raw_summary=raw_summary or {},
        )

    def missing(self, name: str, *, url: str, http_status: int = 404, note: str | None = None) -> RegistryResult:
        raw = {"authoritative": True}
        if note:
            raw["note"] = note
        return RegistryResult(
            ecosystem=self.ecosystem,
            name=name,
            status=RegistryStatus.MISSING,
            exists=False,
            url=url,
            http_status=http_status,
            checked_at=utc_iso(),
            raw_summary=raw,
        )

    def skipped(self, name: str, reason: str) -> RegistryResult:
        return RegistryResult(
            ecosystem=self.ecosystem,
            name=name,
            status=RegistryStatus.SKIPPED,
            exists=None,
            error=reason,
            checked_at=utc_iso(),
        )

    def error(
        self,
        name: str,
        message: str,
        *,
        url: str | None = None,
        http_status: int | None = None,
    ) -> RegistryResult:
        return RegistryResult(
            ecosystem=self.ecosystem,
            name=name,
            status=RegistryStatus.ERROR,
            exists=None,
            url=url,
            http_status=http_status,
            error=message,
            checked_at=utc_iso(),
        )

    def unexpected_status(self, name: str, response: HttpResponse) -> RegistryResult:
        return self.error(
            name,
            f"unexpected registry response HTTP {response.status}",
            url=response.url,
            http_status=response.status,
        )


def clean_git_url(value: str | None) -> str | None:
    if not value:
        return None
    url = value.strip()
    for prefix in ("git+", "git://", "ssh://git@", "git@github.com:"):
        if url.startswith(prefix):
            url = url[len(prefix):]
    if url.startswith("github.com:"):
        url = "https://" + url.replace(":", "/", 1)
    if url.startswith("github.com/"):
        url = "https://" + url
    return url[:500]


def result_from_cache(payload: dict[str, Any]) -> RegistryResult:
    status = RegistryStatus(payload.get("status", "ERROR"))
    return RegistryResult(
        ecosystem=payload.get("ecosystem", ""),
        name=payload.get("name", ""),
        status=status,
        exists=payload.get("exists"),
        latest_version=payload.get("latest_version"),
        versions_count=payload.get("versions_count"),
        publisher=payload.get("publisher"),
        publisher_url=payload.get("publisher_url"),
        repository_url=payload.get("repository_url"),
        first_published=payload.get("first_published"),
        last_published=payload.get("last_published"),
        url=payload.get("url"),
        http_status=payload.get("http_status"),
        error=payload.get("error"),
        checked_at=payload.get("checked_at", utc_iso()),
        raw_summary={**(payload.get("raw_summary") or {}), "cached": True},
    )
