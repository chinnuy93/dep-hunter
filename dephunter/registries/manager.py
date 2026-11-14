from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from dephunter.core.http import SafeHttpClient
from dephunter.core.models import RegistryResult, RegistryStatus
from dephunter.core.names import normalize_package_name
from dephunter.core.util import utc_iso
from dephunter.registries.base import BaseRegistryClient, result_from_cache
from dephunter.registries.crates import CratesRegistryClient
from dephunter.registries.docker import DockerRegistryClient
from dephunter.registries.golang import GoRegistryClient
from dephunter.registries.maven import MavenRegistryClient
from dephunter.registries.npm import NpmRegistryClient
from dephunter.registries.nuget import NugetRegistryClient
from dephunter.registries.packagist import PackagistRegistryClient
from dephunter.registries.pypi import PypiRegistryClient
from dephunter.registries.rubygems import RubygemsRegistryClient

if TYPE_CHECKING:
    from dephunter.database.db import Database

log = logging.getLogger(__name__)

CLIENT_TYPES: dict[str, type[BaseRegistryClient]] = {
    "npm": NpmRegistryClient,
    "pypi": PypiRegistryClient,
    "maven": MavenRegistryClient,
    "nuget": NugetRegistryClient,
    "go": GoRegistryClient,
    "rubygems": RubygemsRegistryClient,
    "packagist": PackagistRegistryClient,
    "crates": CratesRegistryClient,
    "docker": DockerRegistryClient,
}


class RegistryManager:
    """Caches authoritative registry answers and bounds concurrent lookups."""

    def __init__(
        self,
        db: Database | None,
        http: SafeHttpClient,
        ecosystems: Iterable[str],
        *,
        cache_ttl_hours: float = 24.0,
        concurrency: int = 4,
        logger: logging.Logger | None = None,
    ) -> None:
        self.db = db
        self.http = http
        self.enabled = {ecosystem.lower() for ecosystem in ecosystems}
        self.cache_ttl_seconds = max(0, int(cache_ttl_hours * 3600))
        self.concurrency = max(1, concurrency)
        self.log = logger or log
        self.clients: dict[str, BaseRegistryClient] = {
            ecosystem: client_type(http, self.log)
            for ecosystem, client_type in CLIENT_TYPES.items()
            if ecosystem in self.enabled
        }

    def _skipped(self, ecosystem: str, name: str, reason: str) -> RegistryResult:
        return RegistryResult(
            ecosystem=ecosystem,
            name=name,
            status=RegistryStatus.SKIPPED,
            exists=None,
            error=reason,
            checked_at=utc_iso(),
        )

    async def lookup(self, ecosystem: str, name: str) -> RegistryResult:
        eco = (ecosystem or "").strip().lower()
        clean_name = (name or "").strip()
        if not clean_name:
            return self._skipped(eco, clean_name, "empty package name")
        if eco not in CLIENT_TYPES:
            return self._skipped(eco, clean_name, f"unsupported ecosystem: {eco or '<empty>'}")
        if eco not in self.enabled:
            return self._skipped(eco, clean_name, "registry disabled by scope configuration")
        client = self.clients.get(eco)
        if client is None:
            return self._skipped(eco, clean_name, "registry client unavailable")

        cache_key = f"{eco}:{clean_name}"
        if self.db is not None:
            cached = self.db.cache_get(cache_key)
            if cached and isinstance(cached.get("payload"), dict):
                try:
                    return result_from_cache(cached["payload"])
                except (KeyError, TypeError, ValueError):
                    self.log.debug("discarding malformed registry cache entry %s", cache_key)

        try:
            result = await client.lookup(clean_name)
        except Exception as exc:
            self.log.warning("registry lookup crashed for %s %s: %s", eco, clean_name, exc)
            result = RegistryResult(
                ecosystem=eco,
                name=clean_name,
                status=RegistryStatus.ERROR,
                exists=None,
                error=f"registry lookup failed: {exc}",
                checked_at=utc_iso(),
            )

        if (
            self.db is not None
            and self.cache_ttl_seconds > 0
            and result.status in {RegistryStatus.EXISTS, RegistryStatus.MISSING}
        ):
            try:
                self.db.cache_put(cache_key, result.to_json(), result.http_status, self.cache_ttl_seconds)
            except Exception as exc:
                self.log.warning("failed to cache registry result %s: %s", cache_key, exc)
        return result

    async def lookup_many(
        self,
        pairs: Iterable[tuple[str, str]],
        *,
        progress: Callable[[RegistryResult], None] | None = None,
    ) -> list[RegistryResult]:
        order: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ecosystem, name in pairs:
            key = ((ecosystem or "").lower(), (name or "").strip())
            if key in seen or not key[1]:
                continue
            seen.add(key)
            order.append(key)
        if not order:
            return []

        semaphore = asyncio.Semaphore(self.concurrency)
        results: dict[tuple[str, str], RegistryResult] = {}

        async def run(key: tuple[str, str]) -> None:
            async with semaphore:
                result = await self.lookup(key[0], key[1])
                results[key] = result
                if progress is not None:
                    try:
                        progress(result)
                    except Exception:
                        self.log.debug("registry progress callback failed", exc_info=True)

        await asyncio.gather(*(run(key) for key in order))
        return [results[key] for key in order]

    @staticmethod
    def normalized(ecosystem: str, name: str) -> str:
        return normalize_package_name(ecosystem, name)
