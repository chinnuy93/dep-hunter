from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import PurePosixPath
from collections.abc import Callable
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from dephunter.core.errors import NetworkError, ScopeViolation
from dephunter.core.evidence import EvidenceStore
from dephunter.core.http import SafeHttpClient
from dephunter.core.scope import ScopeConfig, ScopePolicy
from dephunter.core.util import canonical_url, utc_iso
from dephunter.database.db import Database
from dephunter.extractors import extract, find_extractor, manifest_role

log = logging.getLogger(__name__)

_SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s*]+)")
_MEDIA_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mov", ".avi", ".mp3", ".wav", ".ogg", ".flac",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".exe", ".dmg", ".iso",
}
_PAGE_EXT = {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".txt"}
_JS_EXT = {".js", ".mjs", ".cjs", ".jsx"}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value}
        if tag in {"a", "area"} and values.get("href"):
            self.links.append((values["href"], "page"))
        elif tag in {"iframe", "frame"} and values.get("src"):
            self.links.append((values["src"], "page"))
        elif tag == "script" and values.get("src"):
            self.links.append((values["src"], "js"))
        elif tag == "link" and values.get("href"):
            self.links.append((values["href"], "asset"))
        elif tag == "meta" and (values.get("property") or "").lower() == "og:url" and values.get("content"):
            self.links.append((values["content"], "page"))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


@dataclass(slots=True)
class _Robots:
    unavailable: bool = False
    parser: RobotFileParser | None = None
    crawl_delay: float = 0.0


@dataclass(slots=True)
class CrawlResult:
    fetched: int = 0
    parsed: int = 0
    skipped: int = 0
    errors: int = 0
    discovered: int = 0
    dependencies_added: int = 0
    config_facts_added: int = 0
    warnings: int = 0


class WebCrawler:
    def __init__(
        self,
        db: Database,
        http: SafeHttpClient,
        policy: ScopePolicy,
        scope: ScopeConfig,
        evidence: EvidenceStore,
        *,
        max_body_bytes: int = 8 * 1024 * 1024,
        progress: Callable[[int, int], None] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.db = db
        self.http = http
        self.policy = policy
        self.scope = scope
        self.evidence = evidence
        self.max_body_bytes = max_body_bytes
        self.progress = progress
        self.log = logger or log
        self._robots: dict[str, _Robots] = {}
        self._robot_locks: dict[str, asyncio.Lock] = {}
        self._host_ready: dict[str, float] = {}
        self._throttle_lock = asyncio.Lock()

    async def crawl(self, scan_id: int, seeds: list[str] | None = None) -> CrawlResult:
        result = CrawlResult()
        seed_urls = seeds if seeds is not None else [target.url for target in self.scope.web]
        for seed in seed_urls:
            self._add_asset(scan_id, seed, 0, None, "page")

        if self.scope.crawl.probe_manifests:
            for target in self.scope.web:
                parsed = urlparse(target.url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                for probe in self.scope.crawl.probe_paths:
                    self._add_asset(scan_id, urljoin(origin + "/", probe.lstrip("/")), 0, None, "asset")

        semaphore = asyncio.Semaphore(max(1, self.scope.crawl.concurrency))
        while True:
            pending = self.db.pending_assets(scan_id, limit=max(1, self.scope.crawl.concurrency * 2))
            if not pending:
                break
            if self._asset_count(scan_id) > self.scope.crawl.max_urls:
                pending = pending[:1]

            async def run(row: dict[str, Any]) -> None:
                async with semaphore:
                    await self._process_asset(scan_id, row, result)

            await asyncio.gather(*(run(row) for row in pending))
            self._report_progress(scan_id)
        self._report_progress(scan_id)
        return result

    def _report_progress(self, scan_id: int) -> None:
        if self.progress is None:
            return
        try:
            total = self._asset_count(scan_id)
            pending = self.db.count_pending_assets(scan_id)
            self.progress(max(0, total - pending), total)
        except Exception:
            self.log.debug("crawl progress callback failed", exc_info=True)

    def _asset_count(self, scan_id: int) -> int:
        counter = getattr(self.db, "count_assets", None)
        if callable(counter):
            return int(counter(scan_id))
        return len(self.db.assets_for_scan(scan_id))

    def _add_asset(
        self,
        scan_id: int,
        url: str,
        depth: int,
        discovered_from: str | None,
        kind: str | None = None,
    ) -> bool:
        if depth > self.scope.crawl.max_depth:
            return False
        if self._asset_count(scan_id) >= self.scope.crawl.max_urls:
            return False
        clean, _fragment = urldefrag(url.strip())
        parsed = urlparse(clean)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if not self.policy.is_url_allowed(clean):
            return False
        resolved_kind = kind or self._kind_for(clean, None)
        try:
            added = self.db.add_asset(
                scan_id,
                clean,
                canonical_url(clean),
                resolved_kind,
                depth,
                discovered_from,
            )
        except Exception as exc:
            self.log.warning("cannot persist asset %s: %s", clean, exc)
            return False
        if added:
            self.log.debug("discovered %s (%s, depth %d)", clean, resolved_kind, depth)
        return added

    def _kind_for(self, url: str, hint: str | None) -> str:
        path = urlparse(url).path
        role = manifest_role(path)
        if role != "asset":
            return role
        ext = PurePosixPath(path.lower()).suffix
        if ext in _JS_EXT:
            return "js"
        if ext == ".map":
            return "source_map"
        if ext == ".css":
            return "css"
        if ext in {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}:
            return "page"
        if hint == "page" and ext == "":
            return "page"
        if ext == ".json":
            return "json"
        return "asset"

    def _interesting(self, url: str, hint: str, depth: int) -> bool:
        if depth > self.scope.crawl.max_depth:
            return False
        path = urlparse(url).path
        ext = PurePosixPath(path.lower()).suffix
        if ext in _MEDIA_EXT:
            return False
        if hint == "page":
            return ext in _PAGE_EXT or path.endswith("/")
        return True

    async def _process_asset(self, scan_id: int, row: dict[str, Any], result: CrawlResult) -> None:
        url = row["url"]
        asset_id = int(row["id"])
        depth = int(row["depth"] or 0)
        try:
            self.policy.check_web_url(url)
        except ScopeViolation as exc:
            self.db.update_asset(asset_id, "DISALLOWED", error=str(exc))
            result.skipped += 1
            return

        origin = self._origin(url)
        robots = await self._robots_for(origin)
        if robots.unavailable:
            self.db.update_asset(asset_id, "DISALLOWED", error="robots.txt unavailable (5xx/timeout); host skipped")
            result.skipped += 1
            return
        if robots.parser is not None and not robots.parser.can_fetch("dep-hunter", url):
            self.db.update_asset(asset_id, "DISALLOWED", error="disallowed by robots.txt")
            result.skipped += 1
            return

        await self._schedule_delay(urlparse(url).hostname or "", robots.crawl_delay)
        try:
            response = await self.http.get(url, max_bytes=self.max_body_bytes)
        except (NetworkError, ScopeViolation) as exc:
            self.db.update_asset(asset_id, "ERROR", error=str(exc))
            result.errors += 1
            return

        if response.status >= 400:
            self.db.update_asset(
                asset_id,
                "ERROR",
                http_status=response.status,
                content_type=response.content_type,
                error=f"HTTP {response.status}",
            )
            result.errors += 1
            return

        digest, evidence_path = self.evidence.store(response.body)
        content_type = response.content_type
        path = urlparse(response.url).path or urlparse(url).path or "/"
        extracted = False
        try:
            if find_extractor(path) is not None:
                from dephunter.extractors.base import ExtractContext

                ctx = ExtractContext(
                    origin="web",
                    source_url=response.url,
                    file_path=path,
                )
                extraction = extract(path, response.body, ctx)
                deps_added = self.db.add_dependencies(scan_id, extraction.dependencies)
                facts_added = self.db.add_config_facts(scan_id, extraction.config_facts)
                result.dependencies_added += deps_added
                result.config_facts_added += facts_added
                result.warnings += len(extraction.warnings)
                for warning in extraction.warnings[:5]:
                    self.log.debug("extractor warning for %s: %s", url, warning)
                extracted = True
        except Exception as exc:
            self.log.warning("failed to extract %s: %s", url, exc)

        self.db.update_asset(
            asset_id,
            "PARSED" if extracted else "FETCHED",
            http_status=response.status,
            content_type=content_type,
            sha256=digest,
            evidence_path=evidence_path,
        )
        result.fetched += 1
        if extracted:
            result.parsed += 1

        text = response.text() if content_type in {"text/html", "application/xhtml+xml"} else ""
        if text:
            for link, hint in self._parse_links(text):
                absolute = urljoin(response.url, link)
                if not self._interesting(absolute, hint, depth + 1):
                    continue
                if self._add_asset(scan_id, absolute, depth + 1, url, self._kind_for(absolute, hint)):
                    result.discovered += 1

        if self.scope.crawl.source_maps and (
            path.lower().endswith((".js", ".mjs", ".cjs", ".css", ".map"))
            or content_type in {"application/javascript", "text/javascript", "text/css"}
        ):
            map_urls = self._source_maps(response.headers, response.url, response.body)
            for map_url in map_urls:
                if self._add_asset(scan_id, map_url, depth + 1, url, "source_map"):
                    result.discovered += 1

    def _parse_links(self, text: str) -> list[tuple[str, str]]:
        parser = _LinkParser()
        try:
            parser.feed(text[:4 * 1024 * 1024])
            parser.close()
        except Exception:
            return parser.links
        return parser.links

    def _source_maps(self, headers: dict[str, str], base_url: str, body: bytes) -> list[str]:
        candidates: list[str] = []
        header = headers.get("sourcemap") or headers.get("x-sourcemap")
        if header:
            candidates.append(header.strip())
        sample = body[:1024 * 1024].decode("utf-8", errors="ignore")
        candidates.extend(match.group(1) for match in _SOURCE_MAP_RE.finditer(sample))
        results: list[str] = []
        for candidate in candidates:
            if candidate.startswith(("data:", "javascript:", "mailto:", "#")):
                continue
            absolute, _ = urldefrag(urljoin(base_url, candidate))
            if absolute and absolute not in results:
                results.append(absolute)
        return results

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    async def _robots_for(self, origin: str) -> _Robots:
        lock = self._robot_locks.setdefault(origin, asyncio.Lock())
        async with lock:
            existing = self._robots.get(origin)
            if existing is not None:
                return existing
            entry = await self._load_robots(origin)
            self._robots[origin] = entry
            return entry

    async def _load_robots(self, origin: str) -> _Robots:
        url = origin + "/robots.txt"
        try:
            response = await self.http.get(url, max_bytes=512 * 1024)
        except (NetworkError, ScopeViolation) as exc:
            self.log.warning("robots.txt unavailable for %s (%s); skipping host", origin, exc)
            return _Robots(unavailable=True)
        if response.status == 429 or response.status >= 500:
            return _Robots(unavailable=True)
        parser = RobotFileParser()
        if response.status >= 400:
            parser.parse([])
        else:
            parser.parse(response.text().splitlines())
        delay = 0.0
        try:
            value = parser.crawl_delay("dep-hunter")
            if value:
                delay = float(value)
        except (TypeError, ValueError):
            delay = 0.0
        return _Robots(parser=parser, crawl_delay=max(0.0, delay))

    async def _schedule_delay(self, host: str, delay: float) -> None:
        if delay <= 0:
            return
        loop = asyncio.get_running_loop()
        async with self._throttle_lock:
            now = loop.time()
            ready = self._host_ready.get(host, now)
            wait = max(0.0, ready - now)
            self._host_ready[host] = max(now, ready) + delay
        if wait:
            await asyncio.sleep(wait)
