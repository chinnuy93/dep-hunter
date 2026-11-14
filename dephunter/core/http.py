from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import aiohttp

from dephunter.core.errors import NetworkError, PolicyViolation, ScopeViolation
from dephunter.core.scope import ScopePolicy

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_DNS_CACHE_TTL = 300.0


@dataclass(slots=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    content_type: str = ""
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        from dephunter.core.util import decode_text

        return decode_text(self.body)


class HostRateLimiter:
    def __init__(self, default_rps: float = 2.0, overrides: dict[str, float] | None = None) -> None:
        self.default_rps = max(0.0, default_rps)
        self.overrides = {k.lower(): v for k, v in (overrides or {}).items()}
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def rate_for(self, host: str) -> float:
        return self.overrides.get(host.lower(), self.default_rps)

    async def acquire(self, host: str) -> None:
        rps = self.rate_for(host)
        if rps <= 0:
            return
        interval = 1.0 / rps
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            scheduled = max(now, self._next.get(host, now))
            self._next[host] = scheduled + interval
            delay = scheduled - now
        if delay > 0:
            await asyncio.sleep(delay)


@dataclass(slots=True)
class _DnsEntry:
    expires: float
    addresses: tuple[str, ...] = field(default_factory=tuple)


class SafeHttpClient:
    """GET/HEAD-only HTTP client with scope, DNS, redirect, and size enforcement."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        policy: ScopePolicy,
        user_agent: str,
        *,
        rate_limiter: HostRateLimiter | None = None,
        timeout: float = 20.0,
        max_body_bytes: int = 8 * 1024 * 1024,
        max_redirects: int = 5,
        retries: int = 2,
        logger: logging.Logger | None = None,
    ) -> None:
        self.session = session
        self.policy = policy
        self.user_agent = user_agent
        self.rate_limiter = rate_limiter or HostRateLimiter(2.0)
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.max_redirects = max_redirects
        self.retries = max(0, retries)
        self.log = logger or logging.getLogger(__name__)
        self._dns: dict[str, _DnsEntry] = {}
        self.request_count = 0

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return await self._request("GET", url, headers=headers, max_bytes=max_bytes, allow_redirects=allow_redirects)

    async def head(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return await self._request("HEAD", url, headers=headers, max_bytes=0, allow_redirects=allow_redirects)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise PolicyViolation(f"HTTP method {method} is not permitted (GET/HEAD only)")
        current = url
        current_headers = dict(headers or {})
        redirects = 0
        while True:
            self.policy.check_url(current)
            await self._assert_destination(current)
            response = await self._fetch_with_retries(method, current, current_headers, max_bytes)
            if not allow_redirects or response.status not in REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            if redirects >= self.max_redirects:
                raise NetworkError(f"redirect limit exceeded for {url}")
            target = urljoin(current, location)
            self.policy.check_url(target)
            if urlparse(target).hostname != urlparse(current).hostname:
                current_headers = {
                    k: v for k, v in current_headers.items()
                    if k.lower() not in {"authorization", "cookie", "proxy-authorization"}
                }
            self.log.debug("redirect %s -> %s", current, target)
            current = target
            redirects += 1

    async def _assert_destination(self, url: str) -> None:
        if self.policy.allow_private_hosts:
            return
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ScopeViolation(f"URL has no host: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        cache_key = f"{host}:{port}"
        now = time.monotonic()
        cached = self._dns.get(cache_key)
        if cached and cached.expires > now:
            addresses = cached.addresses
        else:
            try:
                ipaddress.ip_address(host)
                addresses = (host,)
            except ValueError:
                try:
                    infos = await asyncio.get_running_loop().getaddrinfo(
                        host, port, type=socket.SOCK_STREAM
                    )
                except socket.gaierror as exc:
                    raise NetworkError(f"DNS resolution failed for {host}: {exc}") from exc
                addresses = tuple({info[4][0] for info in infos})
            self._dns[cache_key] = _DnsEntry(expires=now + _DNS_CACHE_TTL, addresses=addresses)
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address.split("%", 1)[0])
            except ValueError:
                continue
            if not ip.is_global:
                raise ScopeViolation(
                    f"destination {host} resolves to non-public address {address}; "
                    "refusing request (set allow_private_hosts only for authorized labs/tests)"
                )

    async def _fetch_with_retries(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        max_bytes: int | None,
    ) -> HttpResponse:
        host = (urlparse(url).hostname or "").lower()
        attempt = 0
        last_error: Exception | None = None
        while attempt <= self.retries:
            await self.rate_limiter.acquire(host)
            self.request_count += 1
            try:
                return await self._fetch_once(method, url, headers, max_bytes, host)
            except ScopeViolation:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError, NetworkError, OSError) as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                delay = min(8.0, (0.5 * (2**attempt)) + random.uniform(0, 0.25))
                self.log.debug("retrying %s after %.2fs: %s", url, delay, exc)
                await asyncio.sleep(delay)
                attempt += 1
        raise NetworkError(f"request failed after retries: {url}: {last_error}") from last_error

    async def _fetch_once(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        max_bytes: int | None,
        host: str,
    ) -> HttpResponse:
        merged = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        merged.update(headers)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with self.session.request(
            method,
            url,
            headers=merged,
            allow_redirects=False,
            timeout=timeout,
        ) as response:
            limit = max_bytes if max_bytes is not None else self.max_body_bytes
            body = b""
            truncated = False
            if method != "HEAD" and limit > 0:
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.content.iter_chunked(65536):
                    if total + len(chunk) > limit:
                        chunks.append(chunk[: limit - total])
                        total = limit
                        truncated = True
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                body = b"".join(chunks)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            if response.status in RETRYABLE_STATUSES and self.retries > 0:
                retry_after = _parse_retry_after(response_headers.get("retry-after"))
                if retry_after:
                    await asyncio.sleep(min(30.0, retry_after))
                raise _RetryableStatus(response.status)
            if response.status in RETRYABLE_STATUSES:
                raise NetworkError(f"HTTP {response.status} from {url}")
            return HttpResponse(
                status=response.status,
                headers=response_headers,
                body=body,
                url=url,
                content_type=response_headers.get("content-type", "").split(";", 1)[0].strip().lower(),
                truncated=truncated,
            )


class _RetryableStatus(NetworkError):
    pass


def _parse_retry_after(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return 0.0


def build_session(concurrency: int = 8, total_timeout: float = 20.0) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(limit=max(1, concurrency), ttl_dns_cache=300, enable_cleanup_closed=True)
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=total_timeout),
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
    )
