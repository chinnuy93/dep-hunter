from __future__ import annotations

import asyncio

import pytest

from dephunter.core.errors import ScopeViolation
from dephunter.core.http import HostRateLimiter, SafeHttpClient
from dephunter.core.scope import ScopeConfig, ScopePolicy, WebTarget


class NoNetworkSession:
    def __init__(self) -> None:
        self.calls = 0

    def request(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("network must not be reached for a rejected URL")


def _policy(url: str, *, allow_private: bool = False) -> ScopePolicy:
    scope = ScopeConfig(
        program="Test",
        authorization="Authorized test engagement 123",
        allow_private_hosts=allow_private,
        web=[WebTarget(url=url)],
    )
    return ScopePolicy(scope)


def test_http_client_rejects_out_of_scope_url_without_network() -> None:
    session = NoNetworkSession()
    client = SafeHttpClient(
        session,
        _policy("https://app.example.com/"),
        "test-agent",
        rate_limiter=HostRateLimiter(1000),
    )

    async def run():
        with pytest.raises(ScopeViolation):
            await client.get("https://evil.example.net/")

    asyncio.run(run())
    assert session.calls == 0


def test_http_client_rejects_loopback_dns_without_network() -> None:
    session = NoNetworkSession()
    client = SafeHttpClient(
        session,
        _policy("http://localhost:8000/"),
        "test-agent",
        rate_limiter=HostRateLimiter(1000),
    )

    async def run():
        with pytest.raises(ScopeViolation):
            await client.get("http://localhost:8000/")

    asyncio.run(run())
    assert session.calls == 0


def test_allow_private_hosts_is_explicit() -> None:
    session = NoNetworkSession()
    client = SafeHttpClient(
        session,
        _policy("http://localhost:8000/", allow_private=True),
        "test-agent",
        rate_limiter=HostRateLimiter(1000),
    )
    assert client.policy.allow_private_hosts


def test_rate_limiter_overrides() -> None:
    limiter = HostRateLimiter(2.0, {"crates.io": 1.0})
    assert limiter.rate_for("crates.io") == 1.0
    assert limiter.rate_for("example.com") == 2.0
