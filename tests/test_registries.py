from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

from dephunter.core.errors import NetworkError
from dephunter.core.http import HttpResponse
from dephunter.registries.manager import RegistryManager
from dephunter.registries.npm import NpmRegistryClient
from dephunter.registries.pypi import PypiRegistryClient


class FakeHttp:
    def __init__(self, responses=None, error: Exception | None = None) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.urls: list[str] = []

    async def get(self, url: str, **kwargs) -> HttpResponse:
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        status, body = self.responses.pop(0)
        return HttpResponse(
            status=status,
            headers={"content-type": "application/json"},
            body=json.dumps(body).encode() if not isinstance(body, bytes) else body,
            url=url,
            content_type="application/json",
        )


def test_npm_exists_and_missing() -> None:
    http = FakeHttp(
        [
            (
                200,
                {
                    "name": "left-pad",
                    "dist-tags": {"latest": "1.3.0"},
                    "versions": {"1.3.0": {}},
                    "maintainers": [{"name": "someone"}],
                    "repository": {"url": "git+https://github.com/stevemao/left-pad.git"},
                },
            ),
            (404, {}),
        ]
    )
    client = NpmRegistryClient(http)
    exists = asyncio.run(client.lookup("left-pad"))
    assert exists.exists and exists.latest_version == "1.3.0"
    assert exists.publisher == "someone"
    missing = asyncio.run(client.lookup("unclaimed-package"))
    assert missing.status.value == "MISSING"
    assert missing.http_status == 404
    assert missing.raw_summary["authoritative"]


def test_npm_server_error_is_error_not_missing() -> None:
    http = FakeHttp([(500, {})])
    result = asyncio.run(NpmRegistryClient(http).lookup("x"))
    assert result.status.value == "ERROR"
    assert result.exists is None


def test_registry_network_error_is_error() -> None:
    http = FakeHttp(error=NetworkError("timeout"))
    result = asyncio.run(NpmRegistryClient(http).lookup("x"))
    assert result.status.value == "ERROR"
    assert "timeout" in (result.error or "")


def test_invalid_json_is_error() -> None:
    http = FakeHttp([(200, b"not-json")])
    result = asyncio.run(PypiRegistryClient(http).lookup("x"))
    assert result.status.value == "ERROR"


def test_pypi_metadata() -> None:
    http = FakeHttp(
        [
            (
                200,
                {
                    "info": {
                        "version": "2.0.0",
                        "author": "Acme",
                        "project_urls": {"Source": "https://github.com/acme/lib"},
                    },
                    "releases": {"2.0.0": [], "1.0.0": []},
                    "urls": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
                },
            )
        ]
    )
    result = asyncio.run(PypiRegistryClient(http).lookup("acme-lib"))
    assert result.exists and result.latest_version == "2.0.0"
    assert result.repository_url == "https://github.com/acme/lib"
    assert result.versions_count == 2


class StubClient:
    def __init__(self, results) -> None:
        self.results = list(results)
        self.calls = 0

    async def lookup(self, name):
        self.calls += 1
        return self.results.pop(0)


def test_manager_caches_only_authoritative_answers(db) -> None:
    http = FakeHttp()
    manager = RegistryManager(db, http, ["npm"], cache_ttl_hours=24)
    stub = StubClient([__import__("tests.conftest", fromlist=["registry"]).registry("npm", "left-pad")])
    manager.clients["npm"] = stub
    first = asyncio.run(manager.lookup("npm", "left-pad"))
    second = asyncio.run(manager.lookup("npm", "left-pad"))
    assert first.status.value == "EXISTS"
    assert second.status.value == "EXISTS"
    assert second.raw_summary.get("cached") is True
    assert stub.calls == 1


def test_manager_does_not_cache_errors(db) -> None:
    from tests.conftest import registry
    from dephunter.core.models import RegistryStatus

    http = FakeHttp()
    manager = RegistryManager(db, http, ["npm"], cache_ttl_hours=24)
    stub = StubClient(
        [
            registry("npm", "x", status=RegistryStatus.ERROR, error="boom", http_status=None),
            registry("npm", "x", status=RegistryStatus.ERROR, error="boom", http_status=None),
        ]
    )
    manager.clients["npm"] = stub
    asyncio.run(manager.lookup("npm", "x"))
    asyncio.run(manager.lookup("npm", "x"))
    assert stub.calls == 2


def test_manager_skips_disabled_and_unknown(db) -> None:
    manager = RegistryManager(db, FakeHttp(), ["npm"])
    assert asyncio.run(manager.lookup("pypi", "x")).status.value == "SKIPPED"
    assert asyncio.run(manager.lookup("unknown", "x")).status.value == "SKIPPED"
