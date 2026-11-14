from __future__ import annotations

from pathlib import Path

import pytest

from dephunter.core.models import ConfigFact, DependencyRef, RegistryResult, RegistryStatus
from dephunter.core.scope import ScopeConfig
from dephunter.database.db import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "test.sqlite3")
    try:
        yield database
    finally:
        database.close()


@pytest.fixture()
def scope() -> ScopeConfig:
    return ScopeConfig(program="Test Program", authorization="Authorized test engagement ref TEST-1")


def make_ref(
    ecosystem: str,
    name: str,
    *,
    normalized: str | None = None,
    version: str | None = "1.0.0",
    source_kind: str = "manifest",
    source_url: str | None = None,
    resolved_url: str | None = None,
    explicit_source: bool = False,
    direct: bool = True,
    repo: str | None = "acme/app",
    file_path: str | None = None,
    extra: dict | None = None,
) -> DependencyRef:
    return DependencyRef(
        ecosystem=ecosystem,
        name=name,
        normalized=normalized or name.lower(),
        version=version,
        source_kind=source_kind,
        source_url=source_url or f"https://github.com/acme/app/{file_path or 'package.json'}",
        resolved_url=resolved_url,
        explicit_source=explicit_source,
        direct=direct,
        repo=repo,
        file_path=file_path,
        extra=extra or {},
    )


def make_fact(
    ecosystem: str,
    fact_type: str,
    value: str,
    *,
    source_kind: str = "config",
    source_url: str | None = None,
    file_path: str | None = None,
    extra: dict | None = None,
) -> ConfigFact:
    return ConfigFact(
        ecosystem=ecosystem,
        fact_type=fact_type,
        value=value,
        source_kind=source_kind,
        source_url=source_url or f"https://github.com/acme/app/{file_path or 'config'}",
        file_path=file_path,
        extra=extra or {},
    )


def registry(
    ecosystem: str,
    name: str,
    *,
    status: RegistryStatus = RegistryStatus.EXISTS,
    publisher: str | None = "someone",
    repository_url: str | None = None,
    latest_version: str | None = "1.0.0",
    http_status: int | None = 200,
    error: str | None = None,
    raw: dict | None = None,
) -> RegistryResult:
    exists = status == RegistryStatus.EXISTS if status in {RegistryStatus.EXISTS, RegistryStatus.MISSING} else None
    return RegistryResult(
        ecosystem=ecosystem,
        name=name,
        status=status,
        exists=exists,
        latest_version=latest_version if exists else None,
        publisher=publisher if exists else None,
        repository_url=repository_url,
        http_status=http_status,
        error=error,
        checked_at="2026-01-01T00:00:00+00:00",
        raw_summary=raw or {},
    )
