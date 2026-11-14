from __future__ import annotations

from dataclasses import replace

import pytest

from dephunter.analysis.engine import AnalysisEngine
from dephunter.core.models import RegistryResult, RegistryStatus
from dephunter.core.scope import ScopeConfig
from dephunter.analysis.routing import intent_signals, registry_facts
from tests.conftest import make_fact, make_ref, registry


class FakeManager:
    def __init__(self, results: dict[tuple[str, str], RegistryResult] | None = None) -> None:
        self.results = results or {}
        self.pairs: list[tuple[str, str]] = []

    async def lookup_many(self, pairs, *, progress=None):
        pair_list = list(pairs)
        self.pairs.extend(pair_list)
        output = []
        for ecosystem, name in pair_list:
            key = (ecosystem, name.lower())
            result = self.results.get(
                key,
                registry(ecosystem, name, publisher="other"),
            )
            output.append(result)
            if progress is not None:
                progress(result)
        return output


@pytest.mark.asyncio
async def test_high_confidence_missing_package(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(
        scan,
        [
            make_ref(
                "pypi",
                "acme-internal-lib",
                file_path="requirements.txt",
                source_url="https://github.com/acme/app/requirements.txt",
            )
        ],
    )
    manager = FakeManager({("pypi", "acme-internal-lib"): registry("pypi", "acme-internal-lib", status=RegistryStatus.MISSING, http_status=404)})
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 1
    findings = db.load_findings(scan)
    assert findings[0]["classification"] == "HIGH_CONFIDENCE"
    assert findings[0]["evidence"]["registry"]["status"] == "MISSING"


@pytest.mark.asyncio
async def test_confirmed_requires_public_resolution_contradiction(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(
        scan,
        [
            make_ref("npm", "@acme/internal-widget", source_kind="npm_manifest"),
            make_ref(
                "npm",
                "@acme/internal-widget",
                source_kind="npm_lockfile",
                resolved_url="https://registry.npmjs.org/@acme/internal-widget/-/internal-widget-1.0.0.tgz",
            ),
        ],
    )
    db.add_config_facts(
        scan, [make_fact("npm", "npm_default_registry", "https://npm.acme.example/repository/npm/", file_path=".npmrc")]
    )
    manager = FakeManager({("npm", "@acme/internal-widget"): registry("npm", "@acme/internal-widget")})
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 1
    finding = db.load_findings(scan)[0]
    assert finding["classification"] == "CONFIRMED"
    assert finding["resolution"]["mixed_provenance"] is True


@pytest.mark.asyncio
async def test_missing_package_cannot_be_confirmed(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(
        scan,
        [
            make_ref(
                "npm",
                "@acme/internal-widget",
                source_kind="npm_lockfile",
                resolved_url="https://registry.npmjs.org/@acme/internal-widget/-/internal-widget-1.0.0.tgz",
            )
        ],
    )
    db.add_config_facts(
        scan, [make_fact("npm", "npm_default_registry", "https://npm.acme.example/repository/npm/", file_path=".npmrc")]
    )
    manager = FakeManager(
        {("npm", "@acme/internal-widget"): registry("npm", "@acme/internal-widget", status=RegistryStatus.MISSING, http_status=404)}
    )
    await AnalysisEngine(db, scope, manager).analyze(scan)
    finding = db.load_findings(scan)[0]
    assert finding["classification"] == "HIGH_CONFIDENCE"


@pytest.mark.asyncio
async def test_private_pin_without_contradiction_is_insufficient(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(scan, [make_ref("npm", "@acme/internal-widget")])
    db.add_config_facts(
        scan, [make_fact("npm", "npm_default_registry", "https://npm.acme.example/repository/npm/", file_path=".npmrc")]
    )
    manager = FakeManager({("npm", "@acme/internal-widget"): registry("npm", "@acme/internal-widget")})
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 0
    assert result.by_confidence["INSUFFICIENT_EVIDENCE"] == 1


@pytest.mark.asyncio
async def test_owned_package_is_excluded(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(scan, [make_ref("pypi", "acme-internal-lib")])
    manager = FakeManager(
        {
            ("pypi", "acme-internal-lib"): registry(
                "pypi",
                "acme-internal-lib",
                publisher="acme",
                repository_url="https://github.com/acme/internal-lib",
            )
        }
    )
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 0


@pytest.mark.asyncio
async def test_registry_error_is_not_absence(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(scan, [make_ref("pypi", "acme-internal-lib")])
    manager = FakeManager(
        {
            ("pypi", "acme-internal-lib"): registry(
                "pypi",
                "acme-internal-lib",
                status=RegistryStatus.ERROR,
                error="timeout",
                http_status=None,
            )
        }
    )
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 0
    assert result.registry_errors == 1
    assert db.load_findings(scan) == []


@pytest.mark.asyncio
async def test_explicit_only_is_not_queried(db, scope) -> None:
    scan = db.create_scan("test", None, {})
    db.add_dependencies(
        scan, [make_ref("pypi", "acme-internal", explicit_source=True)]
    )
    manager = FakeManager()
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.groups == 1
    assert manager.pairs == []
    assert result.findings == 0


@pytest.mark.asyncio
async def test_docker_confirmed_is_capped(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scan = db.create_scan("test", None, {})
    db.add_dependencies(scan, [make_ref("docker", "acme/internal-api")])
    manager = FakeManager({("docker", "acme/internal-api"): registry("docker", "acme/internal-api")})
    await AnalysisEngine(db, scope, manager).analyze(scan)
    finding = db.load_findings(scan)[0]
    assert finding["classification"] == "CANDIDATE"


@pytest.mark.asyncio
async def test_query_limit(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scope.registries.query_limit = 1
    scan = db.create_scan("test", None, {})
    db.add_dependencies(
        scan,
        [
            make_ref("npm", "@acme/one"),
            make_ref("pypi", "acme-two"),
        ],
    )
    manager = FakeManager()
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.queried == 1
    assert result.skipped_by_limit == 1
    assert len(manager.pairs) == 1


@pytest.mark.asyncio
async def test_min_classification_filter(db, scope) -> None:
    scope.analysis.org_patterns = ["acme"]
    scope.analysis.min_classification = "CONFIRMED"
    scan = db.create_scan("test", None, {})
    db.add_dependencies(scan, [make_ref("pypi", "acme-internal-lib")])
    manager = FakeManager({("pypi", "acme-internal-lib"): registry("pypi", "acme-internal-lib", status=RegistryStatus.MISSING, http_status=404)})
    result = await AnalysisEngine(db, scope, manager).analyze(scan)
    assert result.findings == 0
    assert result.by_confidence["HIGH_CONFIDENCE"] == 1
    assert db.load_findings(scan) == []


def test_registry_facts_includes_routing_only_types() -> None:
    facts = [
        make_fact("pypi", "pip_no_index", "true"),
        make_fact("nuget", "nuget_clear_sources", "true"),
        make_fact("nuget", "nuget_source_mapping", "Acme.*=internal"),
        make_fact("packagist", "composer_packagist_disabled", "true"),
    ]
    assert len(registry_facts("pypi", facts)) == 1
    assert len(registry_facts("nuget", facts)) == 2
    assert len(registry_facts("packagist", facts)) == 1


def test_intent_signals_private_npm_marker() -> None:
    ref = make_ref("npm", "acme-internal")
    fact = make_fact("npm", "npm_private_package", "true", extra={"package": "acme-internal"})
    internal, reasons = intent_signals("npm", "acme-internal", [ref], [fact], [], [])
    assert internal
    assert any("private" in reason for reason in reasons)
