from __future__ import annotations

import asyncio
import time

from dephunter.core.models import ScanStatus
from tests.conftest import make_fact, make_ref


def test_dependency_deduplication(db) -> None:
    scan = db.create_scan("test", None, {})
    ref = make_ref("npm", "left-pad")
    assert db.add_dependencies(scan, [ref]) == 1
    assert db.add_dependencies(scan, [ref]) == 0
    assert len(db.load_dependencies(scan)) == 1


def test_config_fact_deduplication(db) -> None:
    scan = db.create_scan("test", None, {})
    fact = make_fact("npm", "npm_default_registry", "https://registry.npmjs.org/")
    assert db.add_config_facts(scan, [fact]) == 1
    assert db.add_config_facts(scan, [fact]) == 0


def test_cache_ttl(db) -> None:
    db.cache_put("npm:x", {"status": "EXISTS"}, 200, ttl_seconds=60)
    assert db.cache_get("npm:x") is not None
    db.cache_put("npm:y", {"status": "EXISTS"}, 200, ttl_seconds=1)
    time.sleep(1.1)
    assert db.cache_get("npm:y") is None


def test_scan_lifecycle_and_stats(db) -> None:
    scan = db.create_scan("program", "scope.yaml", {"program": "program"})
    db.update_scan(scan, status=ScanStatus.RUNNING, phase="crawl")
    row = db.get_scan(scan)
    assert row["status"] == "RUNNING"
    assert row["phase"] == "crawl"
    assert db.latest_scan()["id"] == scan
    assert any(item["id"] == scan for item in db.list_scans())
    assert db.stats(scan)["dependencies"] == 0


def test_asset_resume_queue(db) -> None:
    scan = db.create_scan("test", None, {})
    assert db.add_asset(scan, "https://example.com/", "https://example.com/", "page", 0, None)
    assert not db.add_asset(scan, "https://example.com/", "https://example.com/", "page", 0, None)
    assert db.count_assets(scan) == 1
    pending = db.pending_assets(scan)
    assert len(pending) == 1
    db.update_asset(pending[0]["id"], "FETCHED", http_status=200)
    assert db.pending_assets(scan) == []
    assert db.count_assets(scan) == 1


def test_repo_file_resume(db) -> None:
    scan = db.create_scan("test", None, {})
    assert db.add_repo_file(
        scan, "github", "acme/app", "package.json", "main", "https://github.com/acme/app/package.json"
    )
    assert db.has_repo_file(scan, "acme/app", "package.json", "main")
    db.update_repo_file(scan, "acme/app", "package.json", "main", "PARSED")
    files = db.repo_files_for_scan(scan)
    assert files[0]["status"] == "PARSED"
