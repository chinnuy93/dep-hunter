from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from dephunter.core.models import (
    Assessment,
    ConfigFact,
    DependencyRef,
    RegistryResult,
    ScanStatus,
)
from dephunter.core.names import normalize_package_name
from dephunter.core.util import utc_iso

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    scope_path TEXT,
    scope_json TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error TEXT,
    stats_json TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    kind TEXT NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'PENDING',
    http_status INTEGER,
    content_type TEXT,
    sha256 TEXT,
    evidence_path TEXT,
    error TEXT,
    discovered_from TEXT,
    fetched_at TEXT,
    UNIQUE(scan_id, canonical_url)
);
CREATE INDEX IF NOT EXISTS idx_assets_scan_status ON assets(scan_id, status);

CREATE TABLE IF NOT EXISTS repo_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    repo TEXT NOT NULL,
    path TEXT NOT NULL,
    ref TEXT NOT NULL,
    commit_sha TEXT,
    source_url TEXT NOT NULL,
    sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    error TEXT,
    fetched_at TEXT,
    UNIQUE(scan_id, repo, path, ref)
);
CREATE INDEX IF NOT EXISTS idx_repo_files_scan ON repo_files(scan_id, repo);

CREATE TABLE IF NOT EXISTS dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    normalized TEXT NOT NULL,
    version_constraint TEXT,
    source_kind TEXT NOT NULL,
    source_url TEXT NOT NULL,
    file_path TEXT,
    line INTEGER,
    commit_sha TEXT,
    repo TEXT,
    resolved_url TEXT,
    explicit_source INTEGER NOT NULL DEFAULT 0,
    is_direct INTEGER NOT NULL DEFAULT 1,
    groups_json TEXT,
    extra_json TEXT,
    dedupe_key TEXT NOT NULL,
    UNIQUE(scan_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_dependencies_scan ON dependencies(scan_id, ecosystem, normalized);

CREATE TABLE IF NOT EXISTS config_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_url TEXT NOT NULL,
    file_path TEXT,
    line INTEGER,
    extra_json TEXT,
    dedupe_key TEXT NOT NULL,
    UNIQUE(scan_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_config_facts_scan ON config_facts(scan_id, ecosystem, fact_type);

CREATE TABLE IF NOT EXISTS registry_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    http_status INTEGER,
    fetched_at REAL NOT NULL,
    ttl_seconds INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS registry_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    normalized TEXT NOT NULL,
    status TEXT NOT NULL,
    exists_flag INTEGER,
    latest_version TEXT,
    versions_count INTEGER,
    publisher TEXT,
    publisher_url TEXT,
    repository_url TEXT,
    first_published TEXT,
    last_published TEXT,
    url TEXT,
    http_status INTEGER,
    error TEXT,
    checked_at TEXT NOT NULL,
    raw_json TEXT,
    UNIQUE(scan_id, ecosystem, normalized)
);
CREATE INDEX IF NOT EXISTS idx_registry_checks_scan ON registry_checks(scan_id, status);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    normalized TEXT NOT NULL,
    classification TEXT NOT NULL,
    score INTEGER NOT NULL,
    title TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    missing_json TEXT NOT NULL,
    resolution_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    cwe_primary TEXT NOT NULL,
    cwe_secondary TEXT NOT NULL,
    registry_check_id INTEGER REFERENCES registry_checks(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, ecosystem, normalized)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, classification);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self.initialize()

    def initialize(self) -> None:
        with self._lock, self._conn:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema version {version} is newer than supported {SCHEMA_VERSION}"
                )
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _one(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(query, params).fetchone()

    def _all(self, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(query, params).fetchall())

    def create_scan(self, program: str, scope_path: str | None, scope_json: dict[str, Any]) -> int:
        now = utc_iso()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO scans(program, scope_path, scope_json, status, phase, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    program,
                    scope_path,
                    json.dumps(scope_json, separators=(",", ":")),
                    ScanStatus.CREATED.value,
                    "init",
                    now,
                    now,
                ),
            )
            return int(cursor.lastrowid)

    def update_scan(
        self,
        scan_id: int,
        *,
        status: ScanStatus | str | None = None,
        phase: str | None = None,
        error: str | None = None,
        stats: dict[str, Any] | None = None,
    ) -> None:
        fields: list[str] = ["updated_at = ?"]
        params: list[Any] = [utc_iso()]
        if status is not None:
            fields.append("status = ?")
            params.append(str(status))
        if phase is not None:
            fields.append("phase = ?")
            params.append(phase)
        if error is not None:
            fields.append("error = ?")
            params.append(error)
        if stats is not None:
            fields.append("stats_json = ?")
            params.append(json.dumps(stats, separators=(",", ":")))
        params.append(scan_id)
        with self._lock, self._conn:
            self._conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", tuple(params))

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return _scan_row(row) if row else None

    def latest_scan(self) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        return _scan_row(row) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._all("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [_scan_row(row) for row in rows]

    def add_asset(
        self,
        scan_id: int,
        url: str,
        canonical: str,
        kind: str,
        depth: int = 0,
        discovered_from: str | None = None,
    ) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO assets(scan_id, url, canonical_url, kind, depth, status, discovered_from) "
                "VALUES (?, ?, ?, ?, ?, 'PENDING', ?)",
                (scan_id, url, canonical, kind, depth, discovered_from),
            )
            return cursor.rowcount > 0

    def pending_assets(self, scan_id: int, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT * FROM assets WHERE scan_id = ? AND status = 'PENDING' ORDER BY depth, id LIMIT ?",
            (scan_id, limit),
        )
        return [dict(row) for row in rows]

    def count_pending_assets(self, scan_id: int) -> int:
        row = self._one(
            "SELECT COUNT(*) AS n FROM assets WHERE scan_id = ? AND status = 'PENDING'", (scan_id,)
        )
        return int(row["n"]) if row else 0

    def count_assets(self, scan_id: int) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM assets WHERE scan_id = ?", (scan_id,))
        return int(row["n"]) if row else 0

    def update_asset(
        self,
        asset_id: int,
        status: str,
        *,
        http_status: int | None = None,
        content_type: str | None = None,
        sha256: str | None = None,
        evidence_path: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE assets SET status = ?, http_status = ?, content_type = ?, sha256 = ?, "
                "evidence_path = ?, error = ?, fetched_at = ? WHERE id = ?",
                (
                    status,
                    http_status,
                    content_type,
                    sha256,
                    evidence_path,
                    error,
                    utc_iso() if status in {"FETCHED", "PARSED", "ERROR", "DISALLOWED"} else None,
                    asset_id,
                ),
            )

    def add_repo_file(
        self,
        scan_id: int,
        source: str,
        repo: str,
        path: str,
        ref: str,
        source_url: str,
        commit: str | None = None,
        sha256: str | None = None,
        status: str = "FETCHED",
        error: str | None = None,
    ) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO repo_files(scan_id, source, repo, path, ref, commit_sha, source_url, "
                "sha256, status, error, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, source, repo, path, ref, commit, source_url, sha256, status, error, utc_iso()),
            )
            return cursor.rowcount > 0

    def update_repo_file(self, scan_id: int, repo: str, path: str, ref: str, status: str, error: str | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE repo_files SET status = ?, error = ?, fetched_at = ? "
                "WHERE scan_id = ? AND repo = ? AND path = ? AND ref = ?",
                (status, error, utc_iso(), scan_id, repo, path, ref),
            )

    def has_repo_file(self, scan_id: int, repo: str, path: str, ref: str) -> bool:
        row = self._one(
            "SELECT 1 AS x FROM repo_files WHERE scan_id = ? AND repo = ? AND path = ? AND ref = ?",
            (scan_id, repo, path, ref),
        )
        return row is not None

    def add_dependencies(self, scan_id: int, dependencies: Iterable[DependencyRef]) -> int:
        rows = []
        for dep in dependencies:
            rows.append(
                (
                    scan_id,
                    dep.ecosystem,
                    dep.name,
                    dep.normalized,
                    dep.version,
                    dep.source_kind,
                    dep.source_url,
                    dep.file_path,
                    dep.line,
                    dep.commit,
                    dep.repo,
                    dep.resolved_url,
                    1 if dep.explicit_source else 0,
                    1 if dep.direct else 0,
                    json.dumps(dep.groups),
                    json.dumps(dep.extra, separators=(",", ":"), default=str),
                    dep.dedupe_key(),
                )
            )
        if not rows:
            return 0
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT OR IGNORE INTO dependencies(scan_id, ecosystem, name, normalized, version_constraint, "
                "source_kind, source_url, file_path, line, commit_sha, repo, resolved_url, explicit_source, "
                "is_direct, groups_json, extra_json, dedupe_key) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            return self._conn.total_changes - before

    def add_config_facts(self, scan_id: int, facts: Iterable[ConfigFact]) -> int:
        rows = []
        for fact in facts:
            rows.append(
                (
                    scan_id,
                    fact.ecosystem,
                    fact.fact_type,
                    fact.value,
                    fact.source_kind,
                    fact.source_url,
                    fact.file_path,
                    fact.line,
                    json.dumps(fact.extra, separators=(",", ":"), default=str),
                    fact.dedupe_key(),
                )
            )
        if not rows:
            return 0
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT OR IGNORE INTO config_facts(scan_id, ecosystem, fact_type, value, source_kind, "
                "source_url, file_path, line, extra_json, dedupe_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            return self._conn.total_changes - before

    def load_dependencies(self, scan_id: int) -> list[DependencyRef]:
        rows = self._all("SELECT * FROM dependencies WHERE scan_id = ? ORDER BY id", (scan_id,))
        result: list[DependencyRef] = []
        for row in rows:
            result.append(
                DependencyRef(
                    ecosystem=row["ecosystem"],
                    name=row["name"],
                    normalized=row["normalized"],
                    version=row["version_constraint"],
                    source_kind=row["source_kind"],
                    source_url=row["source_url"],
                    file_path=row["file_path"],
                    line=row["line"],
                    commit=row["commit_sha"],
                    repo=row["repo"],
                    resolved_url=row["resolved_url"],
                    explicit_source=bool(row["explicit_source"]),
                    direct=bool(row["is_direct"]),
                    groups=json.loads(row["groups_json"] or "[]"),
                    extra=json.loads(row["extra_json"] or "{}"),
                )
            )
        return result

    def load_config_facts(self, scan_id: int) -> list[ConfigFact]:
        rows = self._all("SELECT * FROM config_facts WHERE scan_id = ? ORDER BY id", (scan_id,))
        result: list[ConfigFact] = []
        for row in rows:
            result.append(
                ConfigFact(
                    ecosystem=row["ecosystem"],
                    fact_type=row["fact_type"],
                    value=row["value"],
                    source_kind=row["source_kind"],
                    source_url=row["source_url"],
                    file_path=row["file_path"],
                    line=row["line"],
                    extra=json.loads(row["extra_json"] or "{}"),
                )
            )
        return result

    def clear_analysis(self, scan_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            self._conn.execute("DELETE FROM registry_checks WHERE scan_id = ?", (scan_id,))

    def insert_registry_checks(self, scan_id: int, results: Iterable[RegistryResult]) -> dict[tuple[str, str], int]:
        mapping: dict[tuple[str, str], int] = {}
        with self._lock, self._conn:
            for result in results:
                normalized = normalize_package_name(result.ecosystem, result.name)
                cursor = self._conn.execute(
                    "INSERT OR REPLACE INTO registry_checks(scan_id, ecosystem, name, normalized, status, "
                    "exists_flag, latest_version, versions_count, publisher, publisher_url, repository_url, "
                    "first_published, last_published, url, http_status, error, checked_at, raw_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        result.ecosystem,
                        result.name,
                        normalized,
                        result.status.value,
                        None if result.exists is None else (1 if result.exists else 0),
                        result.latest_version,
                        result.versions_count,
                        result.publisher,
                        result.publisher_url,
                        result.repository_url,
                        result.first_published,
                        result.last_published,
                        result.url,
                        result.http_status,
                        result.error,
                        result.checked_at or utc_iso(),
                        json.dumps(result.raw_summary, separators=(",", ":"), default=str),
                    ),
                )
                mapping[(result.ecosystem, normalized)] = int(cursor.lastrowid)
        return mapping

    def insert_findings(
        self,
        scan_id: int,
        assessments: Iterable[Assessment],
        registry_ids: dict[tuple[str, str], int],
    ) -> int:
        rows = []
        now = utc_iso()
        for assessment in assessments:
            refs = sorted(assessment.refs, key=lambda r: (not r.direct, r.source_url))
            ref_payload = [
                {
                    "source_kind": ref.source_kind,
                    "source_url": ref.source_url,
                    "file_path": ref.file_path,
                    "line": ref.line,
                    "commit": ref.commit,
                    "repo": ref.repo,
                    "version_constraint": ref.version,
                    "resolved_url": ref.resolved_url,
                    "explicit_source": ref.explicit_source,
                    "direct": ref.direct,
                    "groups": ref.groups,
                }
                for ref in refs[:100]
            ]
            facts = [
                {
                    "fact_type": fact.fact_type,
                    "value": fact.value,
                    "source_url": fact.source_url,
                    "file_path": fact.file_path,
                    "line": fact.line,
                }
                for fact in assessment.facts[:40]
            ]
            evidence = {
                "refs": ref_payload,
                "ref_count": len(refs),
                "facts": facts,
                "registry": assessment.registry.to_json() if assessment.registry else None,
                "resolution": assessment.resolution.to_json(),
                "publisher_relation": assessment.publisher_relation,
                "intent": assessment.intent,
            }
            rows.append(
                (
                    scan_id,
                    assessment.ecosystem,
                    assessment.name,
                    assessment.normalized,
                    assessment.classification.value,
                    assessment.score,
                    assessment.title,
                    json.dumps(assessment.reasons, default=str),
                    json.dumps(assessment.missing_evidence, default=str),
                    json.dumps(assessment.resolution.to_json(), default=str),
                    json.dumps(evidence, default=str),
                    assessment.cwe_primary,
                    assessment.cwe_secondary,
                    registry_ids.get((assessment.ecosystem, assessment.normalized)),
                    now,
                )
            )
        if not rows:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings(scan_id, ecosystem, name, normalized, classification, score, "
                "title, reasons_json, missing_json, resolution_json, evidence_json, cwe_primary, cwe_secondary, "
                "registry_check_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def load_findings(self, scan_id: int, min_classification: str | None = None) -> list[dict[str, Any]]:
        rows = self._all("SELECT * FROM findings WHERE scan_id = ? ORDER BY score DESC, id", (scan_id,))
        findings: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for key in ("reasons_json", "missing_json", "resolution_json", "evidence_json"):
                item[key.replace("_json", "")] = json.loads(item.pop(key) or "{}")
            if min_classification:
                from dephunter.core.models import CONFIDENCE_ORDER

                if CONFIDENCE_ORDER.get(item["classification"], -1) < CONFIDENCE_ORDER.get(min_classification, 0):
                    continue
            findings.append(item)
        return findings

    def cache_get(self, cache_key: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM registry_cache WHERE cache_key = ?", (cache_key,))
        if not row:
            return None
        if time.time() > float(row["fetched_at"]) + int(row["ttl_seconds"]):
            return None
        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError:
            return None
        return {"payload": payload, "http_status": row["http_status"], "fetched_at": row["fetched_at"]}

    def cache_put(self, cache_key: str, payload: Any, http_status: int | None, ttl_seconds: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO registry_cache(cache_key, payload, http_status, fetched_at, ttl_seconds) "
                "VALUES (?, ?, ?, ?, ?)",
                (cache_key, json.dumps(payload, separators=(",", ":"), default=str), http_status, time.time(), ttl_seconds),
            )

    def stats(self, scan_id: int) -> dict[str, Any]:
        asset_rows = self._all(
            "SELECT status, COUNT(*) AS n FROM assets WHERE scan_id = ? GROUP BY status", (scan_id,)
        )
        repo_rows = self._all(
            "SELECT status, COUNT(*) AS n FROM repo_files WHERE scan_id = ? GROUP BY status", (scan_id,)
        )
        registry_rows = self._all(
            "SELECT status, COUNT(*) AS n FROM registry_checks WHERE scan_id = ? GROUP BY status", (scan_id,)
        )
        finding_rows = self._all(
            "SELECT classification, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY classification",
            (scan_id,),
        )
        dep_count = self._one("SELECT COUNT(*) AS n FROM dependencies WHERE scan_id = ?", (scan_id,))
        fact_count = self._one("SELECT COUNT(*) AS n FROM config_facts WHERE scan_id = ?", (scan_id,))
        return {
            "assets": _group_counts(asset_rows),
            "repo_files": _group_counts(repo_rows),
            "registry_checks": _group_counts(registry_rows),
            "dependencies": int(dep_count["n"]) if dep_count else 0,
            "config_facts": int(fact_count["n"]) if fact_count else 0,
            "findings": _group_counts(finding_rows, key="classification"),
        }

    def assets_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        return [dict(row) for row in self._all("SELECT * FROM assets WHERE scan_id = ? ORDER BY id", (scan_id,))]

    def repo_files_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        return [dict(row) for row in self._all("SELECT * FROM repo_files WHERE scan_id = ? ORDER BY id", (scan_id,))]


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    try:
        item["scope"] = json.loads(item.pop("scope_json"))
    except (json.JSONDecodeError, KeyError, TypeError):
        item["scope"] = {}
    try:
        item["stats"] = json.loads(item.pop("stats_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        item["stats"] = {}
    return item


def _group_counts(rows: list[sqlite3.Row], key: str = "status") -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        result[str(row[key])] = int(row["n"])
    result["total"] = sum(result.values())
    return result
