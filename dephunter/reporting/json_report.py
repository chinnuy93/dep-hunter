from __future__ import annotations

import json

from dephunter.reporting.base import ReportContext, to_jsonable


def render(context: ReportContext) -> str:
    payload = {
        "tool": "dep-hunter",
        "tool_version": context.tool_version,
        "generated_at": context.generated_at,
        "scan": {
            "id": context.scan_id,
            "program": context.program,
            "status": context.scan.get("status"),
            "phase": context.scan.get("phase"),
            "created_at": context.scan.get("created_at"),
            "updated_at": context.scan.get("updated_at"),
            "scope": context.scan.get("scope") or {},
        },
        "runtime": to_jsonable(context.runtime),
        "progress_percent": context.progress_percent,
        "summary": {
            "dependencies": context.stats.get("dependencies", 0),
            "config_facts": context.stats.get("config_facts", 0),
            "registry_checks": context.stats.get("registry_checks", {}),
            "findings_by_confidence": context.confidence_counts(),
            "verification": context.verification_counts(),
        },
        "findings": [],
    }
    for finding in context.sorted_findings():
        verification = context.verification_for(finding)
        item = {
            "ecosystem": finding.get("ecosystem"),
            "name": finding.get("name"),
            "normalized": finding.get("normalized"),
            "classification": finding.get("classification"),
            "score": finding.get("score"),
            "title": finding.get("title"),
            "cwe_primary": finding.get("cwe_primary"),
            "cwe_secondary": finding.get("cwe_secondary"),
            "reasons": finding.get("reasons") or [],
            "missing_evidence": finding.get("missing") or [],
            "resolution": finding.get("resolution") or {},
            "evidence": finding.get("evidence") or {},
            "verification": verification.to_json() if hasattr(verification, "to_json") else None,
        }
        payload["findings"].append(to_jsonable(item))
    return json.dumps(payload, indent=2, sort_keys=False, default=str) + "\n"
