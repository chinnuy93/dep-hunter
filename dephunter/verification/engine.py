from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dephunter.core.models import Confidence, RegistryStatus
from dephunter.database.db import Database

PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(slots=True)
class VerificationCheck:
    name: str
    status: str
    detail: str

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(slots=True)
class FindingVerification:
    finding_key: str
    ecosystem: str
    package: str
    classification: str
    verdict: str
    checks: list[VerificationCheck] = field(default_factory=list)
    allowed_claim: str = ""
    prohibited_claims: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == "READY_FOR_REVIEW"

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "classification": self.classification,
            "verdict": self.verdict,
            "checks": [check.to_json() for check in self.checks],
            "allowed_claim": self.allowed_claim,
            "prohibited_claims": list(self.prohibited_claims),
        }


@dataclass(slots=True)
class VerificationSummary:
    total: int = 0
    ready: int = 0
    needs_review: int = 0
    invalid: int = 0
    results: list[FindingVerification] = field(default_factory=list)


PROHIBITED_CLAIMS = [
    "That a package has been published, claimed, or reserved by anyone.",
    "That the target is exploitable or that a takeover has occurred.",
    "That installing the dependency was observed or tested.",
]


def verify_finding(finding: dict[str, Any]) -> FindingVerification:
    classification = str(finding.get("classification") or "")
    evidence = finding.get("evidence") or {}
    registry = evidence.get("registry") or {}
    resolution = finding.get("resolution") or {}
    reasons = finding.get("reasons") or []
    checks: list[VerificationCheck] = []

    status = registry.get("status")
    http_status = registry.get("http_status")
    authoritative = status in {RegistryStatus.EXISTS.value, RegistryStatus.MISSING.value} and http_status in {200, 404}
    if status == RegistryStatus.MISSING.value and http_status != 404:
        authoritative = False
    checks.append(
        VerificationCheck(
            "authoritative_registry_response",
            PASS if authoritative else FAIL,
            f"registry status={status or 'missing'}, HTTP={http_status if http_status is not None else 'none'}",
        )
    )

    refs = evidence.get("refs") or []
    located = [ref for ref in refs if ref.get("source_url")]
    checks.append(
        VerificationCheck(
            "reproducible_locators",
            PASS if located else FAIL,
            f"{len(located)} dependency occurrence(s) have source URLs",
        )
    )

    relation = str(evidence.get("publisher_relation") or "UNKNOWN")
    checks.append(
        VerificationCheck(
            "ownership_not_visible",
            FAIL if relation == "OWN_LIKELY" else PASS,
            f"publisher relation={relation}",
        )
    )

    if classification == Confidence.CONFIRMED.value:
        contradiction = bool(resolution.get("mixed_provenance")) and bool(evidence.get("registry", {}).get("exists"))
        checks.append(
            VerificationCheck(
                "static_resolution_contradiction",
                PASS if contradiction else FAIL,
                "CONFIRMED requires both public resolution evidence and private routing configuration",
            )
        )
    else:
        checks.append(
            VerificationCheck(
                "static_resolution_contradiction",
                NOT_APPLICABLE,
                "only required for CONFIRMED classification",
            )
        )

    explicit = [ref for ref in refs if ref.get("explicit_source")]
    checks.append(
        VerificationCheck(
            "explicit_sources_excluded",
            FAIL if explicit else PASS,
            f"{len(explicit)} explicit local/VCS/direct-URL occurrence(s) included",
        )
    )

    checks.append(
        VerificationCheck(
            "no_active_actions",
            PASS,
            "no package publication, installation, callback, or target-side action was performed",
        )
    )

    checks.append(
        VerificationCheck(
            "classification_supported",
            PASS if classification in {c.value for c in Confidence} else FAIL,
            f"classification={classification or 'missing'}, reasons={len(reasons)}",
        )
    )

    failed = [check for check in checks if check.status == FAIL]
    if failed:
        verdict = "INVALID"
    elif classification == Confidence.CANDIDATE.value:
        verdict = "NEEDS_REVIEW"
    else:
        verdict = "READY_FOR_REVIEW"

    allowed = _allowed_claim(classification)
    return FindingVerification(
        finding_key=f"{finding.get('ecosystem')}:{finding.get('normalized') or finding.get('name')}",
        ecosystem=str(finding.get("ecosystem") or ""),
        package=str(finding.get("name") or ""),
        classification=classification,
        verdict=verdict,
        checks=checks,
        allowed_claim=allowed,
        prohibited_claims=list(PROHIBITED_CLAIMS),
    )


def _allowed_claim(classification: str) -> str:
    if classification == Confidence.CONFIRMED.value:
        return (
            "Static evidence is consistent with a dependency-confusion path: an internal-looking "
            "name is publicly present and private/public resolution evidence contradicts. "
            "Target-side confirmation was not performed."
        )
    if classification == Confidence.HIGH_CONFIDENCE.value:
        return (
            "Static evidence indicates a high-confidence dependency-confusion risk based on "
            "internal intent and public resolution routing. Authorized confirmation is still required."
        )
    if classification == Confidence.CANDIDATE.value:
        return (
            "The name and public registry state are candidates for manual review. "
            "Unintended dependency resolution was not established."
        )
    return "Insufficient static evidence; do not report this item as a vulnerability."


def verify_scan(db: Database, scan_id: int) -> VerificationSummary:
    summary = VerificationSummary()
    for finding in db.load_findings(scan_id):
        item = verify_finding(finding)
        summary.results.append(item)
        summary.total += 1
        if item.verdict == "READY_FOR_REVIEW":
            summary.ready += 1
        elif item.verdict == "NEEDS_REVIEW":
            summary.needs_review += 1
        else:
            summary.invalid += 1
    return summary
