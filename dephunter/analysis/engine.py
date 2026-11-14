from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from dephunter.analysis.routing import (
    assess_resolution,
    classify_registry_value,
    docker_namespace_claimable,
    intent_signals,
    ref_scope_key,
    registry_facts,
)
from dephunter.core.models import (
    CONFIDENCE_ORDER,
    Assessment,
    Confidence,
    ConfigFact,
    DependencyRef,
    RegistryResult,
    RegistryStatus,
    ResolutionAssessment,
)
from dephunter.core.names import (
    NPM_BUILTINS,
    normalize_package_name,
    relation_to_target,
)
from dephunter.core.scope import ScopeConfig
from dephunter.database.db import Database
from dephunter.registries.manager import RegistryManager

log = logging.getLogger(__name__)

_MAX_CONFIDENCE = {
    "maven": Confidence.HIGH_CONFIDENCE,
    "nuget": Confidence.HIGH_CONFIDENCE,
    "go": Confidence.CANDIDATE,
    "docker": Confidence.CANDIDATE,
}


@dataclass(slots=True)
class AnalysisResult:
    groups: int = 0
    dependencies: int = 0
    queried: int = 0
    findings: int = 0
    skipped_by_limit: int = 0
    registry_errors: int = 0
    by_confidence: dict[str, int] = field(default_factory=dict)


class AnalysisEngine:
    def __init__(
        self,
        db: Database,
        scope: ScopeConfig,
        manager: RegistryManager,
        *,
        progress: Callable[[int, int], None] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.db = db
        self.scope = scope
        self.manager = manager
        self.progress = progress
        self.log = logger or log
        self.org_patterns = scope.org_patterns()
        self.keywords = scope.analysis.internal_keywords
        self.min_classification = scope.analysis.min_classification

    async def analyze(self, scan_id: int) -> AnalysisResult:
        result = AnalysisResult()
        dependencies = self.db.load_dependencies(scan_id)
        facts = self.db.load_config_facts(scan_id)
        result.dependencies = len(dependencies)
        if not dependencies:
            self.db.clear_analysis(scan_id)
            return result

        groups = self._group(dependencies)
        result.groups = len(groups)
        facts_by_scope = self._facts_by_scope(facts)
        enabled = {ecosystem.lower() for ecosystem in self.scope.enabled_ecosystems}
        plans = self._plan(groups, facts_by_scope, enabled)
        limit = max(1, self.scope.registries.query_limit)
        selected = plans[:limit]
        result.skipped_by_limit = max(0, len(plans) - len(selected))

        pairs = [(plan["ecosystem"], plan["name"]) for plan in selected]
        if self.progress is not None:
            self.progress(0, len(selected))
        checked = 0

        def _checked(_: RegistryResult) -> None:
            nonlocal checked
            checked += 1
            if self.progress is not None:
                self.progress(checked, len(selected))

        registry_results = await self.manager.lookup_many(pairs, progress=_checked)
        registry_map: dict[tuple[str, str], RegistryResult] = {}
        for registry_result in registry_results:
            key = (
                registry_result.ecosystem,
                normalize_package_name(registry_result.ecosystem, registry_result.name),
            )
            registry_map[key] = registry_result
            if registry_result.status == RegistryStatus.ERROR:
                result.registry_errors += 1
        result.queried = len(selected)

        assessments: list[Assessment] = []
        planned_keys = {(plan["ecosystem"], plan["normalized"]) for plan in selected}
        for key, refs in groups.items():
            ecosystem, normalized = key
            name = self._display_name(refs)
            registry_result = registry_map.get(key)
            if key not in planned_keys:
                assessment = self._insufficient(
                    ecosystem,
                    name,
                    normalized,
                    refs,
                    "registry lookup not performed (query limit or disabled ecosystem)",
                )
            else:
                assessment = self._evaluate(
                    ecosystem,
                    name,
                    normalized,
                    refs,
                    facts_by_scope,
                    registry_result,
                )
            assessments.append(assessment)

        self.db.clear_analysis(scan_id)
        if registry_results:
            registry_ids = self.db.insert_registry_checks(scan_id, registry_results)
        else:
            registry_ids = {}
        threshold = CONFIDENCE_ORDER[Confidence(self.min_classification)]
        reportable = [
            assessment
            for assessment in assessments
            if assessment.registry is not None
            and CONFIDENCE_ORDER[assessment.classification] >= threshold
        ]
        reportable.sort(
            key=lambda item: (CONFIDENCE_ORDER[item.classification], item.score),
            reverse=True,
        )
        if reportable:
            self.db.insert_findings(scan_id, reportable, registry_ids)
        result.findings = len(reportable)
        counts: dict[str, int] = defaultdict(int)
        for assessment in assessments:
            counts[assessment.classification.value] += 1
        result.by_confidence = dict(counts)
        return result

    def _group(self, dependencies: list[DependencyRef]) -> dict[tuple[str, str], list[DependencyRef]]:
        groups: dict[tuple[str, str], list[DependencyRef]] = {}
        for dependency in dependencies:
            ecosystem = (dependency.ecosystem or "").lower()
            name = (dependency.name or "").strip()
            if ecosystem not in _MAX_CONFIDENCE and ecosystem not in {
                "npm", "pypi", "rubygems", "packagist", "crates",
            }:
                continue
            if not name:
                continue
            if ecosystem == "npm":
                bare = name[5:] if name.startswith("node:") else name
                if bare in NPM_BUILTINS or name.startswith("node:"):
                    continue
            normalized = dependency.normalized or normalize_package_name(ecosystem, name)
            norm_key = (ecosystem, normalized)
            groups.setdefault(norm_key, []).append(dependency)
        return groups

    def _facts_by_scope(self, facts: list[ConfigFact]) -> dict[str, list[ConfigFact]]:
        from dephunter.analysis.routing import fact_scope_key

        by_scope: dict[str, list[ConfigFact]] = defaultdict(list)
        for fact in facts:
            by_scope[fact_scope_key(fact)].append(fact)
        return dict(by_scope)

    def _refs_by_scope(self, refs: list[DependencyRef]) -> dict[str, list[DependencyRef]]:
        grouped: dict[str, list[DependencyRef]] = defaultdict(list)
        for ref in refs:
            grouped[ref_scope_key(ref)].append(ref)
        return dict(grouped)

    def _scope_facts(
        self,
        ecosystem: str,
        scope_key: str,
        facts_by_scope: dict[str, list[ConfigFact]],
    ) -> list[ConfigFact]:
        return [fact for fact in facts_by_scope.get(scope_key, []) if fact.ecosystem == ecosystem]

    def _plan(
        self,
        groups: dict[tuple[str, str], list[DependencyRef]],
        facts_by_scope: dict[str, list[ConfigFact]],
        enabled: set[str],
    ) -> list[dict[str, object]]:
        plans: list[dict[str, object]] = []
        for (ecosystem, normalized), refs in groups.items():
            if ecosystem not in enabled:
                continue
            concrete = [ref for ref in refs if not ref.explicit_source]
            if not concrete:
                continue
            name = self._display_name(refs)
            intent_any = False
            private_config = False
            for scope_key, scoped_refs in self._refs_by_scope(concrete).items():
                scoped_facts = self._scope_facts(ecosystem, scope_key, facts_by_scope)
                intent, _reasons = intent_signals(
                    ecosystem,
                    name,
                    scoped_refs,
                    scoped_facts,
                    self.org_patterns,
                    self.keywords,
                )
                intent_any = intent_any or intent
                for fact in registry_facts(ecosystem, scoped_facts):
                    classification = classify_registry_value(fact.value)
                    if classification.private:
                        private_config = True
            plans.append(
                {
                    "ecosystem": ecosystem,
                    "normalized": normalized,
                    "name": name,
                    "intent": intent_any,
                    "direct": any(ref.direct for ref in concrete),
                    "private": private_config,
                }
            )
        plans.sort(
            key=lambda plan: (
                not bool(plan["intent"]),
                not bool(plan["direct"]),
                not bool(plan["private"]),
                str(plan["ecosystem"]),
                str(plan["normalized"]),
            )
        )
        return plans

    def _display_name(self, refs: list[DependencyRef]) -> str:
        priority = {"manifest": 0, "lockfile": 1, "js": 2, "bundle": 3, "sourcemap": 4}
        ordered = sorted(
            refs,
            key=lambda ref: (
                priority.get("lockfile" if ref.is_lockfile else ref.source_kind.split("_")[-1], 5),
                not ref.direct,
                len(ref.name),
            ),
        )
        return ordered[0].name

    def _insufficient(
        self,
        ecosystem: str,
        name: str,
        normalized: str,
        refs: list[DependencyRef],
        reason: str,
    ) -> Assessment:
        return Assessment(
            ecosystem=ecosystem,
            name=name,
            normalized=normalized,
            classification=Confidence.INSUFFICIENT_EVIDENCE,
            score=0,
            reasons=[reason],
            missing_evidence=["Static analysis only; runtime resolution was not exercised."],
            refs=list(refs),
            facts=[],
            registry=None,
            resolution=ResolutionAssessment(),
            title=f"Dependency confusion review: {ecosystem} '{name}'",
        )

    def _evaluate(
        self,
        ecosystem: str,
        name: str,
        normalized: str,
        refs: list[DependencyRef],
        facts_by_scope: dict[str, list[ConfigFact]],
        registry: RegistryResult | None,
    ) -> Assessment:
        concrete = [ref for ref in refs if not ref.explicit_source]
        excluded = len(refs) - len(concrete)
        if not concrete:
            assessment = self._insufficient(
                ecosystem, name, normalized, refs,
                "all occurrences are explicit local, VCS, or direct URL sources",
            )
            return assessment
        if registry is None:
            return self._insufficient(
                ecosystem, name, normalized, concrete,
                "registry lookup was not performed for this dependency",
            )

        candidates: list[Assessment] = []
        if registry.status == RegistryStatus.ERROR:
            return self._insufficient(
                ecosystem, name, normalized, concrete,
                f"registry lookup failed ({registry.error or 'unknown error'}); absence was not inferred",
            )
        if registry.status == RegistryStatus.SKIPPED:
            return self._insufficient(
                ecosystem, name, normalized, concrete,
                f"registry metadata not applicable or disabled ({registry.error or 'skipped'})",
            )

        relation = relation_to_target(registry, self.org_patterns)
        for scope_key, scoped_refs in self._refs_by_scope(concrete).items():
            scoped_facts = self._scope_facts(ecosystem, scope_key, facts_by_scope)
            intent, intent_reasons = intent_signals(
                ecosystem,
                name,
                scoped_refs,
                scoped_facts,
                self.org_patterns,
                self.keywords,
            )
            if not intent:
                continue
            if registry.exists and relation == "OWN_LIKELY":
                assessment = self._insufficient(
                    ecosystem, name, normalized, scoped_refs,
                    "public package metadata appears related to the target (publisher/repository); excluded",
                )
                assessment.registry = registry
                assessment.publisher_relation = relation
                candidates.append(assessment)
                continue
            resolution = assess_resolution(ecosystem, name, scoped_refs, scoped_facts)
            assessment = self._classify(
                ecosystem,
                name,
                normalized,
                scoped_refs,
                scoped_facts,
                registry,
                resolution,
                relation,
                intent_reasons,
                excluded,
            )
            candidates.append(assessment)

        if not candidates:
            assessment = self._insufficient(
                ecosystem, name, normalized, concrete,
                "no internal intent signal (name, private package marker, or private provenance)",
            )
            assessment.registry = registry
            assessment.publisher_relation = relation
            return assessment
        candidates.sort(
            key=lambda item: (CONFIDENCE_ORDER[item.classification], item.score),
            reverse=True,
        )
        return candidates[0]

    def _classify(
        self,
        ecosystem: str,
        name: str,
        normalized: str,
        refs: list[DependencyRef],
        facts: list[ConfigFact],
        registry: RegistryResult,
        resolution: ResolutionAssessment,
        relation: str,
        intent_reasons: list[str],
        excluded: int,
    ) -> Assessment:
        reasons = list(intent_reasons)
        missing: list[str] = ["Static analysis only; runtime installation behavior was not exercised."]
        score = 20
        if any(ref.direct for ref in refs):
            score += 10

        contradiction = (
            resolution.private_routing and resolution.public_resolution_evidence
        ) or (
            resolution.public_resolution_evidence and resolution.private_resolution_evidence
        )

        if resolution.notes:
            reasons.extend(resolution.notes)
        if resolution.private_routing:
            score += 5
        else:
            missing.append("No private registry configuration was found in the same scanned scope.")

        if registry.exists:
            score += 15
            version = registry.latest_version or "unknown"
            reasons.append(
                f"public package exists on {registry.ecosystem} (latest {version}); "
                f"publisher metadata: {registry.publisher or 'not exposed'}"
            )
            if relation == "UNRELATED":
                reasons.append("no public repository/publisher field links the package to the target")
            elif relation == "UNKNOWN":
                missing.append(
                    "public registry metadata does not expose ownership; ownership can only be partially excluded"
                )
            if not resolution.public_resolution_evidence:
                missing.append(
                    "No lockfile-resolved public URL proves that this dependency resolves from the public registry."
                )
            if ecosystem == "docker":
                if not docker_namespace_claimable(name):
                    classification = Confidence.INSUFFICIENT_EVIDENCE
                    reasons.append("Docker namespace is not publicly claimable; no confusion path")
                    return self._build(
                        ecosystem, name, normalized, refs, facts, registry, resolution,
                        relation, classification, score, reasons, missing, False,
                    )
        else:
            score += 8
            reasons.append(
                f"no public package with this name is currently published "
                f"(authoritative HTTP {registry.http_status or 404})"
            )
            missing.append("The name is currently unclaimed publicly; this is not proof of a published takeover.")
            if ecosystem == "go":
                missing.append(
                    "Go module paths are domain-bound; public proxy absence is not conclusive for private modules."
                )
            if ecosystem == "docker":
                if not docker_namespace_claimable(name):
                    classification = Confidence.INSUFFICIENT_EVIDENCE
                    reasons.append("Docker official/unqualified namespaces are not claimable by third parties")
                    return self._build(
                        ecosystem, name, normalized, refs, facts, registry, resolution,
                        relation, classification, score, reasons, missing, False,
                    )
            if registry.raw_summary.get("note"):
                reasons.append(str(registry.raw_summary["note"])[:300])

        if contradiction and registry.exists:
            reasons.append(
                "resolution contradiction: private registry configuration coexists with public "
                "lockfile resolution evidence"
            )
            score += 20
            classification = Confidence.CONFIRMED
            missing.append(
                "Target-side confirmation or any package-claiming step requires separate written authorization."
            )
        elif resolution.public_routing is True:
            reasons.append("public registry resolution remains reachable for this name")
            score += 10
            classification = Confidence.HIGH_CONFIDENCE
        elif resolution.public_routing is None:
            if registry.raw_summary.get("note") and ecosystem == "go":
                classification = Confidence.CANDIDATE
            else:
                classification = Confidence.CANDIDATE
            missing.append("Registry routing is ambiguous from the available configuration evidence.")
        else:
            classification = Confidence.INSUFFICIENT_EVIDENCE
            reasons.append("available configuration pins resolution away from the public registry")
            missing.append("No public resolution path was established from the scanned configuration.")

        classification = self._cap(classification, ecosystem)
        if classification == Confidence.CANDIDATE and resolution.public_routing is True:
            reasons.append("confidence capped by ecosystem ownership limits")

        if excluded:
            missing.append(f"{excluded} explicitly pinned local/VCS dependency occurrence(s) were excluded.")
        return self._build(
            ecosystem, name, normalized, refs, facts, registry, resolution,
            relation, classification, min(100, score), reasons, missing, True,
        )

    def _build(
        self,
        ecosystem: str,
        name: str,
        normalized: str,
        refs: list[DependencyRef],
        facts: list[ConfigFact],
        registry: RegistryResult,
        resolution: ResolutionAssessment,
        relation: str,
        classification: Confidence,
        score: int,
        reasons: list[str],
        missing: list[str],
        intent: bool,
    ) -> Assessment:
        return Assessment(
            ecosystem=ecosystem,
            name=name,
            normalized=normalized,
            classification=classification,
            score=score,
            reasons=list(dict.fromkeys(reasons))[:20],
            missing_evidence=list(dict.fromkeys(missing))[:10],
            refs=refs,
            facts=facts[:100],
            registry=registry,
            resolution=resolution,
            intent=intent,
            publisher_relation=relation,
            title=f"Potential dependency confusion: {ecosystem} package '{name}'"[:200],
            cwe_primary="CWE-427",
            cwe_secondary="CWE-829",
        )

    def _cap(self, classification: Confidence, ecosystem: str) -> Confidence:
        cap = _MAX_CONFIDENCE.get(ecosystem)
        if cap is None:
            return classification
        if CONFIDENCE_ORDER[classification] > CONFIDENCE_ORDER[cap]:
            return cap
        return classification
