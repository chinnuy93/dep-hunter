from __future__ import annotations

from pathlib import Path

import pytest

from dephunter.core.errors import ConfigError, ScopeViolation
from dephunter.core.scope import ScopePolicy, load_scope


def _write_scope(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_scope_and_policy(tmp_path: Path) -> None:
    path = _write_scope(
        tmp_path,
        """
program: Example Program
authorization: HackerOne program policy ref 123
contact: security@example.com
web:
  - url: https://app.example.com/
    include_subdomains: true
crawl:
  respect_robots: true
  exclude_paths: ["/logout"]
github:
  orgs: [example]
registries:
  enabled: [npm, pypi]
  query_limit: 10
analysis:
  org_patterns: [example]
  min_classification: high_confidence
""",
    )
    scope = load_scope(path)
    scope.validate_for_scan()
    assert scope.program == "Example Program"
    assert scope.web[0].host == "app.example.com"
    assert scope.enabled_ecosystems == ["npm", "pypi"]
    assert scope.analysis.min_classification == "HIGH_CONFIDENCE"

    policy = ScopePolicy(scope)
    assert policy.web_host_allowed("app.example.com")
    assert policy.web_host_allowed("api.app.example.com")
    assert not policy.web_host_allowed("evil-example.com")
    assert policy.path_excluded("/logout")
    assert policy.category("https://app.example.com/index") == "web"
    assert policy.category("https://registry.npmjs.org/left-pad") == "registry"
    with pytest.raises(ScopeViolation):
        policy.check_url("https://evil.example.net/")
    with pytest.raises(ScopeViolation):
        policy.check_url("http://app.example.com:22/")
    with pytest.raises(ScopeViolation):
        policy.check_url("http://app.example.com:99999/")


def test_scope_requires_authorization(tmp_path: Path) -> None:
    path = _write_scope(tmp_path, "program: Example\nauthorization: short\nweb: [https://example.com]\n")
    scope = load_scope(path)
    with pytest.raises(ConfigError):
        scope.validate_for_scan()


def test_scope_rejects_unknown_registry(tmp_path: Path) -> None:
    path = _write_scope(
        tmp_path,
        """
program: Example
authorization: Authorized engagement 12345
web: [https://example.com]
registries:
  enabled: [not-a-registry]
""",
    )
    with pytest.raises(ConfigError):
        load_scope(path)


def test_invalid_min_classification(tmp_path: Path) -> None:
    path = _write_scope(
        tmp_path,
        """
program: Example
authorization: Authorized engagement 12345
web: [https://example.com]
analysis:
  min_classification: INSUFFICIENT_EVIDENCE
""",
    )
    with pytest.raises(ConfigError):
        load_scope(path).validate_for_scan()
