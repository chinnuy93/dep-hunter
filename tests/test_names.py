from __future__ import annotations

from dephunter.core.names import (
    looks_internal,
    normalize_package_name,
    normalize_pattern,
    parse_scoped_npm,
    relation_to_target,
)
from dephunter.core.models import RegistryStatus
from tests.conftest import registry


def test_normalize_package_name() -> None:
    assert normalize_package_name("npm", "@Acme/Lib") == "@acme/lib"
    assert normalize_package_name("pypi", "Acme_Internal.Lib") == "acme-internal-lib"
    assert normalize_package_name("nuget", "Acme.Lib") == "acme.lib"
    assert normalize_package_name("maven", "Com.Acme:Lib") == "com.acme:lib"


def test_parse_scoped_npm() -> None:
    assert parse_scoped_npm("@acme/internal") == ("@acme", "internal")
    assert parse_scoped_npm("left-pad") == (None, "left-pad")


def test_looks_internal_signals() -> None:
    internal, reasons = looks_internal(
        "npm", "@acme/internal-tools", ["acme"], ["internal", "private"]
    )
    assert internal
    assert any("organization" in reason for reason in reasons)


def test_public_scoped_package_without_signal_is_not_internal() -> None:
    internal, _ = looks_internal("npm", "@types/node", ["acme"], ["internal"])
    assert not internal


def test_docker_internal_keyword() -> None:
    internal, reasons = looks_internal("docker", "acme/internal-api", [], ["internal"])
    assert internal
    assert reasons


def test_relation_to_target_detects_owner() -> None:
    result = registry(
        "npm",
        "@acme/lib",
        publisher="acme",
        repository_url="https://github.com/acme/lib",
    )
    assert relation_to_target(result, ["acme"]) == "OWN_LIKELY"


def test_relation_to_target_unrelated() -> None:
    result = registry(
        "npm",
        "@acme/lib",
        publisher="other",
        repository_url="https://github.com/other/lib",
    )
    assert relation_to_target(result, ["acme"]) == "UNRELATED"


def test_relation_to_target_missing() -> None:
    result = registry("npm", "x", status=RegistryStatus.MISSING, http_status=404)
    assert relation_to_target(result, ["acme"]) == "UNKNOWN"


def test_normalize_pattern() -> None:
    assert normalize_pattern("@Acme-Internal/Lib") == "acmeinternallib"
