from __future__ import annotations

from dephunter.extractors import extract, find_extractor, is_manifest_path, manifest_role
from dephunter.extractors.base import ExtractContext
from dephunter.extractors.repo import history_worthy, is_repo_manifest


def run(path: str, text: str):
    return extract(
        path,
        text.encode("utf-8"),
        ExtractContext(
            origin="repo",
            source_url=f"https://github.com/acme/app/{path}",
            file_path=path,
            repo="acme/app",
        ),
    )


def dep_names(result) -> set[str]:
    return {dep.name for dep in result.dependencies}


def test_manifest_routing() -> None:
    assert manifest_role("package.json") == "manifest"
    assert manifest_role("package-lock.json") == "lockfile"
    assert manifest_role("webpack.js") == "js"
    assert manifest_role("unknown.bin") == "asset"
    assert is_manifest_path("requirements.txt")
    assert not is_repo_manifest("node_modules/pkg/package.json")
    assert is_repo_manifest("package.json")
    assert not history_worthy("package-lock.json")
    assert history_worthy("package.json")


def test_npm_manifest_and_lock() -> None:
    manifest = run(
        "package.json",
        """
        {
          "dependencies": {"@acme/internal-lib": "^1.0.0", "left-pad": "1.0.0"},
          "devDependencies": {"jest": "^29"},
          "optionalDependencies": {"fsevents": "^2"}
        }
        """,
    )
    assert {"@acme/internal-lib", "left-pad", "jest", "fsevents"} <= dep_names(manifest)
    lock = run(
        "package-lock.json",
        """
        {
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"left-pad": "1.0.0"}},
            "node_modules/left-pad": {
              "version": "1.0.0",
              "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"
            }
          }
        }
        """,
    )
    left_pad = next(dep for dep in lock.dependencies if dep.name == "left-pad")
    assert left_pad.is_lockfile
    assert left_pad.resolved_url == "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"


def test_npmrc_scope_and_redaction() -> None:
    result = run(
        ".npmrc",
        """
        @acme:registry=https://npm.acme.example/repository/npm/
        //npm.acme.example/:_authToken=secret-token-value
        registry=https://registry.npmjs.org/
        """,
    )
    facts = {fact.fact_type: fact for fact in result.config_facts}
    assert facts["npm_scope_registry"].value.startswith("https://npm.acme.example")
    assert facts["npm_scope_registry"].extra["scope"] == "@acme"
    assert facts["npm_registry_auth_present"].value == "[REDACTED]"
    assert "secret-token-value" not in str(result.config_facts)


def test_python_requirements_and_pyproject() -> None:
    requirements = run(
        "requirements.txt",
        """
        requests==2.31.0
        --index-url https://pypi.acme.example/simple
        --extra-index-url https://pypi.org/simple
        acme-internal @ git+https://github.com/acme/internal.git@abc
        local-lib @ file:///opt/local/lib
        """,
    )
    deps = {dep.name: dep for dep in requirements.dependencies}
    assert deps["requests"].version == "==2.31.0"
    assert deps["acme-internal"].explicit_source
    assert deps["local-lib"].explicit_source
    facts = {fact.fact_type for fact in requirements.config_facts}
    assert {"pip_index_url", "pip_extra_index_url"} <= facts

    pyproject = run(
        "pyproject.toml",
        """
        [project]
        name = "app"
        dependencies = ["fastapi>=0.1", "acme-internal>=1.0"]

        [tool.poetry.dependencies]
        python = "^3.11"
        requests = "^2.31"
        """,
    )
    names = dep_names(pyproject)
    assert {"fastapi", "acme-internal", "requests"} <= names
    assert "python" not in names


def test_maven_pom_repository() -> None:
    result = run(
        "pom.xml",
        """
        <project>
          <groupId>com.acme</groupId>
          <artifactId>app</artifactId>
          <version>1.0</version>
          <repositories>
            <repository><id>internal</id><url>https://maven.acme.example/repo</url></repository>
          </repositories>
          <dependencies>
            <dependency>
              <groupId>com.acme</groupId><artifactId>secret-lib</artifactId><version>1.2.3</version>
            </dependency>
          </dependencies>
        </project>
        """,
    )
    assert "com.acme:secret-lib" in dep_names(result)
    assert any(fact.fact_type == "maven_repository" for fact in result.config_facts)


def test_nuget_sources_and_mapping() -> None:
    result = run(
        "nuget.config",
        """
        <configuration>
          <packageSources>
            <clear />
            <add key="internal" value="https://nuget.acme.example/v3/index.json" />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
          </packageSources>
          <packageSourceMapping>
            <packageSource key="internal"><package pattern="Acme.*" /></packageSource>
          </packageSourceMapping>
        </configuration>
        """,
    )
    fact_types = {fact.fact_type for fact in result.config_facts}
    assert {"nuget_clear_sources", "nuget_package_source", "nuget_source_mapping"} <= fact_types


def test_go_mod() -> None:
    result = run(
        "go.mod",
        """
        module github.com/acme/app

        go 1.22

        require (
          github.com/acme/secret-lib v1.2.3
          github.com/pkg/errors v0.9.1 // indirect
        )
        """,
    )
    deps = {dep.name: dep for dep in result.dependencies}
    assert deps["github.com/acme/secret-lib"].direct
    assert not deps["github.com/pkg/errors"].direct


def test_gemfile_source_block() -> None:
    result = run(
        "Gemfile",
        """
        source "https://rubygems.org"

        source "https://gems.acme.example" do
          gem "acme-internal"
        end
        gem "rails", "~> 7.0"
        """,
    )
    deps = {dep.name: dep for dep in result.dependencies}
    assert deps["acme-internal"].extra["source_block"] == "https://gems.acme.example"
    assert {fact.fact_type for fact in result.config_facts} == {"gem_source"}


def test_composer_canonical_false() -> None:
    result = run(
        "composer.json",
        """
        {
          "repositories": [
            {"type": "composer", "url": "https://packages.acme.example", "canonical": false},
            {"packagist.org": false}
          ],
          "require": {"acme/internal-lib": "^1.0", "monolog/monolog": "^3"}
        }
        """,
    )
    assert {"acme/internal-lib", "monolog/monolog"} <= dep_names(result)
    fact_types = {fact.fact_type for fact in result.config_facts}
    assert {"composer_repository", "composer_packagist_disabled"} <= fact_types


def test_cargo_registry() -> None:
    result = run(
        "Cargo.toml",
        """
        [package]
        name = "app"
        version = "0.1.0"

        [dependencies]
        acme-internal = { version = "1.0", registry = "internal" }
        serde = "1"
        """,
    )
    deps = {dep.name: dep for dep in result.dependencies}
    assert deps["acme-internal"].extra["registry"] == "internal"


def test_docker_images() -> None:
    dockerfile = run("Dockerfile", "FROM node:22\nFROM registry.acme.example/app-base:1.0\n")
    names = dep_names(dockerfile)
    assert {"library/node", "registry.acme.example/app-base"} <= names

    compose = run(
        "docker-compose.yml",
        """
        services:
          app:
            image: "acme/internal-api:1.2.3"
          db:
            image: postgres:16
        """,
    )
    assert {"acme/internal-api", "library/postgres"} <= dep_names(compose)


def test_javascript_bundle_and_sourcemap() -> None:
    bundle = run(
        "static/app.js",
        'const x = require("@acme/internal-lib"); const y = require("left-pad"); fetch("/api");',
    )
    assert {"@acme/internal-lib", "left-pad"} <= dep_names(bundle)
    assert all(not dep.direct for dep in bundle.dependencies)

    sourcemap = run(
        "static/app.js.map",
        """
        {
          "sources": ["webpack:///./node_modules/@acme/internal-lib/package.json"],
          "sourcesContent": ["{\\"name\\":\\"@acme/internal-lib\\",\\"version\\":\\"1.2.3\\"}"]
        }
        """,
    )
    dep = next(dep for dep in sourcemap.dependencies if dep.name == "@acme/internal-lib")
    assert dep.version == "1.2.3"
    assert dep.source_kind.endswith("sourcemap")


def test_ci_install_and_env() -> None:
    result = run(
        ".github/workflows/ci.yml",
        """
        env:
          PIP_INDEX_URL: https://pypi.acme.example/simple
        jobs:
          build:
            steps:
              - run: npm install
              - run: pip install -r requirements.txt
              - run: npm ci --ignore-scripts
        """,
    )
    fact_types = {fact.fact_type for fact in result.config_facts}
    assert "env_pip_index_url" in fact_types
    assert "ci_install_command" in fact_types
    assert any(fact.fact_type == "ci_npm_install_without_lock" for fact in result.config_facts)


def test_python_requirements_equals_form_options() -> None:
    result = run(
        "requirements.txt",
        """
        --index-url=https://pypi.acme.example/simple
        --extra-index-url=https://mirror.example/simple
        acme-internal==1.0.0
        """,
    )
    facts = {fact.fact_type: fact.value for fact in result.config_facts}
    assert facts["pip_index_url"] == "https://pypi.acme.example/simple"
    assert facts["pip_extra_index_url"] == "https://mirror.example/simple"
    assert "acme-internal" in dep_names(result)
