from __future__ import annotations

from typing import Any

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    make_fact,
    toml_loads,
)

_DEP_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


class CargoManifestExtractor(BaseExtractor):
    ecosystem = "crates"
    filenames = ("Cargo.toml",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        try:
            data = toml_loads(text)
        except Exception as exc:
            result.warnings.append(f"invalid Cargo.toml: {exc}")
            return result
        loc = locator(text)
        for section, groups in (
            ("dependencies", ["runtime"]),
            ("dev-dependencies", ["dev"]),
            ("build-dependencies", ["build"]),
        ):
            _add_deps(data.get(section), result, ctx, loc, groups)
        workspace = data.get("workspace")
        if isinstance(workspace, dict):
            _add_deps(workspace.get("dependencies"), result, ctx, loc, ["workspace"])
            members = workspace.get("members")
            if isinstance(members, list):
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "crates",
                        "cargo_workspace_members",
                        ",".join(str(m) for m in members)[:500],
                        line=loc.find("members"),
                    )
                )
        targets = data.get("target")
        if isinstance(targets, dict):
            for _target, target_cfg in targets.items():
                if isinstance(target_cfg, dict):
                    _add_deps(target_cfg.get("dependencies"), result, ctx, loc, ["target-specific"])
        registries = data.get("registries")
        if isinstance(registries, dict):
            for name, cfg in registries.items():
                if isinstance(cfg, dict) and isinstance(cfg.get("index"), str):
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "crates",
                            "cargo_registry",
                            f"{name}={cfg['index']}",
                            line=loc.find(str(name)),
                        )
                    )
        source = data.get("source")
        if isinstance(source, dict):
            crates_io = source.get("crates-io")
            if isinstance(crates_io, dict) and isinstance(crates_io.get("replace-with"), str):
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "crates",
                        "cargo_source_replace",
                        f"crates-io=>{crates_io['replace-with']}",
                        line=loc.find("replace-with"),
                    )
                )
            for name, cfg in source.items():
                if isinstance(cfg, dict) and isinstance(cfg.get("registry"), str):
                    result.config_facts.append(
                        make_fact(
                            ctx,
                            "crates",
                            "cargo_source_registry",
                            f"{name}={cfg['registry']}",
                            line=loc.find(str(name)),
                        )
                    )
        patch = data.get("patch")
        if isinstance(patch, dict):
            for source_name, entries in patch.items():
                if isinstance(entries, dict):
                    for crate, spec in entries.items():
                        result.config_facts.append(
                            make_fact(
                                ctx,
                                "crates",
                                "cargo_patch",
                                f"{source_name}:{crate}={str(spec)[:200]}",
                                line=loc.find(str(crate)),
                            )
                        )
        return result


def _add_deps(entries: Any, result: ExtractionResult, ctx: ExtractContext, loc, groups: list[str]) -> None:
    if not isinstance(entries, dict):
        return
    for name, spec in entries.items():
        if not isinstance(name, str):
            continue
        version = None
        explicit = False
        extra: dict[str, Any] = {"cargo_groups": list(groups)}
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            version = spec.get("version") if isinstance(spec.get("version"), str) else None
            if any(key in spec for key in ("path", "git")):
                explicit = True
                extra["explicit_source_spec"] = str(spec.get("path") or spec.get("git"))[:300]
            if isinstance(spec.get("registry"), str):
                extra["registry"] = spec["registry"]
            if spec.get("workspace") is True:
                extra["workspace_dependency"] = True
            if spec.get("optional") is True:
                extra["optional"] = True
        result.dependencies.append(
            make_dep(
                ctx,
                "crates",
                name,
                version,
                line=loc.find(f'"{name}"') if f'"{name}"' in loc.text else loc.find(f"{name} ="),
                explicit_source=explicit,
                direct=True,
                groups=groups,
                extra=extra,
            )
        )


class CargoLockExtractor(BaseExtractor):
    ecosystem = "crates"
    filenames = ("Cargo.lock",)
    role = "lockfile"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        try:
            data = toml_loads(text)
        except Exception as exc:
            result.warnings.append(f"invalid Cargo.lock: {exc}")
            return result
        packages = data.get("package")
        if not isinstance(packages, list):
            return result
        loc = locator(text)
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            source = package.get("source")
            if not isinstance(name, str):
                continue
            if not source:
                result.names_local_to_project.add(name)
                continue
            source_text = str(source)
            resolved = source_text
            if source_text.startswith("registry+"):
                resolved = source_text[len("registry+"):]
            elif source_text.startswith("git+"):
                resolved = source_text[len("git+"):].split("#", 1)[0]
            result.dependencies.append(
                make_dep(
                    ctx,
                    "crates",
                    name,
                    str(version) if version is not None else None,
                    role="lockfile",
                    resolved_url=resolved,
                    direct=False,
                    groups=["runtime"],
                    extra={
                        "source": source_text,
                        "checksum": package.get("checksum"),
                        "local": False,
                    },
                )
            )
        return result
