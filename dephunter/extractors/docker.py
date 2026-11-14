from __future__ import annotations

import re
from dataclasses import dataclass

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    yaml_load_safe,
)

_FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?\s*$", re.I)
_ARG = re.compile(r"^ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<value>.+))?$", re.I)
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(slots=True)
class ImageRef:
    registry: str
    path: str
    tag: str | None
    digest: str | None
    unqualified: bool
    implicit_latest: bool

    @property
    def name(self) -> str:
        return self.path

    @property
    def version(self) -> str | None:
        if self.digest and self.tag:
            return f"{self.tag}@{self.digest}"
        return self.digest or self.tag


def parse_image_ref(reference: str) -> ImageRef | None:
    ref = reference.strip()
    if not ref or ref.startswith("$") or ref == "scratch":
        return None
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last_slash = ref.rfind("/")
    last_colon = ref.rfind(":")
    if last_colon > last_slash:
        ref, tag = ref[:last_colon], ref[last_colon + 1:]
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts[0]
        path = "/".join(parts[1:])
        unqualified = False
    else:
        registry = "docker.io"
        path = ref
        unqualified = True
        if "/" not in path:
            path = f"library/{path}"
    implicit_latest = tag is None and digest is None
    return ImageRef(
        registry=registry,
        path=path.lower(),
        tag=tag,
        digest=digest,
        unqualified=unqualified,
        implicit_latest=implicit_latest,
    )


class DockerfileExtractor(BaseExtractor):
    ecosystem = "docker"
    filenames = ("Dockerfile",)
    suffixes = (".dockerfile",)
    globs = ("Dockerfile.*",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        loc = locator(text)
        args: dict[str, str] = {}
        stages: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            arg_match = _ARG.match(line)
            if arg_match and arg_match.group("value"):
                args[arg_match.group("name")] = _resolve_vars(arg_match.group("value"), args)
                continue
            from_match = _FROM.match(line)
            if not from_match:
                continue
            image_token = _resolve_vars(from_match.group("image"), args)
            alias = from_match.group("alias")
            if image_token.lower() in stages:
                if alias:
                    stages.add(alias.lower())
                continue
            parsed = parse_image_ref(image_token)
            if parsed is None:
                continue
            if alias:
                stages.add(alias.lower())
            extra = {
                "registry": parsed.registry,
                "unqualified": parsed.unqualified,
                "tag": parsed.tag,
                "digest": parsed.digest,
                "implicit_latest": parsed.implicit_latest,
                "stage": alias,
                "base_image": True,
            }
            result.dependencies.append(
                make_dep(
                    ctx,
                    "docker",
                    f"{parsed.path}" if parsed.registry == "docker.io" else f"{parsed.registry}/{parsed.path}",
                    parsed.version,
                    line=loc.find(image_token),
                    explicit_source=bool(parsed.digest),
                    direct=True,
                    groups=["base-image"],
                    extra=extra,
                )
            )
            if parsed.implicit_latest:
                result.config_facts.append(
                    make_fact_unpinned(ctx, parsed, loc.find(image_token))
                )
        return result


def make_fact_unpinned(ctx: ExtractContext, parsed: ImageRef, line: int | None):
    from dephunter.extractors.base import make_fact

    return make_fact(
        ctx,
        "docker",
        "docker_unpinned_image",
        f"{parsed.registry}/{parsed.path}:latest",
        line=line,
    )


class DockerComposeExtractor(BaseExtractor):
    ecosystem = "docker"
    filenames = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        try:
            data = yaml_load_safe(text)
        except Exception as exc:
            result.warnings.append(f"invalid compose file: {exc}")
            return result
        if not isinstance(data, dict):
            return result
        services = data.get("services")
        if not isinstance(services, dict):
            return result
        loc = locator(text)
        for service_name, cfg in services.items():
            if not isinstance(cfg, dict):
                continue
            image = cfg.get("image")
            if not isinstance(image, str):
                continue
            parsed = parse_image_ref(image)
            if parsed is None:
                continue
            result.dependencies.append(
                make_dep(
                    ctx,
                    "docker",
                    parsed.path if parsed.registry == "docker.io" else f"{parsed.registry}/{parsed.path}",
                    parsed.version,
                    line=loc.find(image),
                    explicit_source=bool(parsed.digest),
                    direct=True,
                    groups=[f"compose-service:{service_name}"],
                    extra={
                        "registry": parsed.registry,
                        "unqualified": parsed.unqualified,
                        "tag": parsed.tag,
                        "digest": parsed.digest,
                        "service": str(service_name),
                        "compose": True,
                    },
                )
            )
        return result


def _resolve_vars(value: str, args: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3)
        default = match.group(2) or ""
        return args.get(name, default if name else "")

    return _VAR.sub(replace, value)
