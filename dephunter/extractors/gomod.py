from __future__ import annotations

from dephunter.core.models import ExtractionResult
from dephunter.extractors.base import (
    BaseExtractor,
    ExtractContext,
    decode_manifest,
    locator,
    make_dep,
    make_fact,
)

_STDLIB_HINTS = {"std", "cmd", "unsafe", "builtin"}


class GoModExtractor(BaseExtractor):
    ecosystem = "go"
    filenames = ("go.mod",)
    role = "manifest"

    def extract(self, content: bytes, ctx_name: str, ctx: ExtractContext) -> ExtractionResult:
        result = ExtractionResult()
        text = decode_manifest(content)
        loc = locator(text)
        module_path: str | None = None
        replaces: dict[str, tuple[str, bool]] = {}
        block: str | None = None
        entries: list[tuple[str, str, str | None, bool]] = []

        for raw_line in text.splitlines():
            comment = raw_line.split("//", 1)[1] if "//" in raw_line else ""
            line = raw_line.split("//", 1)[0].strip()
            if not line:
                continue
            if line.endswith("("):
                block = line[:-1].strip().split()[0]
                continue
            if line == ")":
                block = None
                continue
            tokens = line.split()
            keyword = tokens[0] if not block else block
            if block:
                payload = tokens
            else:
                payload = tokens[1:]
            if keyword == "module" and payload:
                module_path = payload[0]
                result.config_facts.append(
                    make_fact(ctx, "go", "go_module_path", module_path, line=loc.find(module_path))
                )
            elif keyword == "require" and len(payload) >= 2:
                indirect = "indirect" in comment
                entries.append((payload[0], payload[1], None, indirect))
            elif keyword == "replace" and "=>" in payload:
                try:
                    arrow = payload.index("=>")
                    old = payload[:arrow]
                    new = payload[arrow + 1:]
                except ValueError:
                    continue
                if not old:
                    continue
                old_path = old[0]
                new_path = new[0] if new else ""
                local = new_path.startswith((".", "/"))
                replaces[old_path] = (new_path + (" " + new[1] if len(new) > 1 else ""), local)
                result.config_facts.append(
                    make_fact(
                        ctx,
                        "go",
                        "go_replace",
                        f"{old_path} => {' '.join(new)}",
                        line=loc.find(old_path),
                        extra={"local": local},
                    )
                )
            elif keyword == "exclude" and len(payload) >= 2:
                result.config_facts.append(
                    make_fact(ctx, "go", "go_exclude", f"{payload[0]}@{payload[1]}", line=loc.find(payload[0]))
                )

        for module, version, _comment, indirect in entries:
            if not module or module in _STDLIB_HINTS:
                continue
            replaced = replaces.get(module)
            explicit = bool(replaced and replaced[1])
            extra = {"module_path": module, "indirect": indirect}
            if replaced:
                extra["replaced_by"] = replaced[0][:300]
            result.dependencies.append(
                make_dep(
                    ctx,
                    "go",
                    module,
                    version,
                    line=loc.find(f"{module} "),
                    explicit_source=explicit,
                    direct=not indirect,
                    groups=["runtime"] if not indirect else ["transitive"],
                    extra=extra,
                )
            )
        return result
