"""Compose files: their logical lines, the services they declare and the images each one runs or builds."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    Manifest,
)
from cordon_scanner.ecosystems.infra.references import ImageReference, Interpolation
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.foundation.content import FileContent


class ComposeLines:
    """Compose YAML read by indentation: anchors, aliases and merge keys followed by name, which
    the hostile-input YAML reader elsewhere refuses on principle."""

    #: A `key:` line (or a list item, which a mapping does not hold but `children` reports).
    KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"""^(?:"[^"]*"|'[^']*'|[^"'\s][^:]*?)\s*:(?:\s|$)|^-(?:\s|$)"""
    )

    @staticmethod
    def logical(text: str) -> tuple[list[tuple[int, int, str]], str | None]:
        """`(line, indent, content)` of each non-blank line, comments dropped."""
        out: list[tuple[int, int, str]] = []
        block: int | None = None  # the indentation of a block scalar's header, while inside it
        for number, raw in enumerate(text.splitlines(), start=1):
            if not out and re.fullmatch(r"---[ \t]*(?:#.*)?", raw.rstrip("\r")):
                # YAML's document-start marker, which Compose accepts before the document.
                continue
            if block is not None:
                # A block scalar's lines are its text, however they look: vulhub's
                # `command: >` script holds `members: [...]` and then a shallower line, which
                # were read as a key and a malformed line after it.
                if not raw.strip() or len(raw) - len(raw.lstrip(" ")) > block:
                    continue
                block = None
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                return out, f"line {number}: a tab in the indentation, which YAML does not allow"
            content = ComposeLines.uncomment(raw).rstrip()
            if content.strip():
                indent = len(content) - len(content.lstrip())
                out.append((number, indent, content.strip()))
                if re.search(r"(?:^-|:)[ \t]+[|>][-+1-9]*$", content.strip()):
                    block = indent
        return out, None

    @staticmethod
    def malformed(lines: list[tuple[int, int, str]]) -> str | None:
        """A line YAML refuses: neither `key: value`, a `- item`, nor a plain scalar continued
        deeper than the key it belongs to (`    volumes` where a key was due is a file cut short)."""
        anchor: int | None = None
        for number, indent, text in lines:
            if (
                text.startswith("- ")
                or text == "-"
                or re.match(r"""^(?:"[^"]*"|'[^']*'|[^"'\s][^:]*?)\s*:(?:\s|$)""", text)
            ):
                anchor = indent
                continue
            if anchor is not None and indent > anchor:
                continue
            return f"line {number}: {text[:40]!r} is neither a key nor a list item"
        return None

    @staticmethod
    def uncomment(line: str) -> str:
        quote = ""
        for index, char in enumerate(line):
            if quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == "#" and (index == 0 or line[index - 1] in " \t"):
                return line[:index]
        return line

    @staticmethod
    def scalar(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    @staticmethod
    def block(
        lines: list[tuple[int, int, str]], start: int
    ) -> tuple[list[tuple[int, int, str]], int]:
        """The lines indented under `lines[start]`, and the index after them."""
        indent = lines[start][1]
        end = start + 1
        while end < len(lines) and lines[end][1] > indent:
            end += 1
        return lines[start + 1 : end], end

    @staticmethod
    def children(
        lines: list[tuple[int, int, str]],
    ) -> list[tuple[str, str, list[tuple[int, int, str]], int]]:
        """`(key, inline value, nested lines, line)` for each key at the block's first indent."""
        if not lines:
            return []
        indent = lines[0][1]
        out: list[tuple[str, str, list[tuple[int, int, str]], int]] = []
        index = 0
        while index < len(lines):
            number, level, content = lines[index]
            if level != indent:
                index += 1
                continue
            nested, index = ComposeLines.block(lines, index)
            if content.startswith("- ") or content == "-":
                # A list item, whatever colons it holds (`- base=docker-image://python:3.12`).
                out.append(("-", content[2:].strip(), nested, number))
                continue
            key, colon, value = (
                content.partition(":")
                if not content.startswith(('"', "'"))
                else ComposeLines.quoted_key(content)
            )
            if colon:
                out.append((ComposeLines.scalar(key), value.strip(), nested, number))
        return out

    @staticmethod
    def quoted_key(content: str) -> tuple[str, str, str]:
        quote = content[0]
        end = content.find(quote, 1)
        if end < 0 or not content[end + 1 :].lstrip().startswith(":"):
            return content, "", ""
        return content[1:end], ":", content[end + 1 :].lstrip()[1:]


class Compose:
    """compose.yaml and docker-compose.yml."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str, environment: Mapping[str, str]) -> Manifest:
        lines, error = ComposeLines.logical(content.text)
        if error:
            return BaseEcosystem._err(content, ecosystem, error)
        if not lines or lines[0][1] != 0:
            return BaseEcosystem._err(content, ecosystem, "a Compose file must be a mapping")
        problem = ComposeLines.malformed(lines)
        if problem:
            return BaseEcosystem._err(content, ecosystem, problem)
        lines = Compose._resolve_aliases(lines)
        top = ComposeLines.children(lines)
        anchors = Compose._anchors(lines)
        services = next((nested for key, _value, nested, _n in top if key == "services"), None)
        includes = next((nested for key, _value, nested, _n in top if key == "include"), None)
        sources = Compose._included_sources(includes)
        if services is None:
            if sources:
                return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))
            return BaseEcosystem._err(content, ecosystem, "a Compose file without services")
        declared: list[DeclaredDependency] = []
        for service, _value, body, number in ComposeLines.children(services):
            stray = next(
                (
                    (line, text)
                    for line, level, text in body
                    if level == body[0][1] and not ComposeLines.KEY.match(text)
                ),
                None,
            )
            if stray is not None:
                # A service is a mapping, and Compose refuses one that is not. This is what a
                # file cut inside a key leaves (`sidecar:` then `ima`), and since a service with
                # no image is not refused per file, it is the line that says the file is damaged.
                return BaseEcosystem._err(
                    content,
                    ecosystem,
                    f"line {stray[0]}: service {service} holds {stray[1][:40]!r}, not a key",
                )
            fields = Compose._fields(body, anchors)
            conditions = Compose._conditions(fields, environment)
            image = fields.get("image")
            build = fields.get("build")
            if build is not None:
                Compose._build_sources(
                    build, image, sources, service, environment, conditions, declared
                )
                continue
            if image is None or not image[0]:
                if "extends" in fields:
                    sources.append(f"service {service} extends another service's definition")
                    continue
                # Compose requires one after merging the files it is run with -- `compose.yaml`
                # with `compose.override.yaml` by default, or `-f base.yml -f prod.yml` -- and a
                # file read alone cannot see the other. Coolify's docker-compose.yml names its
                # services' images only in docker-compose.prod.yml; refusing the base file left
                # every other service in it unread.
                sources.append(
                    f"service {service} names neither an image nor a build context in this file "
                    f"(line {number}); Compose takes it from a file merged over this one"
                )
                continue
            written, missing = Interpolation.expand(ComposeLines.scalar(image[0]), environment)
            if missing:
                sources.append(
                    f"service {service} takes its image from ${missing[0]}, which neither the environment file nor a default sets"
                )
                continue
            dependency = ImageReference.declare(
                written,
                scope=Scope.RUNTIME,
                field_name=f"services.{service}.image",
                platform=tuple(conditions),
            )
            if dependency is None:
                return BaseEcosystem._err(
                    content, ecosystem, f"line {number}: {written[:80]!r} is not an image reference"
                )
            declared.append(dependency)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )

    @staticmethod
    def _resolve_aliases(lines: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
        """Each scalar alias read as the value its anchor names."""
        # A scalar anchor (`x-node-image: &node-image node:22@sha256:...`) and the aliases that
        # name it (`image: *node-image`, `NODE_IMAGE: *node-image`): each alias reads as the value
        # it names, as YAML reads it. An alias was taken for an image reference and refused the
        # whole file.
        scalars: dict[str, str] = {}
        for _number, _level, text in lines:
            found = re.search(r"^(?:-\s+)?[^\s:][^:]*:\s*&([A-Za-z0-9_.-]+)\s+(\S.*)$", text)
            if found:
                scalars[found.group(1)] = found.group(2)
        if scalars:
            resolved: list[tuple[int, int, str]] = []
            for number, level, text in lines:
                alias = re.match(r"^(.*?(?::\s+|^-\s+))\*([A-Za-z0-9_.-]+)\s*$", text)
                if alias and alias.group(2) in scalars:
                    text = alias.group(1) + scalars[alias.group(2)]
                resolved.append((number, level, text))
            lines = resolved
        return lines

    @staticmethod
    def _anchors(lines: list[tuple[int, int, str]]) -> dict[str, list[tuple[int, int, str]]]:
        """Anchors anywhere: `x-common: &common` and its children, to follow `<<: *common` by name."""
        # Anchors anywhere: `x-common: &common` and its children, to follow `<<: *common` by name.
        anchors: dict[str, list[tuple[int, int, str]]] = {}
        for index, (_number, _level, text) in enumerate(lines):
            found = re.search(r":\s*&([A-Za-z0-9_.-]+)\s*$", text)
            if found:
                anchors[found.group(1)] = ComposeLines.block(lines, index)[0]
        return anchors

    @staticmethod
    def _included_sources(includes: list[tuple[int, int, str]] | None) -> list[str]:
        """The files `include` names, as sources this file is read with."""
        sources: list[str] = []
        for _key, value, nested, _n in ComposeLines.children(includes or []):
            path = (
                ComposeLines.scalar(value)
                if value
                else next(
                    (
                        ComposeLines.scalar(v)
                        for k, v, _, _ in ComposeLines.children(nested)
                        if k == "path"
                    ),
                    "",
                )
            )
            if path.startswith("path:"):
                path = ComposeLines.scalar(path[5:])
            if path:
                sources.append(f"includes {path}")
        return sources

    @staticmethod
    def _fields(
        body: list[tuple[int, int, str]], anchors: dict[str, list[tuple[int, int, str]]]
    ) -> dict[str, tuple[str, list[tuple[int, int, str]]]]:
        """A service's keys, with those `<<` merges in from an anchor where the service has none of its own."""
        fields = {key: (value, nested) for key, value, nested, _n in ComposeLines.children(body)}
        merge = fields.get("<<")
        if merge is not None:
            # `<<: *common` or `<<: [*a, *b]`: the service's own keys win over the merged ones.
            for alias in re.findall(r"\*([A-Za-z0-9_.-]+)", merge[0]):
                for key, value, nested, _n in ComposeLines.children(anchors.get(alias, [])):
                    fields.setdefault(key, (value, nested))
        return fields

    @staticmethod
    def _conditions(
        fields: dict[str, tuple[str, list[tuple[int, int, str]]]], environment: Mapping[str, str]
    ) -> list[str]:
        """The profiles and platform a service runs under."""
        conditions: list[str] = []
        profiles = fields.get("profiles")
        if profiles is not None:
            names = (
                re.findall(r"[A-Za-z0-9_.-]+", profiles[0])
                if profiles[0]
                else [
                    ComposeLines.scalar(v)
                    for k, v, _, _ in ComposeLines.children(profiles[1])
                    if k == "-"
                ]
            )
            conditions.extend(f"profile {name}" for name in names)
        platform = fields.get("platform")
        if platform is not None and platform[0]:
            conditions.append(
                f"platform {Interpolation.expand(ComposeLines.scalar(platform[0]), environment)[0]}"
            )
        return conditions

    @staticmethod
    def _build_sources(
        build: tuple[str, list[tuple[int, int, str]]],
        image: tuple[str, list[tuple[int, int, str]]] | None,
        sources: list[str],
        service: str,
        environment: Mapping[str, str],
        conditions: list[str],
        declared: list[DeclaredDependency],
    ) -> None:
        """A service built from a context: what it builds from, and the images its additional contexts name."""
        context = ComposeLines.scalar(build[0]) if build[0] and not build[0].startswith("{") else ""
        inline = (
            dict(re.findall(r"(\w+)\s*:\s*([^,}]+)", build[0])) if build[0].startswith("{") else {}
        )
        nested_fields = {k: (v, n) for k, v, n, _ in ComposeLines.children(build[1])}
        context = (
            context
            or ComposeLines.scalar(inline.get("context", ""))
            or ComposeLines.scalar(nested_fields.get("context", ("", []))[0])
        )
        tag = f" (tagged {ComposeLines.scalar(image[0])})" if image is not None and image[0] else ""
        sources.append(f"service {service} builds its image{tag} from {context or '.'}")
        extra = nested_fields.get("additional_contexts")
        for key, value, _nested, line in ComposeLines.children(extra[1] if extra else []):
            target = ComposeLines.scalar(value if key != "-" else value.partition("=")[2])
            if target.startswith("docker-image://"):
                expanded, missing = Interpolation.expand(
                    target.removeprefix("docker-image://"), environment
                )
                if not missing:
                    dependency = ImageReference.declare(
                        expanded,
                        scope=Scope.BUILD,
                        field_name=f"services.{service}.build.additional_contexts (line {line})",
                        platform=tuple(conditions),
                    )
                    if dependency is not None:
                        declared.append(dependency)

    @staticmethod
    def environment(text: str) -> dict[str, str]:
        """A Compose `.env` file: `NAME=value` lines, quotes removed, `export` allowed."""
        values: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = line.removeprefix("export ").strip()
            name, equals, value = line.partition("=")
            if equals and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name.strip()):
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                else:
                    value = value.split(" #", 1)[0].strip()
                values[name.strip()] = value
        return values


__all__ = ["Compose", "ComposeLines"]
