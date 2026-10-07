"""Container images: what a Dockerfile builds from, and what a Compose file runs.

```
  Dockerfile, Containerfile    every image the build pulls: each stage's `FROM` (with
  (and Dockerfile.*,           `--platform`, and the global `ARG` defaults a reference is built
  *.Dockerfile)                from), `COPY --from=` / `ADD --from=` and `RUN --mount=from=` an
                               image rather than a stage. The image the final stage runs on is a
                               runtime dependency; the rest are the build's. `RUN` and `ONBUILD`
                               are the build's own code, reported as hooks. Heredocs, line
                               continuations and the `escape` parser directive are read as
                               BuildKit reads them.
  compose.yaml,                each service's `image:` (with `${VAR:-default}` from the `.env`
  docker-compose.yml           beside it, `<<: *anchor` merges, `profiles:` and `platform:`), and
  (and their overrides)        the images a build's `additional_contexts` pulls. A service that
                               builds its image tags it with `image:`; that is the build's
                               output, not something pulled.
```

A reference is read as the Docker client reads one: `python:3.12` is `docker.io/library/python`,
and is recorded as `python`; a reference on another registry keeps its host (`ghcr.io/acme/app`).
A digest pins an image; a tag names one the registry can re-point.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.core.content import FileContent


HUB_HOSTS = frozenset(
    {"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}
)


class PublicRegistries:
    """Registries that serve public images anonymously, which `--online` asks. Any other is a
    registry an organisation runs, which answers only with credentials this tool does not hold."""

    HOSTS: ClassVar[frozenset[str]] = frozenset(
        {
            "ghcr.io",
            "quay.io",
            "gcr.io",
            "us.gcr.io",
            "eu.gcr.io",
            "asia.gcr.io",
            "mcr.microsoft.com",
            "public.ecr.aws",
            "registry.k8s.io",
            "registry.gitlab.com",
            "docker.elastic.co",
            "nvcr.io",
            "cgr.dev",
            "lscr.io",
        }
    )

    @staticmethod
    def covers(registry: str | None) -> bool:
        return registry is None or registry in PublicRegistries.HOSTS


class ReferenceGrammar:
    """The distribution reference grammar, as the Docker client applies it."""

    COMPONENT: ClassVar[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
    TAG: ClassVar[re.Pattern[str]] = re.compile(r"^[\w][\w.-]{0,127}$")
    DIGEST: ClassVar[re.Pattern[str]] = re.compile(
        r"^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$"
    )
    DOMAIN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?$"
    )


class ImageReference(NamedTuple):
    """`[registry/]repository[:tag][@digest]`, normalised as the Docker client does."""

    registry: str | None
    """The registry host (and port); None for Docker Hub."""
    repository: str
    """The path on the registry: `library/python` for an official image."""
    tag: str | None
    digest: str | None

    @staticmethod
    def parse(text: str) -> ImageReference | None:
        """The reference, or None when it is not one the Docker client would accept."""
        text = text.strip()
        if not text or len(text) > 512 or any(c.isspace() for c in text):
            return None
        rest, digest = text, None
        if "@" in rest:
            rest, _, digest = rest.partition("@")
            if not ReferenceGrammar.DIGEST.match(digest):
                return None
        first, slash, remainder = rest.partition("/")
        registry = None
        # The first component is a registry when it looks like a host: a dot, a port, or localhost.
        if slash and (
            "." in first or ":" in first or first == "localhost" or first.startswith("[")
        ):
            if not ReferenceGrammar.DOMAIN.match(first):
                return None
            registry, rest = first.lower(), remainder
        path, tag = rest, None
        last = rest.rpartition("/")[2]
        if ":" in last:
            path, _, tag = rest.rpartition(":")
            if not ReferenceGrammar.TAG.match(tag):
                return None
        components = path.split("/")
        if (
            not path
            or not all(ReferenceGrammar.COMPONENT.match(c) for c in components)
            or len(path) > 255
        ):
            return None
        if registry in HUB_HOSTS:
            registry = None
        if registry is None and len(components) == 1:
            path = f"library/{path}"
        return ImageReference(registry, path, tag, digest.lower() if digest else None)

    @property
    def familiar(self) -> str:
        """The name `docker images` shows: `python`, `bitnami/redis`, `ghcr.io/acme/app`."""
        if self.registry is None:
            return (
                self.repository.removeprefix("library/")
                if self.repository.count("/") == 1
                else self.repository
            )
        return f"{self.registry}/{self.repository}"

    @staticmethod
    def declare(
        written: str,
        *,
        scope: Scope,
        field_name: str,
        platform: tuple[str, ...] = (),
        note: str | None = None,
    ) -> DeclaredDependency | None:
        """The image a reference names, as a dependency of the `image` ecosystem. A digest that is
        not one keeps the image and is recorded as written, for the integrity check to report: a
        pin that cannot be a digest is a sign of tampering, not a typo to drop silently."""
        reference = ImageReference.parse(written)
        malformed = None
        if reference is None and "@" in written:
            base_reference, _, malformed = written.rpartition("@")
            reference = ImageReference.parse(base_reference)
            written = base_reference
        if reference is None:
            return None
        name = written.partition("@")[0]
        if ":" in name.rpartition("/")[2]:
            name = name.rpartition(":")[0]
        return DeclaredDependency(
            name=reference.familiar,
            spec=reference.tag or ("" if reference.digest else "latest"),
            scope=scope,
            field_name=field_name,
            ecosystem="image",
            # `docker.io/library/python` as written, where it is recorded as `python`.
            alias=name if name != reference.familiar else None,
            integrity=reference.digest or malformed,
            platform=platform,
            source=f"registry:{reference.registry}" if reference.registry else None,
            note=note,
        )


class Interpolation:
    """`${NAME}`, `${NAME:-default}`, `${NAME-default}`, `${NAME:+alternative}`, `$NAME`."""

    VARIABLE: ClassVar[re.Pattern[str]] = re.compile(
        r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<op>:?[-+?])(?P<word>[^}]*))?\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
    )

    @staticmethod
    def expand(text: str, values: Mapping[str, str]) -> tuple[str, tuple[str, ...]]:
        """The text with each variable replaced, and the names nothing gave a value to."""
        missing: list[str] = []

        def replace(match: re.Match[str]) -> str:
            name = match.group("braced") or match.group("bare")
            op, word = match.group("op"), match.group("word") or ""
            value = values.get(name)
            if op in (":-", "-"):
                return value if value or (op == "-" and value is not None) else word
            if op in (":+", "+"):
                return word if value or (op == "+" and value is not None) else ""
            if value is None:
                missing.append(name)
                return match.group(0)
            return value

        return Interpolation.VARIABLE.sub(replace, text.replace("$$", "\x00")).replace(
            "\x00", "$"
        ), tuple(missing)


class Dockerfile:
    """A Dockerfile, as BuildKit reads it."""

    INSTRUCTIONS: ClassVar[frozenset[str]] = frozenset(
        {
            "FROM",
            "RUN",
            "CMD",
            "LABEL",
            "MAINTAINER",
            "EXPOSE",
            "ENV",
            "ADD",
            "COPY",
            "ENTRYPOINT",
            "VOLUME",
            "USER",
            "WORKDIR",
            "ARG",
            "ONBUILD",
            "STOPSIGNAL",
            "HEALTHCHECK",
            "SHELL",
        }
    )
    HEREDOC: ClassVar[re.Pattern[str]] = re.compile(r"<<(-?)([\"']?)([A-Za-z_][A-Za-z0-9_]*)\2")
    DIRECTIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"^#\s*([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*(.*?)\s*$"
    )

    @staticmethod
    def instructions(text: str) -> tuple[list[tuple[int, str, str]], str | None]:
        """`(line, KEYWORD, arguments)` for each instruction, and an error the build would stop on."""
        # A byte-order mark (a Windows editor's) is not part of the first instruction.
        lines = text.removeprefix("\ufeff").splitlines()
        escape = "\\"
        index = 0
        # Parser directives come first, before any instruction, comment or blank line.
        while index < len(lines):
            directive = Dockerfile.DIRECTIVE.match(lines[index].strip())
            if not directive:
                break
            if directive.group(1).lower() == "escape" and directive.group(2) in ("\\", "`"):
                escape = directive.group(2)
            index += 1
        out: list[tuple[int, str, str]] = []
        while index < len(lines):
            stripped = lines[index].strip()
            if not stripped or stripped.startswith("#"):
                index += 1
                continue
            start = index + 1
            parts: list[str] = []
            line = lines[index].rstrip()
            index += 1
            while line.endswith(escape):
                parts.append(line[: -len(escape)])
                # Comment and blank lines inside a continued instruction are dropped.
                while index < len(lines) and (
                    not lines[index].strip() or lines[index].strip().startswith("#")
                ):
                    index += 1
                if index >= len(lines):
                    return out, f"line {start}: the file ends inside a continued instruction"
                line = lines[index].rstrip()
                index += 1
            parts.append(line)
            logical = " ".join(part.strip() for part in parts)
            keyword, _, arguments = logical.partition(" ")
            keyword = keyword.upper()
            if keyword not in Dockerfile.INSTRUCTIONS:
                return out, f"line {start}: unknown instruction {keyword[:40]}"
            if keyword in ("RUN", "COPY", "ADD") or (
                keyword == "ONBUILD"
                and arguments.split(" ", 1)[0].upper() in ("RUN", "COPY", "ADD")
            ):
                for heredoc in Dockerfile.HEREDOC.finditer(arguments):
                    strip_tabs, terminator = heredoc.group(1) == "-", heredoc.group(3)
                    body: list[str] = []
                    while (
                        index < len(lines)
                        and (lines[index].lstrip("\t") if strip_tabs else lines[index])
                        != terminator
                    ):
                        body.append(lines[index])
                        index += 1
                    if index >= len(lines):
                        return out, f"line {start}: the heredoc {terminator} is never closed"
                    index += 1
                    arguments += "\n" + "\n".join(body)
            out.append((start, keyword, arguments.strip()))
        return out, None

    @staticmethod
    def flags(arguments: str) -> tuple[dict[str, str], str]:
        """Leading `--name=value` flags, and the rest."""
        flags: dict[str, str] = {}
        rest = arguments
        while rest.startswith("--"):
            token, _, rest = rest.partition(" ")
            name, _, value = token[2:].partition("=")
            flags.setdefault(name.lower(), value)
            rest = rest.lstrip()
        return flags, rest

    @staticmethod
    def arguments(declaration: str) -> Iterator[tuple[str, str | None]]:
        """`ARG A=1 B` -> (A, "1"), (B, None)."""
        for token in declaration.split():
            name, equals, value = token.partition("=")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                yield name, value.strip("\"'") if equals else None

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        instructions, error = Dockerfile.instructions(content.text)
        if error:
            return BaseEcosystem._err(content, ecosystem, error)
        if not any(keyword == "FROM" for _, keyword, _ in instructions):
            return BaseEcosystem._err(content, ecosystem, "a Dockerfile without FROM")
        defaults: dict[str, str] = {}
        sources: list[str] = []
        hooks: list[Hook] = []
        stages: list[str | None] = []
        # Each stage's base: ("stage", index), ("image", reference text, line, platform) or ("scratch",).
        bases: list[tuple[str, ...]] = []
        pulls: list[tuple[str, int, tuple[str, ...], str]] = []  # (reference, line, platform, how)
        added: list[DeclaredDependency] = []
        for line, keyword, arguments in instructions:
            if not stages and keyword not in ("ARG", "FROM"):
                return BaseEcosystem._err(
                    content, ecosystem, f"line {line}: {keyword} before the first FROM"
                )
            if keyword == "ARG" and not stages:
                # A global build argument: visible to every FROM line, with its default.
                for name, value in Dockerfile.arguments(arguments):
                    if value is not None:
                        defaults[name] = value
                continue
            if keyword == "FROM":
                flags, rest = Dockerfile.flags(arguments)
                words = rest.split()
                if (
                    not words
                    or (len(words) not in (1, 3))
                    or (len(words) == 3 and words[1].upper() != "AS")
                ):
                    return BaseEcosystem._err(
                        content,
                        ecosystem,
                        f"line {line}: FROM takes an image and an optional AS name",
                    )
                written, missing = Interpolation.expand(words[0], defaults)
                platform: tuple[str, ...] = ()
                if "platform" in flags:
                    expanded, _ = Interpolation.expand(flags["platform"], defaults)
                    platform = (f"platform {expanded}",)
                stages.append(words[2].lower() if len(words) == 3 else None)
                if missing:
                    sources.append(
                        f"FROM on line {line} takes its image from the build argument {missing[0]}, which has no default: --build-arg chooses it"
                    )
                    bases.append(("unknown",))
                elif written.lower() == "scratch":
                    bases.append(("scratch",))
                elif written.lower() in stages[:-1]:
                    bases.append(("stage", str(stages.index(written.lower()))))
                else:
                    if ImageReference.parse(written) is None:
                        return BaseEcosystem._err(
                            content,
                            ecosystem,
                            f"line {line}: {written[:80]!r} is not an image reference",
                        )
                    bases.append(("image", written, str(line), *platform))
                continue
            stage = len(stages) - 1
            label = stages[stage] or str(stage)
            if keyword in ("COPY", "ADD", "RUN"):
                flags, rest = Dockerfile.flags(arguments)
                sources_from = (
                    [flags["from"]] if keyword in ("COPY", "ADD") and "from" in flags else []
                )
                if keyword == "RUN":
                    for mount in re.findall(r"--mount=(\S+)", arguments):
                        found = re.search(r"(?:^|,)from=([^,\s]+)", mount)
                        if found:
                            sources_from.append(found.group(1))
                for value in sources_from:
                    written, missing = Interpolation.expand(value, defaults)
                    if (
                        missing
                        or written.isdigit()
                        or written.lower() in stages
                        or written.lower() == "scratch"
                    ):
                        continue
                    pulls.append((written, line, (), f"{keyword} --from"))
                if keyword == "RUN":
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"RUN in stage {label}",
                            command=rest[:300],
                            ecosystem=ecosystem,
                        )
                    )
                if keyword == "ADD":
                    added.extend(Dockerfile.remote_sources(rest, flags, line, defaults))
            elif keyword == "ONBUILD":
                hooks.append(
                    Hook(
                        kind="build",
                        path=content.path,
                        name=f"ONBUILD in stage {label}",
                        command=arguments[:300],
                        ecosystem=ecosystem,
                    )
                )
        # The image the target (the last stage) runs on: follow stage-to-stage bases down to one.
        runtime: int | None = len(bases) - 1
        seen: set[int] = set()
        while runtime is not None and bases[runtime][0] == "stage" and runtime not in seen:
            seen.add(runtime)
            runtime = int(bases[runtime][1])
        declared: list[DeclaredDependency] = []
        for index, base in enumerate(bases):
            if base[0] != "image":
                continue
            label = stages[index] or str(index)
            dependency = ImageReference.declare(
                base[1],
                scope=Scope.RUNTIME if index == runtime else Scope.BUILD,
                field_name=f"FROM (stage {label}, line {base[2]})",
                platform=tuple(base[3:]),
            )
            if dependency is not None:
                declared.append(dependency)
        for written, line, platform, how in pulls:
            dependency = ImageReference.declare(
                written, scope=Scope.BUILD, field_name=f"{how} (line {line})", platform=platform
            )
            if dependency is None:
                return BaseEcosystem._err(
                    content, ecosystem, f"line {line}: {written[:80]!r} is not an image reference"
                )
            declared.append(dependency)
        declared.extend(added)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            sources=tuple(sources),
        )

    @staticmethod
    def remote_sources(
        rest: str, flags: dict[str, str], line: int, defaults: dict[str, str]
    ) -> list[DeclaredDependency]:
        """What an `ADD` fetches: an archive or file by URL (pinned by `--checksum`), or a git
        repository (`https://.../x.git#ref`, `git@host:x.git#ref`), pinned by a commit."""
        try:
            items = json.loads(rest) if rest.startswith("[") else rest.split()
        except ValueError:
            return []
        out: list[DeclaredDependency] = []
        # Written as the IaC rule reads it -- the URL first, no flags -- the line is that rule's to
        # report; the field says which, so the generic source rules stay quiet on it.
        how = f"ADD {'--' + ' --'.join(sorted(flags)) + ' ' if flags else ''}(line {line})"
        for item in [str(i) for i in items][:-1]:
            source, missing = Interpolation.expand(item, defaults)
            if missing or not re.match(r"^(?:https?://|git@)", source):
                continue
            url, _, ref = source.partition("#")
            if source.startswith("git@") or re.search(r"\.git/?$", url):
                remote = "ssh://" + url.replace(":", "/", 1) if url.startswith("git@") else url
                name = url.rstrip("/").rpartition("/")[2].removesuffix(".git") or url
                commit = flags.get("checksum", "")
                pinned = (
                    ref
                    if re.fullmatch(r"[0-9a-f]{40}", ref)
                    else commit
                    if re.fullmatch(r"[0-9a-f]{40}", commit)
                    else ""
                )
                out.append(
                    DeclaredDependency(
                        name=name,
                        spec=f"git+{remote}#{pinned or ref}"
                        if (pinned or ref)
                        else f"git+{remote}",
                        scope=Scope.BUILD,
                        field_name=how,
                    )
                )
            else:
                checksum = flags.get("checksum")
                out.append(
                    DeclaredDependency(
                        name=url.rstrip("/").rpartition("/")[2] or url,
                        spec=source,
                        scope=Scope.BUILD,
                        field_name=how,
                        integrity=checksum
                        if checksum
                        and re.fullmatch(r"sha(?:256|384|512):[0-9a-f]{64,128}", checksum)
                        else None,
                    )
                )
        return out


class ComposeLines:
    """Compose YAML read by indentation: anchors, aliases and merge keys followed by name, which
    the hostile-input YAML reader elsewhere refuses on principle."""

    @staticmethod
    def logical(text: str) -> tuple[list[tuple[int, int, str]], str | None]:
        """`(line, indent, content)` of each non-blank line, comments dropped."""
        out: list[tuple[int, int, str]] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                return out, f"line {number}: a tab in the indentation, which YAML does not allow"
            content = ComposeLines.uncomment(raw).rstrip()
            if content.strip():
                out.append((number, len(content) - len(content.lstrip()), content.strip()))
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
        top = ComposeLines.children(lines)
        # Anchors anywhere: `x-common: &common` and its children, to follow `<<: *common` by name.
        anchors: dict[str, list[tuple[int, int, str]]] = {}
        for index, (_number, _level, text) in enumerate(lines):
            found = re.search(r":\s*&([A-Za-z0-9_.-]+)\s*$", text)
            if found:
                anchors[found.group(1)] = ComposeLines.block(lines, index)[0]
        services = next((nested for key, _value, nested, _n in top if key == "services"), None)
        includes = next((nested for key, _value, nested, _n in top if key == "include"), None)
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
        if services is None:
            if sources:
                return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))
            return BaseEcosystem._err(content, ecosystem, "a Compose file without services")
        declared: list[DeclaredDependency] = []
        for service, _value, body, number in ComposeLines.children(services):
            fields = {
                key: (value, nested) for key, value, nested, _n in ComposeLines.children(body)
            }
            merge = fields.get("<<")
            if merge is not None:
                # `<<: *common` or `<<: [*a, *b]`: the service's own keys win over the merged ones.
                for alias in re.findall(r"\*([A-Za-z0-9_.-]+)", merge[0]):
                    for key, value, nested, _n in ComposeLines.children(anchors.get(alias, [])):
                        fields.setdefault(key, (value, nested))
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
            image = fields.get("image")
            build = fields.get("build")
            if build is not None:
                context = (
                    ComposeLines.scalar(build[0])
                    if build[0] and not build[0].startswith("{")
                    else ""
                )
                inline = (
                    dict(re.findall(r"(\w+)\s*:\s*([^,}]+)", build[0]))
                    if build[0].startswith("{")
                    else {}
                )
                nested_fields = {k: (v, n) for k, v, n, _ in ComposeLines.children(build[1])}
                context = (
                    context
                    or ComposeLines.scalar(inline.get("context", ""))
                    or ComposeLines.scalar(nested_fields.get("context", ("", []))[0])
                )
                tag = (
                    f" (tagged {ComposeLines.scalar(image[0])})"
                    if image is not None and image[0]
                    else ""
                )
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
                continue
            if image is None or not image[0]:
                if "extends" in fields:
                    sources.append(f"service {service} extends another service's definition")
                    continue
                return BaseEcosystem._err(
                    content,
                    ecosystem,
                    f"line {number}: service {service} has neither an image nor a build context",
                )
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


class Kubernetes:
    """The images a Kubernetes manifest runs: every pod template's `containers`, `initContainers`
    and `ephemeralContainers`, at whatever depth the workload nests them (a Deployment's
    `spec.template.spec`, a CronJob's `spec.jobTemplate.spec.template.spec`, a bare Pod's `spec`),
    and a Kustomization's `images:` overrides, which replace them at deploy time."""

    CONTAINER_LISTS: ClassVar[frozenset[str]] = frozenset(
        {"containers", "initContainers", "ephemeralContainers"}
    )
    DOCUMENT_BREAK: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*(?:#[^\n]*)?$")
    MAX_DOCUMENTS: ClassVar[int] = 2_000

    @staticmethod
    def documents(text: str) -> list[dict[str, Any]]:
        """Each `---`-separated document that is a Kubernetes object. A Helm template (`{{ }}`)
        is not YAML until it is rendered, and is skipped rather than misread."""
        from cordon_scanner.core.datayaml import DataYaml, DataYamlError

        found: list[dict[str, Any]] = []
        for chunk in Kubernetes.DOCUMENT_BREAK.split(text)[: Kubernetes.MAX_DOCUMENTS]:
            if "apiVersion" not in chunk or "kind" not in chunk or "{{" in chunk:
                continue
            try:
                document = DataYaml.load(chunk)
            except (DataYamlError, ValueError, RecursionError):
                continue
            if (
                isinstance(document, dict)
                and isinstance(document.get("apiVersion"), str)
                and isinstance(document.get("kind"), str)
            ):
                found.append(document)
        return found

    @staticmethod
    def images(node: Any, trail: str, depth: int = 0) -> Iterator[tuple[str, str]]:
        """`(field, image)` for every container under this node."""
        if depth > 32:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key in Kubernetes.CONTAINER_LISTS and isinstance(value, list):
                    for index, container in enumerate(value):
                        if isinstance(container, dict) and isinstance(container.get("image"), str):
                            name = container.get("name")
                            label = f"{key}[{name if isinstance(name, str) else index}]"
                            yield f"{trail} {label}.image", container["image"]
                else:
                    yield from Kubernetes.images(value, trail, depth + 1)
        elif isinstance(node, list):
            for item in node:
                yield from Kubernetes.images(item, trail, depth + 1)

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        text = content.text
        dependencies: list[DeclaredDependency] = []
        for document in Kubernetes.documents(text):
            kind = document["kind"]
            metadata = document.get("metadata")
            named = metadata.get("name") if isinstance(metadata, dict) else None
            trail = f"{kind}/{named}" if isinstance(named, str) else kind
            if kind == "Kustomization":
                for entry in document.get("images") or []:
                    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                        continue
                    renamed = entry.get("newName")
                    image: str = renamed if isinstance(renamed, str) else entry["name"]
                    if isinstance(entry.get("digest"), str):
                        image = f"{image}@{entry['digest']}"
                    elif isinstance(entry.get("newTag"), str):
                        image = f"{image}:{entry['newTag']}"
                    declared = ImageReference.declare(
                        image,
                        scope=Scope.RUNTIME,
                        field_name=f"Kustomization images[{entry['name']}]",
                    )
                    if declared is not None:
                        dependencies.append(declared)
                continue
            for field_name, image in Kubernetes.images(document.get("spec"), trail):
                declared = ImageReference.declare(
                    image.strip(), scope=Scope.RUNTIME, field_name=field_name
                )
                if declared is not None:
                    dependencies.append(declared)
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=tuple(dependencies))


class ImageEcosystem(BaseEcosystem):
    """Container images a build pulls, a Compose file runs, and a Kubernetes manifest deploys."""

    id = "image"
    purl_type = "docker"
    manifest_globs: tuple[str, ...] = (
        "**/Dockerfile",
        "**/Dockerfile.*",
        "**/*.Dockerfile",
        "**/*.dockerfile",
        "**/Containerfile",
        "**/Containerfile.*",
        "**/compose.yaml",
        "**/compose.yml",
        "**/compose.*.yaml",
        "**/compose.*.yml",
        "**/docker-compose.yml",
        "**/docker-compose.yaml",
        "**/docker-compose.*.yml",
        "**/docker-compose.*.yaml",
        # Kubernetes manifests where they are conventionally kept, and Kustomize's file. Read by
        # content: a YAML file here that is not a Kubernetes object contributes nothing, and an
        # earlier ecosystem's file in the same directory (Helm's Chart.yaml, an Ansible
        # requirements.yml) stays that ecosystem's.
        *(
            f"**/{folder}/**/*.{suffix}"
            for folder in (
                "k8s",
                "kubernetes",
                "kube",
                "manifests",
                "deploy",
                "deployment",
                "deployments",
                "kustomize",
                "overlays",
            )
            for suffix in ("yaml", "yml")
        ),
        "**/kustomization.yaml",
        "**/kustomization.yml",
        *(
            f"**/{kind}.{suffix}"
            for kind in ("deployment", "statefulset", "daemonset", "cronjob", "job", "pod")
            for suffix in ("yaml", "yml")
        ),
        *(
            f"**/*-{kind}.{suffix}"
            for kind in ("deployment", "statefulset", "daemonset", "cronjob", "job", "pod")
            for suffix in ("yaml", "yml")
        ),
    )
    lockfile_globs: tuple[str, ...] = ()
    registry_hosts: frozenset[str] = HUB_HOSTS
    records_integrity = False

    def normalize_name(self, name: str) -> str:
        reference = ImageReference.parse(name)
        return reference.familiar if reference is not None else name.strip().lower()

    def exact_pin(self, spec: str) -> str | None:
        """A tag is the version an image is published under: `3.12-slim`, `bookworm`, `latest`."""
        tag = spec.strip()
        return tag if tag and ReferenceGrammar.TAG.match(tag) else None

    @staticmethod
    def is_reference(name: str, spec: str | None) -> bool:
        """An image a registry serves -- not an archive or repository a Dockerfile `ADD`s."""
        return (
            not (spec or "").startswith(("http://", "https://", "git+", "git@"))
            and ImageReference.parse(name) is not None
        )

    def is_public_registry(self, url: str | None) -> bool:
        """Docker Hub, where anyone can register a namespace. An image on any other registry is
        named with its host, so nothing else resolves it."""
        return not url

    @staticmethod
    def is_compose(path: str) -> bool:
        base = path.rpartition("/")[2]
        return base.startswith(("compose.", "docker-compose.")) and base.endswith((".yml", ".yaml"))

    @staticmethod
    def is_kubernetes(path: str) -> bool:
        return path.endswith((".yaml", ".yml")) and not ImageEcosystem.is_compose(path)

    def parse_manifest(self, content: FileContent) -> Manifest:
        if ImageEcosystem.is_compose(content.path):
            return Compose.parse(content, self.id, {})
        if ImageEcosystem.is_kubernetes(content.path):
            return Kubernetes.parse(content, self.id)
        return Dockerfile.parse(content, self.id)

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A Compose file with the `.env` beside it, which Compose reads for `${VAR}`."""
        if ImageEcosystem.is_kubernetes(content.path):
            return Kubernetes.parse(content, self.id)
        if not ImageEcosystem.is_compose(content.path):
            return Dockerfile.parse(content, self.id)
        directory = content.path.rpartition("/")[0]
        environment = files.get(f"{directory}/.env" if directory else ".env")
        return Compose.parse(
            content,
            self.id,
            Compose.environment(environment.text) if environment is not None else {},
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(path=content.path, ecosystem=self.id)


__all__ = [
    "HUB_HOSTS",
    "Compose",
    "ComposeLines",
    "Dockerfile",
    "ImageEcosystem",
    "ImageReference",
    "Interpolation",
    "Kubernetes",
    "PublicRegistries",
    "ReferenceGrammar",
]
