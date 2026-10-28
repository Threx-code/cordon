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

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.foundation.content import FileContent


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

    @staticmethod
    def word(text: str, values: Mapping[str, str]) -> tuple[str, tuple[str, ...]]:
        """One Dockerfile word as BuildKit's shell lexer processes it (`frontend/dockerfile/
        shell/lex.go`): quotes removed, variables expanded outside single quotes, a backslash
        escaping the next character. Homebrew's own Dockerfile writes `FROM ubuntu:"${version}"`,
        which BuildKit reads as `ubuntu:24.04` and which was refused, quotes and all."""
        out: list[str] = []
        missing: list[str] = []
        index = 0
        quote = ""

        def variable(at: int) -> int:
            found = Interpolation.VARIABLE.match(text, at)
            if not found:
                out.append("$")
                return at + 1
            value, absent = Interpolation.expand(found.group(0), values)
            out.append(value)
            missing.extend(absent)
            return found.end()

        while index < len(text):
            character = text[index]
            if quote == "'":
                if character == "'":
                    quote = ""
                else:
                    out.append(character)
                index += 1
            elif character == "\\" and index + 1 < len(text):
                following = text[index + 1]
                # Inside double quotes only `"`, `$` and the escape itself are escaped.
                if quote == '"' and following not in '"$\\':
                    out.append(character)
                out.append(following)
                index += 2
            elif character == "$":
                index = variable(index)
            elif character in "'\"" and not quote:
                quote = character
                index += 1
            elif character == '"' and quote == '"':
                quote = ""
                index += 1
            else:
                out.append(character)
                index += 1
        return "".join(out), tuple(missing)


class Dockerfile:
    """A Dockerfile, as BuildKit reads it."""

    #: The file names of a template engine's source: EEx, Jinja, Go templates, ERB, Mustache,
    #: Handlebars, EJS, Liquid, and the generic `.template`, `.tmpl` and `.tpl`.
    TEMPLATE: ClassVar[re.Pattern[str]] = re.compile(
        r"\.(?:eex|j2|jinja2?|tmpl|tpl|template|gotmpl|erb|mustache|hbs|handlebars|ejs|liquid)$",
        re.IGNORECASE,
    )

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
        """`ARG A=1 B` -> (A, "1"), (B, None): each default as written, quotes and all, for
        `Interpolation.word`. Split as BuildKit's lexer splits words -- on whitespace outside
        quotes, a backslash escaping the next character -- so `ARG A="x y"` is one argument."""
        for token in Dockerfile.shell_words(declaration):
            name, equals, value = token.partition("=")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                yield name, value if equals else None

    @staticmethod
    def shell_words(text: str) -> list[str]:
        """Whitespace-separated words, quotes and escapes kept for `Interpolation.word`."""
        words: list[str] = []
        current: list[str] = []
        quote = ""
        index = 0
        while index < len(text):
            character = text[index]
            if character == "\\" and quote != "'" and index + 1 < len(text):
                current.append(text[index : index + 2])
                index += 2
                continue
            if quote:
                if character == quote:
                    quote = ""
            elif character in "'\"":
                quote = character
            elif character.isspace():
                if current:
                    words.append("".join(current))
                    current = []
                index += 1
                continue
            current.append(character)
            index += 1
        if current:
            words.append("".join(current))
        return words

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        if Dockerfile.TEMPLATE.search(content.basename):
            # A template a tool renders into a Dockerfile (Phoenix's `Dockerfile.eex`, balena's
            # `Dockerfile.template`): not one until rendered, and refused at its first tag.
            return Manifest(
                path=content.path,
                ecosystem=ecosystem,
                sources=("a template of a Dockerfile, read once it is rendered",),
            )
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
                Dockerfile._global_arguments(arguments, defaults)
                continue
            if keyword == "FROM":
                failed = Dockerfile._from_line(
                    content, ecosystem, line, arguments, defaults, stages, sources, bases
                )
                if failed is not None:
                    return failed
                continue
            stage = len(stages) - 1
            label = stages[stage] or str(stage)
            if keyword in ("COPY", "ADD", "RUN"):
                Dockerfile._copy_add_run(
                    arguments,
                    keyword,
                    defaults,
                    stages,
                    pulls,
                    line,
                    hooks,
                    content,
                    label,
                    ecosystem,
                    added,
                )
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
        declared = Dockerfile._base_images(bases, stages)
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
    def _global_arguments(arguments: str, defaults: dict[str, str]) -> None:
        """Each global build argument's default, expanded with the arguments declared before it."""
        # A global build argument: visible to every FROM line, with its default.
        # Each default expanded with the arguments declared before it, as BuildKit
        # expands them: `ARG BUILDER_IMAGE="hexpm/elixir:${ELIXIR_VERSION}-..."`. One
        # naming an argument with no value is left unset, so a FROM using it says so.
        for name, value in Dockerfile.arguments(arguments):
            if value is None:
                continue
            expanded, missing = Interpolation.word(value, defaults)
            if missing:
                defaults.pop(name, None)
            else:
                defaults[name] = expanded

    @staticmethod
    def _copy_add_run(
        arguments: str,
        keyword: str,
        defaults: dict[str, str],
        stages: list[str | None],
        pulls: list[tuple[str, int, tuple[str, ...], str]],
        line: int,
        hooks: list[Hook],
        content: FileContent,
        label: str,
        ecosystem: str,
        added: list[DeclaredDependency],
    ) -> None:
        """What a COPY, ADD or RUN reads from another image or the network, and what it runs at build time."""
        flags, rest = Dockerfile.flags(arguments)
        sources_from = [flags["from"]] if keyword in ("COPY", "ADD") and "from" in flags else []
        if keyword == "RUN":
            for mount in re.findall(r"--mount=(\S+)", arguments):
                found = re.search(r"(?:^|,)from=([^,\s]+)", mount)
                if found:
                    sources_from.append(found.group(1))
        for value in sources_from:
            written, missing = Interpolation.word(value, defaults)
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

    @staticmethod
    def _from_line(
        content: FileContent,
        ecosystem: str,
        line: int,
        arguments: str,
        defaults: dict[str, str],
        stages: list[str | None],
        sources: list[str],
        bases: list[tuple[str, ...]],
    ) -> Manifest | None:
        """A FROM line: its stage, and the base it names -- an image, a stage, scratch, or one a
        build argument chooses. The manifest refusing the file when the line is malformed."""
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
        written, missing = Interpolation.word(words[0], defaults)
        platform: tuple[str, ...] = ()
        if "platform" in flags:
            expanded, _ = Interpolation.word(flags["platform"], defaults)
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
        return None

    @staticmethod
    def _base_images(
        bases: list[tuple[str, ...]], stages: list[str | None]
    ) -> list[DeclaredDependency]:
        """The base image of each stage, the one the last stage runs on scoped as runtime and the rest as build."""
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
        return declared

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


class Kubernetes:
    """The images a Kubernetes manifest runs: every pod template's `containers`, `initContainers`
    and `ephemeralContainers`, at whatever depth the workload nests them (a Deployment's
    `spec.template.spec`, a CronJob's `spec.jobTemplate.spec.template.spec`, a bare Pod's `spec`),
    and a Kustomization's `images:` overrides, which replace them at deploy time."""

    CONTAINER_LISTS: ClassVar[frozenset[str]] = frozenset(
        {"containers", "initContainers", "ephemeralContainers"}
    )
    DOCUMENT_BREAK: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*(?:#[^\r\n]*)?\r?$")
    MAX_DOCUMENTS: ClassVar[int] = 2_000

    @staticmethod
    def documents(text: str) -> list[dict[str, Any]]:
        """Each `---`-separated document that is a Kubernetes object. A Helm template (`{{ }}`)
        is not YAML until it is rendered, and is skipped rather than misread."""
        from cordon_scanner.foundation.formats.datayaml import DataYaml, DataYamlError

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
        from cordon_scanner.ecosystems.infra.compose import Compose

        if ImageEcosystem.is_compose(content.path):
            return Compose.parse(content, self.id, {})
        if ImageEcosystem.is_kubernetes(content.path):
            return Kubernetes.parse(content, self.id)
        return Dockerfile.parse(content, self.id)

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A Compose file with the `.env` beside it, which Compose reads for `${VAR}`."""
        from cordon_scanner.ecosystems.infra.compose import Compose

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
    "Dockerfile",
    "ImageEcosystem",
    "ImageReference",
    "Interpolation",
    "Kubernetes",
    "PublicRegistries",
    "ReferenceGrammar",
]
