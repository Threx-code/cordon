"""An image reference, read as the Docker client reads one, and the `${VAR}` interpolation that
builds one: the grammar the Dockerfile, Kubernetes and Compose readers share, below all three.

`python:3.12` is `docker.io/library/python`, and is recorded as `python`; a reference on another
registry keeps its host (`ghcr.io/acme/app`). A digest pins an image; a tag names one the registry
can re-point.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from cordon_scanner.ecosystems.base import DeclaredDependency
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Mapping


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


__all__ = [
    "HUB_HOSTS",
    "ImageReference",
    "Interpolation",
    "PublicRegistries",
    "ReferenceGrammar",
]
