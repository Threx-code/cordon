"""BP-3-14: an MCP server named in a config is resolved through its package spec to the version and archive digest the registry serves.

A config entry is `{"command": "npx", "args": ["-y", "@x/y@1.2"]}` or `{"command": "uvx", "args": ["tool==2.0"]}`: a program that
fetches a package and runs it. The subject is the package (`mcp:npm/@x/y`), the version is the one the registry gives for the spec
(`1.2`, `latest`, a range), and the artifact is the digest of the archive as the registry serves it (`ArtifactDigests.of_bytes`).

The arguments are read strictly. Only the flags of the program whose meaning is known are taken; any other flag makes the entry
`unparseable`, because a flag the reader does not know may change what the program runs, and a guess here would be a decision about
something else (invariant I2). A spec that is not a registry package (a git URL, a path, a tarball URL) is
`not_a_registry_package`; a program that is neither `npx` nor `uvx` is `local_command`; a `url` entry is a remote server, whose artifact is
its tool list at session start (`McpResolver.remote`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple, Protocol
from urllib.parse import urlsplit

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import CanonicalIds, InvalidSubject, SubjectKind
from cordon_scanner.decide.resolve.resolution import NotFound, Resolution, SourceUnavailable

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence


class RegistryArchive(NamedTuple):
    version: str
    content: bytes
    registry: str


class Registry(Protocol):
    def archive(
        self, ecosystem: str, name: str, selector: str | None, index: str | None
    ) -> RegistryArchive:
        """The archive the registry serves for `name` at `selector` (None, a tag, an exact version or a range), from `index` when
        one was named. Raises `NotFound` when there is none and `SourceUnavailable` when the registry could not be asked."""


class Invocation(NamedTuple):
    ecosystem: str
    name: str
    selector: str | None
    host: str | None


class _Unreadable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class McpResolver:
    PROGRAMS: ClassVar[dict[str, str]] = {"npx": "npm", "uvx": "pypi"}
    #: Flags that take no value, and flags that take one, for each program. Any other flag is not read.
    FLAGS: ClassVar[dict[str, tuple[frozenset[str], frozenset[str]]]] = {
        "npx": (
            frozenset(
                {
                    "-y",
                    "--yes",
                    "-q",
                    "--quiet",
                    "--no-install",
                    "--prefer-online",
                    "--prefer-offline",
                    "--offline",
                    "--ignore-scripts",
                }
            ),
            frozenset({"-p", "--package", "--registry"}),
        ),
        "uvx": (
            frozenset(
                {
                    "--isolated",
                    "--no-cache",
                    "-q",
                    "--quiet",
                    "--offline",
                    "--no-progress",
                    "--refresh",
                }
            ),
            frozenset({"--from", "--python", "-p", "--index-url", "--default-index", "--index"}),
        ),
    }
    PACKAGE_FLAGS: ClassVar[dict[str, frozenset[str]]] = {
        "npx": frozenset({"-p", "--package"}),
        "uvx": frozenset({"--from"}),
    }
    INDEX_FLAGS: ClassVar[dict[str, frozenset[str]]] = {
        "npx": frozenset({"--registry"}),
        "uvx": frozenset({"--index-url", "--default-index", "--index"}),
    }

    @classmethod
    def resolve(cls, entry: Mapping[str, Any], registry: Registry) -> Resolution:
        """One entry of an MCP config as (subject, version, archive digest), or why not."""
        kind = SubjectKind.MCP_SERVER.value
        command = entry.get("command")
        if command is None and isinstance(entry.get("url"), str):
            return cls._remote_unresolved(str(entry["url"]))
        if not isinstance(command, str) or not command.strip():
            return Resolution.failed(
                kind, Resolution.stand_in("mcp", repr(sorted(entry))), "unparseable"
            )
        args = entry.get("args", [])
        shown = " ".join([command, *map(str, args)]) if isinstance(args, list) else command
        program = cls._program(command)
        if program not in cls.PROGRAMS:
            return Resolution.failed(kind, Resolution.stand_in("mcp", shown), "local_command")
        if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
            return Resolution.failed(kind, Resolution.stand_in("mcp", shown), "unparseable")
        try:
            call = cls.invocation(program, args)
        except _Unreadable as problem:
            return Resolution.failed(kind, Resolution.stand_in("mcp", shown), problem.reason)
        try:
            subject = CanonicalIds.canonical_id(
                SubjectKind.MCP_SERVER, {"transport": call.ecosystem, "locator": call.name}
            )
        except InvalidSubject:
            return Resolution.failed(kind, Resolution.stand_in("mcp", shown), "unparseable")
        try:
            archive = registry.archive(call.ecosystem, call.name, call.selector, call.host)
        except SourceUnavailable:
            return Resolution.failed(kind, subject, "source_unreachable", version=call.selector)
        except NotFound:
            return Resolution.failed(kind, subject, "not_found", version=call.selector)
        return Resolution(
            kind=kind,
            subject_id=subject,
            status="resolved",
            version=archive.version,
            digest=ArtifactDigests.of_bytes(archive.content),
            registry=archive.registry,
            ecosystem=call.ecosystem,
        )

    @classmethod
    def remote(cls, url: str, tools: Iterable[Mapping[str, Any]]) -> Resolution:
        """A remote server at session start: its artifact is the canonical digest of the tool list it declared."""
        kind = SubjectKind.MCP_SERVER.value
        try:
            subject = CanonicalIds.canonical_id(
                SubjectKind.MCP_SERVER, {"transport": "remote", "locator": url}
            )
            digest = ArtifactDigests.of_tool_list(tools)
        except (InvalidSubject, ValueError):
            return Resolution.failed(kind, Resolution.stand_in("mcp", url), "unparseable")
        return Resolution(kind=kind, subject_id=subject, status="resolved", digest=digest)

    @classmethod
    def _remote_unresolved(cls, url: str) -> Resolution:
        kind = SubjectKind.MCP_SERVER.value
        try:
            subject = CanonicalIds.canonical_id(
                SubjectKind.MCP_SERVER, {"transport": "remote", "locator": url}
            )
        except InvalidSubject:
            return Resolution.failed(kind, Resolution.stand_in("mcp", url), "unparseable")
        return Resolution.failed(kind, subject, "remote_server")

    @staticmethod
    def _program(command: str) -> str:
        name = command.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
        for suffix in (".cmd", ".exe", ".bat"):
            name = name.removesuffix(suffix)
        return name

    @classmethod
    def invocation(cls, program: str, args: Sequence[str]) -> Invocation:
        """The package an `npx` or `uvx` argument list runs; raises `_Unreadable` with the reason when it cannot be read."""
        plain, valued = cls.FLAGS[program]
        package_flags, index_flags = cls.PACKAGE_FLAGS[program], cls.INDEX_FLAGS[program]
        spec: str | None = None
        index: str | None = None
        first_positional: str | None = None
        position = 0
        while position < len(args):
            word = args[position]
            position += 1
            flag, equals, inline = word.partition("=")
            if word == "--":
                if position < len(args) and first_positional is None:
                    first_positional = args[position]
                break
            if not word.startswith("-"):
                first_positional = word
                break
            if flag in plain and not equals:
                continue
            if flag in valued:
                if equals:
                    value = inline
                elif position < len(args):
                    value = args[position]
                    position += 1
                else:
                    raise _Unreadable("unparseable")
                if flag in package_flags:
                    spec = value
                elif flag in index_flags:
                    index = value
                continue
            raise _Unreadable("unparseable")
        chosen = spec if spec is not None else first_positional
        if chosen is None:
            raise _Unreadable("unparseable")
        name, selector = cls._split(program, chosen)
        return Invocation(cls.PROGRAMS[program], name, selector, cls._host(index))

    @staticmethod
    def _host(index: str | None) -> str | None:
        if index is None:
            return None
        host = urlsplit(index).hostname
        if host is None:
            raise _Unreadable("unparseable")
        return host.lower()

    @classmethod
    def _split(cls, program: str, text: str) -> tuple[str, str | None]:
        """The package name and what selects its version from one spec word."""
        if not text or any(char.isspace() for char in text):
            raise _Unreadable("unparseable")
        if program == "npx":
            if (
                ":" in text
                or text.startswith((".", "/", "~"))
                or text.count("/") > (1 if text.startswith("@") else 0)
            ):
                raise _Unreadable("not_a_registry_package")
            body = text[1:] if text.startswith("@") else text
            name_part, at, selector = body.partition("@")
            name = ("@" if text.startswith("@") else "") + name_part
            return name, (selector if at and selector else None)
        # uvx: name[extras] followed by a specifier (==, >=, ~=, <, >, !=) or @version
        if "://" in text or "/" in text or text.startswith((".", "~")):
            raise _Unreadable("not_a_registry_package")
        cut = len(text)
        for marker in ("==", ">=", "<=", "~=", "!=", ">", "<", "@", ";"):
            found = text.find(marker)
            if found != -1:
                cut = min(cut, found)
        name = text[:cut].split("[", 1)[0]
        rest = text[cut:]
        if rest.startswith("@"):
            rest = rest[1:]
        return name, (rest or None)


__all__ = ["Invocation", "McpResolver", "Registry", "RegistryArchive"]
