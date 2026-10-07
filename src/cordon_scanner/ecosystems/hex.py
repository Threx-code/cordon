"""Hex: Elixir's mix and Erlang's rebar3.

```
  mix.exs        project (elixir, apps_path, lockfile), deps: only/optional/runtime/override,
                 git/github/path/in_umbrella, hex: (a package under another name)
  mix.lock       a map of resolved packages: {:hex, ...} with outer checksum and requirements,
                 {:git, url, commit, opts}
  rebar.config   deps (Hex, git, pkg aliases), profiles, minimum_otp_vsn, hooks, plugins
  rebar.lock     {"1.2.0", [{<<"name">>, Source, Level}]} and the package hashes
```

All four are BEAM terms. They are read with a small data-only term reader -- tuples, lists, maps,
atoms, strings, binaries, numbers, keywords -- and anything that is code rather than data (a
function call, a variable) is kept as an opaque value, never evaluated.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


@dataclass(frozen=True)
class Atom:
    name: str


@dataclass(frozen=True)
class Opaque:
    """Code, not data: a call or a variable, kept as written and never evaluated."""

    text: str


@dataclass(frozen=True)
class KeywordPair:
    """`key: value` inside a tuple, gathered into the tuple's trailing keyword list."""

    key: Atom
    value: Any


class TermError(ValueError):
    """The text is not a term this reader accepts. The message names a position, never content."""


class BeamTerms:
    """Elixir and Erlang literal terms."""

    MAX_DEPTH: ClassVar[int] = 64
    MAX_ITEMS: ClassVar[int] = 200_000

    def __init__(self, text: str, erlang: bool) -> None:
        self.text = text
        self.erlang = erlang
        self.position = 0
        self.items = 0

    # -- lexing -----------------------------------------------------------------------------------

    def fail(self, message: str) -> TermError:
        line = self.text.count("\n", 0, self.position) + 1
        return TermError(f"line {line}: {message}")

    def skip(self) -> None:
        comment = "%" if self.erlang else "#"
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character.isspace():
                self.position += 1
            elif character == comment:
                end = text.find("\n", self.position)
                self.position = len(text) if end < 0 else end + 1
            else:
                break

    def peek(self) -> str:
        self.skip()
        return self.text[self.position] if self.position < len(self.text) else ""

    def expect(self, token: str) -> None:
        self.skip()
        if not self.text.startswith(token, self.position):
            raise self.fail(f"expected {token!r}")
        self.position += len(token)

    def string(self, quote: str) -> str:
        self.position += 1
        out: list[str] = []
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character == "\\" and self.position + 1 < len(text):
                out.append(text[self.position + 1])
                self.position += 2
                continue
            if character == quote:
                self.position += 1
                return "".join(out)
            if character == "#" and not self.erlang and text.startswith("#{", self.position):
                raise self.fail("an interpolated string is code, not data")
            out.append(character)
            self.position += 1
        raise self.fail("a string is never closed")

    # -- terms -----------------------------------------------------------------------------------

    def term(self, depth: int = 0) -> Any:
        if depth > self.MAX_DEPTH:
            raise self.fail(f"nested deeper than {self.MAX_DEPTH}")
        self.items += 1
        if self.items > self.MAX_ITEMS:
            raise self.fail(f"more than {self.MAX_ITEMS} terms")
        character = self.peek()
        text = self.text
        if not character:
            raise self.fail("unexpected end of input")
        if character == "{":
            self.position += 1
            items = self.sequence("}", depth)
            # `{:mox, "~> 1.2", only: :test}`: trailing keywords are one keyword list, the
            # tuple's last element, as Elixir reads them.
            plain = [i for i in items if not isinstance(i, KeywordPair)]
            pairs = [(i.key, i.value) for i in items if isinstance(i, KeywordPair)]
            return tuple(plain + ([pairs] if pairs else []))
        if character == "[":
            self.position += 1
            return self.sequence("]", depth)
        if text.startswith("%{", self.position):
            self.position += 2
            return self.mapping(depth)
        if text.startswith("<<", self.position):
            self.position += 2
            self.skip()
            value = self.string('"') if self.peek() == '"' else ""
            self.expect(">>")
            return value
        if character == '"':
            return self.string('"')
        if character == "'" and self.erlang:
            return Atom(self.string("'"))
        if character == ":" and not self.erlang:
            self.position += 1
            if self.peek() == '"':
                return Atom(self.string('"'))
            found = re.compile(r"[A-Za-z_][\w@]*[?!]?").match(text, self.position)
            if not found:
                raise self.fail("malformed atom")
            self.position = found.end()
            return Atom(found.group(0))
        number = re.compile(r"-?\d[\d_]*(?:\.\d+)?").match(text, self.position)
        if number:
            self.position = number.end()
            value = number.group(0).replace("_", "")
            return float(value) if "." in value else int(value)
        word = re.compile(r"[A-Za-z_][\w.@]*[?!]?").match(text, self.position)
        if word:
            self.position = word.end()
            name = word.group(0)
            if name in ("true", "false"):
                return name == "true"
            if name == "nil":
                return None
            if self.erlang and name[0].islower() and "." not in name:
                return Atom(name)
            # A call or a variable: consume its argument list and keep it opaque.
            if self.peek() == "(":
                start = self.position
                self.balanced("(", ")")
                return Opaque(name + text[start : self.position])
            return Opaque(name)
        raise self.fail("unexpected character")

    def balanced(self, opening: str, closing: str) -> None:
        depth = 0
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character == '"':
                self.string('"')
                continue
            if character == opening:
                depth += 1
            elif character == closing:
                depth -= 1
                if depth == 0:
                    self.position += 1
                    return
            self.position += 1
        raise self.fail(f"{opening!r} is never closed")

    def key(self) -> str | None:
        """A keyword key at the position (`name:` or `"name":`), consumed, or None."""
        if self.erlang:
            return None
        self.skip()
        text = self.text
        quoted = re.compile(r'"([^"\\]{0,256})":\s').match(text, self.position)
        if quoted:
            self.position = quoted.end()
            return quoted.group(1)
        bare = re.compile(r"([A-Za-z_][\w]*[?!]?):\s").match(text, self.position)
        if bare:
            self.position = bare.end()
            return bare.group(1)
        return None

    def value(self, depth: int, closers: str) -> Any:
        """A term, or -- when an operator follows it (`Mix.env() == :prod`) -- the whole
        expression up to the next separator, kept opaque."""
        start = self.position
        found = self.term(depth)
        following = self.peek()
        if (
            not following
            or following == ","
            or following in closers
            or self.text.startswith("=>", self.position)
        ):
            return found
        depth_count = 0
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character == '"':
                self.string('"')
                continue
            if character in "([{":
                depth_count += 1
            elif character in ")]}":
                if depth_count == 0:
                    break
                depth_count -= 1
            elif character == "," and depth_count == 0:
                break
            self.position += 1
        return Opaque(" ".join(text[start : self.position].split())[:200])

    def sequence(self, closing: str, depth: int) -> list[Any]:
        out: list[Any] = []
        while True:
            if self.peek() == closing:
                self.position += 1
                return out
            name = self.key()
            if name is not None:
                item = self.value(depth + 1, closing)
                out.append(KeywordPair(Atom(name), item) if closing == "}" else (Atom(name), item))
            else:
                out.append(self.value(depth + 1, closing))
            if self.peek() == ",":
                self.position += 1
                continue
            if self.peek() == "|" and closing == "]":
                raise self.fail("an improper list is not data")
            self.expect(closing)
            return out

    def mapping(self, depth: int) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        while True:
            if self.peek() == "}":
                self.position += 1
                return out
            name = self.key()
            if name is not None:
                out[name] = self.value(depth + 1, "}")
            else:
                key = self.term(depth + 1)
                self.expect("=>")
                value = self.value(depth + 1, "}")
                out[key if not isinstance(key, list) else str(key)] = value
            if self.peek() == ",":
                self.position += 1
                continue
            self.expect("}")
            return out

    @staticmethod
    def parse(text: str, *, erlang: bool = False) -> Any:
        reader = BeamTerms(text, erlang)
        value = reader.term()
        if reader.peek():
            raise reader.fail("text after the term")
        return value

    @staticmethod
    def consult(text: str) -> list[Any]:
        """Erlang's `file:consult/1`: a sequence of terms, each ending in `.`."""
        reader = BeamTerms(text, erlang=True)
        out = []
        while reader.peek():
            out.append(reader.term())
            reader.expect(".")
        return out

    @staticmethod
    def keyword(value: Any) -> dict[str, Any]:
        """A keyword list (`[only: :test, runtime: false]`) as a dict; anything else as {}."""
        out: dict[str, Any] = {}
        if isinstance(value, list):
            for item in value:
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], Atom):
                    out[item[0].name] = item[1]
        return out


class Mixfile:
    """`mix.exs`: the `project` keyword list and the `deps` list, found by their function names
    and read as terms. The surrounding Elixir is not evaluated."""

    @staticmethod
    def _body(text: str, function: str) -> Any:
        """The first list literal in `def[p] <function> do ... end` (or `function: [...]`)."""
        found = re.search(rf"\bdefp?\s+{function}\b[^\n]*?\bdo\b", text)
        start = found.end() if found else -1
        if start < 0:
            inline = re.search(rf"\b{function}:\s*\[", text)
            if not inline:
                return None
            start = inline.end() - 1
        bracket = text.find("[", start)
        if bracket < 0:
            return None
        reader = BeamTerms(text, erlang=False)
        reader.position = bracket
        return reader.term()

    @staticmethod
    def balanced(text: str) -> bool:
        """Whether every `do` block is closed by an `end` (strings, charlists and comments set
        aside; `do:` one-liners are not blocks). A mix.exs cut short is not."""
        code = re.sub(
            r'"""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|#[^\n]*', " ", text
        )
        opened = len(re.findall(r"\bdo\b(?!:)", code)) + len(re.findall(r"\bfn\b", code))
        closed = len(re.findall(r"\bend\b", code))
        return opened == closed

    @staticmethod
    def read(content: FileContent) -> tuple[dict[str, Any], list[Any]]:
        text = content.text
        if not Mixfile.balanced(text):
            raise TermError("its `do` blocks and `end`s do not balance: the file is incomplete")
        project = BeamTerms.keyword(Mixfile._body(text, "project"))
        deps = project.get("deps")
        if not isinstance(deps, list):
            deps = Mixfile._body(text, "deps")
        return project, deps if isinstance(deps, list) else []

    @staticmethod
    def scope(options: dict[str, Any]) -> Scope:
        only = options.get("only")
        envs = (
            [only]
            if isinstance(only, Atom)
            else [o for o in only if isinstance(o, Atom)]
            if isinstance(only, list)
            else []
        )
        names = {e.name for e in envs}
        if options.get("optional") is True:
            return Scope.OPTIONAL
        if names and "prod" not in names:
            return Scope.TEST if "test" in names else Scope.DEV
        if options.get("runtime") is False:
            return Scope.BUILD
        return Scope.RUNTIME


class MixLock:
    """`mix.lock`."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BeamTerms.parse(content.text)
        except TermError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"not a mix.lock map: {exc}"
            )
        if not isinstance(data, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="not a mix.lock map"
            )
        entries: list[LockEntry] = []
        for key, value in sorted(data.items(), key=lambda item: str(item[0])):
            if not isinstance(value, tuple) or not value or not isinstance(value[0], Atom):
                continue
            kind = value[0].name
            app = str(key)
            if kind == "hex" and len(value) >= 3:
                package = value[1].name if isinstance(value[1], Atom) else app
                version = str(value[2])
                requirements = value[5] if len(value) > 5 and isinstance(value[5], list) else []
                outer = value[7] if len(value) > 7 and isinstance(value[7], str) else None
                inner = value[3] if len(value) > 3 and isinstance(value[3], str) else None
                integrity = f"sha256:{outer}" if outer else f"hexinner:{inner}" if inner else None
                repository = value[6] if len(value) > 6 and isinstance(value[6], str) else "hexpm"
                entries.append(
                    LockEntry(
                        name=package,
                        version=version,
                        integrity=integrity,
                        alias=app if app != package else None,
                        dependencies=MixLock._edges(requirements),
                        resolved_from=None if repository == "hexpm" else f"registry:{repository}",
                    )
                )
            elif kind == "git" and len(value) >= 3:
                url, commit = str(value[1]), str(value[2])
                entries.append(
                    LockEntry(name=app, version=commit, resolved_from=f"git+{url}#{commit}")
                )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def _edges(requirements: list[Any]) -> tuple[str, ...]:
        names = []
        for requirement in requirements:
            if isinstance(requirement, tuple) and requirement and isinstance(requirement[0], Atom):
                options = BeamTerms.keyword(requirement[2]) if len(requirement) > 2 else {}
                hex_name = options.get("hex")
                names.append(hex_name.name if isinstance(hex_name, Atom) else requirement[0].name)
        return tuple(sorted(names))


class RebarConfig:
    """`rebar.config`: deps, profiles, minimum_otp_vsn, hooks and plugins."""

    @staticmethod
    def dependency(item: Any, scope: Scope, field: str) -> DeclaredDependency | None:
        # rebar3 locks the default profile only: a profile's dependency is absent from
        # rebar.lock by design.
        note = (
            f"a {field.split('.')[1]}-profile dependency: rebar.lock records the default profile only"
            if field.startswith("profiles.")
            else None
        )
        if isinstance(item, Atom):
            return DeclaredDependency(
                name=item.name, spec="*", scope=scope, field_name=field, note=note
            )
        if not isinstance(item, tuple) or not item or not isinstance(item[0], Atom):
            return None
        name = item[0].name
        rest = item[1:]
        spec = "*"
        package = name
        for part in rest:
            if isinstance(part, str):
                spec = part
            elif isinstance(part, tuple) and part and isinstance(part[0], Atom):
                kind = part[0].name
                if kind == "pkg" and len(part) > 1 and isinstance(part[1], Atom):
                    package = part[1].name
                    if len(part) > 2 and isinstance(part[2], str):
                        spec = part[2]
                elif kind in ("git", "git_subdir", "hg") and len(part) > 1:
                    url = str(part[1])
                    reference = ""
                    if len(part) > 2 and isinstance(part[2], tuple) and len(part[2]) == 2:
                        reference = str(part[2][1])
                    spec = f"git+{url}" + (f"#{reference}" if reference else "")
        return DeclaredDependency(
            name=package,
            spec=spec,
            scope=scope,
            field_name=field + (f" (as {name})" if package != name else ""),
            note=note,
        )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            terms = BeamTerms.consult(content.text)
        except TermError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not readable rebar.config terms: {exc}")
        config: dict[str, Any] = {}
        for term in terms:
            if isinstance(term, tuple) and len(term) == 2 and isinstance(term[0], Atom):
                config[term[0].name] = term[1]
        declared: list[DeclaredDependency] = []
        for item in config.get("deps") or []:
            found = RebarConfig.dependency(item, Scope.RUNTIME, "deps")
            if found:
                declared.append(found)
        for profile in config.get("profiles") or []:
            if isinstance(profile, tuple) and len(profile) == 2 and isinstance(profile[0], Atom):
                settings = (
                    {
                        t[0].name: t[1]
                        for t in profile[1]
                        if isinstance(t, tuple) and len(t) == 2 and isinstance(t[0], Atom)
                    }
                    if isinstance(profile[1], list)
                    else {}
                )
                scope = Scope.TEST if profile[0].name == "test" else Scope.DEV
                for item in settings.get("deps") or []:
                    found = RebarConfig.dependency(item, scope, f"profiles.{profile[0].name}.deps")
                    if found:
                        declared.append(found)
        for key in ("plugins", "project_plugins"):
            for item in config.get(key) or []:
                found = RebarConfig.dependency(item, Scope.TOOL, key)
                if found:
                    declared.append(found)
        otp = config.get("minimum_otp_vsn")
        if isinstance(otp, str):
            declared.append(
                DeclaredDependency(
                    name="erlang/otp",
                    spec=f">= {otp}",
                    scope=Scope.PLATFORM,
                    field_name="minimum_otp_vsn",
                )
            )
        hooks: list[Hook] = []
        for key in ("pre_hooks", "post_hooks"):
            for hook in config.get(key) or []:
                if isinstance(hook, tuple) and len(hook) >= 2:
                    command = hook[-1] if isinstance(hook[-1], str) else ""
                    stage = hook[-2].name if isinstance(hook[-2], Atom) else "?"
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"{key}:{stage}",
                            command=command,
                            ecosystem=ecosystem,
                        )
                    )
        return Manifest(
            path=content.path, ecosystem=ecosystem, dependencies=tuple(declared), hooks=tuple(hooks)
        )


class RebarLock:
    """`rebar.lock`: `{"1.2.0", [Entries]}.` then `[{pkg_hash, ...}, {pkg_hash_ext, ...}].`, or the
    pre-1.0 form, a bare list of entries -- which records no hashes at all, so its entries are
    marked as keeping their integrity nowhere rather than as hashes gone missing."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            terms = BeamTerms.consult(content.text)
        except TermError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not readable rebar.lock terms: {exc}",
            )
        if not terms:
            return LockGraph(path=content.path, ecosystem=ecosystem, parse_error="no lock term")
        head = terms[0]
        listed = (
            head[1]
            if isinstance(head, tuple) and len(head) == 2 and isinstance(head[1], list)
            else head
        )
        if not isinstance(listed, list):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no list of locked dependencies"
            )
        hashes: dict[str, str] = {}
        for term in terms[1:]:
            if not isinstance(term, list):
                continue
            for block in term:
                if (
                    isinstance(block, tuple)
                    and len(block) == 2
                    and isinstance(block[0], Atom)
                    and block[0].name == "pkg_hash_ext"
                ):
                    for pair in block[1]:
                        if isinstance(pair, tuple) and len(pair) == 2:
                            hashes[str(pair[0])] = f"sha256:{str(pair[1]).lower()}"
        entries: list[LockEntry] = []
        for item in listed:
            if not isinstance(item, tuple) or len(item) < 3:
                continue
            name, source, level = str(item[0]), item[1], item[2]
            if not isinstance(source, tuple) or not source or not isinstance(source[0], Atom):
                continue
            kind = source[0].name
            if kind == "pkg" and len(source) >= 3:
                entries.append(
                    LockEntry(
                        name=str(source[1]),
                        version=str(source[2]),
                        integrity=hashes.get(name),
                        direct=level == 0,
                        alias=name if str(source[1]) != name else None,
                    )
                )
            elif kind in ("git", "git_subdir") and len(source) >= 3:
                reference = (
                    source[2][1] if isinstance(source[2], tuple) and len(source[2]) == 2 else ""
                )
                entries.append(
                    LockEntry(
                        name=name,
                        version=str(reference),
                        resolved_from=f"git+{source[1]}#{reference}",
                        direct=level == 0,
                    )
                )
        legacy = not (isinstance(head, tuple) and len(head) == 2)
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            integrity_elsewhere=legacy,
        )


class HexEcosystem(BaseEcosystem):
    """Hex, through mix and rebar3."""

    id = "hex"
    purl_type = "hex"
    manifest_globs: tuple[str, ...] = ("**/mix.exs", "**/rebar.config")
    lockfile_globs: tuple[str, ...] = ("**/mix.lock", "**/rebar.lock")
    registry_hosts: frozenset[str] = frozenset({"hex.pm", "repo.hex.pm"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        if content.basename == "rebar.config":
            return RebarConfig.parse(content, self.id)
        try:
            project, deps = Mixfile.read(content)
        except TermError as exc:
            return BaseEcosystem._err(content, self.id, f"not a readable mix.exs: {exc}")
        if not project and not deps and content.text.strip():
            return BaseEcosystem._err(
                content, self.id, "not a Mix project: neither `project` nor `deps` could be read"
            )
        directory = content.path.rpartition("/")[0]
        declared: list[DeclaredDependency] = []
        overrides: dict[str, str] = {}
        for item in deps:
            if not isinstance(item, tuple) or not item or not isinstance(item[0], Atom):
                continue
            app = item[0].name
            requirement = next((p for p in item[1:] if isinstance(p, str)), None)
            options = (
                BeamTerms.keyword(item[-1]) if len(item) > 1 and isinstance(item[-1], list) else {}
            )
            scope = Mixfile.scope(options)
            hex_name = options.get("hex")
            name = hex_name.name if isinstance(hex_name, Atom) else app
            if options.get("in_umbrella") is True:
                spec = f"path:../{app}"
            elif isinstance(options.get("path"), str):
                spec = f"path:{options['path']}"
            elif isinstance(options.get("git"), str) or isinstance(options.get("github"), str):
                url = options.get("git") or f"https://github.com/{options['github']}.git"
                reference = options.get("tag") or options.get("ref") or options.get("branch")
                spec = f"git+{url}" + (f"#{reference}" if isinstance(reference, str) else "")
            else:
                spec = requirement or "*"
            if options.get("override") is True:
                overrides[name] = spec
            conditions = []
            targets = options.get("targets")
            if targets is not None:
                listed = targets if isinstance(targets, list) else [targets]
                conditions.append(
                    "targets " + ", ".join(t.name for t in listed if isinstance(t, Atom))
                )
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec,
                    scope=scope,
                    field_name="deps" + (" (override)" if options.get("override") is True else ""),
                    alias=app if name != app else None,
                    platform=tuple(conditions),
                    note="a path dependency: mix.lock never locks one"
                    if spec.startswith("path:")
                    else None,
                )
            )
        elixir = project.get("elixir")
        if isinstance(elixir, str):
            declared.append(
                DeclaredDependency(
                    name="elixir", spec=elixir, scope=Scope.PLATFORM, field_name="elixir"
                )
            )
        lockfile = project.get("lockfile")
        locked_by: str | None = None
        if isinstance(lockfile, str) and lockfile != "mix.lock":
            locked_by = (
                posixpath.normpath(posixpath.join(directory, posixpath.dirname(lockfile)))
                if directory
                else posixpath.dirname(lockfile)
            )
        own_app = project.get("app")
        hooks: list[Hook] = []
        compilers = project.get("compilers")
        if isinstance(compilers, list):
            for compiler in compilers:
                if isinstance(compiler, Atom) and compiler.name in (
                    "elixir_make",
                    "make",
                    "rustler",
                    "cmake",
                ):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"compiler {compiler.name}",
                            ecosystem=self.id,
                        )
                    )
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=own_app.name if isinstance(own_app, Atom) else None,
            version=project.get("version") if isinstance(project.get("version"), str) else None,
            dependencies=tuple(declared),
            overrides=overrides,
            locked_by=locked_by
            if locked_by not in (".", "")
            else ("" if locked_by is not None else None),
            hooks=tuple(hooks),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "rebar.lock":
            return RebarLock.parse(content, self.id)
        return MixLock.parse(content, self.id)


__all__ = [
    "Atom",
    "BeamTerms",
    "HexEcosystem",
    "MixLock",
    "Mixfile",
    "Opaque",
    "RebarConfig",
    "RebarLock",
    "TermError",
]
