"""Nix: flake inputs and pinned sources -- read, never evaluated.

```
  flake.nix     inputs: `name.url = "<flake ref>"`, `name = { url; flake = false; inputs.x.follows }`
                -- flake refs github:, gitlab:, sourcehut:, git+https://, https:// tarballs,
                path:, and an indirect name (`nixpkgs`) the flake registry resolves at lock time
  flake.lock    the recursive input graph: each node's locked type, revision and NAR hash, its own
                inputs (a node key, or a `follows` path from the root), and what it was asked as
  default.nix   pinned sources written by hand: fetchFromGitHub / fetchFromGitLab / fetchgit /
  shell.nix     builtins.fetchGit / fetchTarball / fetchurl / fetchzip, and `<nixpkgs>` -- a channel
                lookup on NIX_PATH, pinned to nothing
```

Nix is a programming language; evaluating it runs whatever it says. Nothing here evaluates: the
files are tokenised, and only literal attribute sets and strings are read. An input is code the
build evaluates, so every one is a dependency; a revision is its version and its NAR hash the hash
Nix verifies.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.content import FileContent


class LockJson:
    """Readings of flake.lock's JSON."""

    @staticmethod
    def mapping(value: Any) -> dict[str, Any]:
        """`value` when it is a JSON object, an empty one otherwise."""
        return value if isinstance(value, dict) else {}


class NixError(ValueError):
    """Not a Nix file this reader can tokenise. The message never repeats the file's content."""


@dataclass(frozen=True)
class Token:
    kind: str  # ident, string (literal), template (interpolated), path, uri, number, punct
    text: str


class NixLexer:
    PUNCTUATION: ClassVar[tuple[str, ...]] = (
        "...",
        "//",
        "++",
        "->",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "${",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        ";",
        "=",
        ".",
        ":",
        ",",
        "@",
        "?",
        "!",
        "+",
        "-",
        "*",
        "/",
        "<",
        ">",
    )
    IDENT: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_'\-]*")
    URI: ClassVar[re.Pattern[str]] = re.compile(
        r"[A-Za-z][A-Za-z0-9+\-.]*:[A-Za-z0-9%/?:@&=+$,\-_.!~*']+"
    )
    PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:\.{1,2}|~)?(?:/[A-Za-z0-9._+\-]+)+/?|<[A-Za-z0-9._+\-/]+>"
    )
    MAX_TOKENS: ClassVar[int] = 2_000_000

    @staticmethod
    def balanced(tokens: list[Token]) -> None:
        """Every bracket closes: a Nix file cut short does not, and no valid expression is so."""
        depth = 0
        for token in tokens:
            if token.kind == "punct" and token.text in ("{", "[", "(", "${"):
                depth += 1
            elif token.kind == "punct" and token.text in ("}", "]", ")"):
                depth -= 1
                if depth < 0:
                    raise NixError("a closing bracket with nothing open")
        if depth:
            raise NixError("a bracket that does not close")

    @staticmethod
    def tokens(text: str) -> list[Token]:
        out: list[Token] = []
        index, length = 0, len(text)
        while index < length:
            char = text[index]
            if char in " \t\r\n":
                index += 1
            elif char == "#":
                end = text.find("\n", index)
                index = length if end < 0 else end
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0:
                    raise NixError("an unterminated comment")
                index = end + 2
            elif char == '"':
                index, value, literal = NixLexer.string(text, index)
                out.append(Token("string" if literal else "template", value))
            elif text.startswith("''", index):
                index, value, literal = NixLexer.indented(text, index)
                out.append(Token("string" if literal else "template", value))
            elif (path := NixLexer.PATH.match(text, index)) and (char in "./~<"):
                out.append(Token("path", path.group(0)))
                index = path.end()
            elif (
                (uri := NixLexer.URI.match(text, index))
                and ":" in uri.group(0)
                and not uri.group(0).endswith(":")
            ):
                out.append(Token("uri", uri.group(0)))
                index = uri.end()
            elif char.isalpha() or char == "_":
                word = NixLexer.IDENT.match(text, index)
                if word is None:
                    raise NixError("an unreadable identifier")
                out.append(Token("ident", word.group(0)))
                index = word.end()
            elif char.isdigit():
                number = re.compile(r"\d+(?:\.\d+)?").match(text, index)
                if number is None:
                    raise NixError("an unreadable number")
                out.append(Token("number", number.group(0)))
                index = number.end()
            else:
                symbol = next((p for p in NixLexer.PUNCTUATION if text.startswith(p, index)), None)
                if symbol is None:
                    raise NixError("a character that is not part of Nix")
                out.append(Token("punct", symbol))
                index += len(symbol)
            if len(out) > NixLexer.MAX_TOKENS:
                raise NixError("more tokens than an expression holds")
        return out

    @staticmethod
    def interpolation(text: str, index: int) -> int:
        """The index after the `}` closing the `${` at `index`, nested strings followed."""
        depth = 0
        while index < len(text):
            if text.startswith("${", index):
                depth += 1
                index += 2
                continue
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index + 1
            elif char == '"':
                index, _value, _literal = NixLexer.string(text, index)
                continue
            index += 1
        raise NixError("an interpolation that does not close")

    @staticmethod
    def string(text: str, index: int) -> tuple[int, str, bool]:
        index += 1
        buffer: list[str] = []
        literal = True
        while index < len(text):
            char = text[index]
            if char == "\\" and index + 1 < len(text):
                buffer.append(
                    {"n": "\n", "t": "\t", "r": "\r"}.get(text[index + 1], text[index + 1])
                )
                index += 2
                continue
            if char == '"':
                return index + 1, "".join(buffer), literal
            if text.startswith("${", index):
                literal = False
                end = NixLexer.interpolation(text, index)
                buffer.append(text[index:end])
                index = end
                continue
            buffer.append(char)
            index += 1
        raise NixError("an unterminated string")

    @staticmethod
    def indented(text: str, index: int) -> tuple[int, str, bool]:
        index += 2
        start = index
        literal = True
        while index < len(text):
            if (
                text.startswith("'''", index)
                or text.startswith("''$", index)
                or text.startswith("''\\", index)
            ):
                index += 3
                continue
            if text.startswith("''", index):
                return index + 2, text[start:index], literal
            if text.startswith("${", index):
                literal = False
                index = NixLexer.interpolation(text, index)
                continue
            index += 1
        raise NixError("an unterminated indented string")


class NixReader:
    """Literal attribute sets out of a token stream; everything else is passed over unread."""

    MAX_DEPTH: ClassVar[int] = 128
    OPENERS: ClassVar[dict[str, str]] = {"{": "}", "[": "]", "(": ")", "${": "}"}

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self, offset: int = 0) -> Token | None:
        position = self.index + offset
        return self.tokens[position] if position < len(self.tokens) else None

    def skip_expression(self, stops: tuple[str, ...]) -> None:
        """Past one expression, to the `;` (or the given stops) that ends it at this depth. A
        `let ... in`, `with ...;` and `assert ...;` inside it carry semicolons of their own."""
        depth = 0
        lets = 0  # `let` bindings awaiting their `in`: their semicolons separate bindings
        owed = 0  # `with x;` and `assert x;` each own the next semicolon
        while (token := self.peek()) is not None:
            if token.kind == "punct" and token.text in self.OPENERS:
                depth += 1
            elif token.kind == "punct" and token.text in ("}", "]", ")"):
                if depth == 0:
                    return
                depth -= 1
            elif depth == 0 and token.kind == "ident" and token.text == "let":
                lets += 1
            elif depth == 0 and token.kind == "ident" and token.text == "in" and lets:
                lets -= 1
            elif depth == 0 and token.kind == "ident" and token.text in ("with", "assert"):
                owed += 1
            elif depth == 0 and token.kind == "punct" and token.text in stops:
                if token.text == ";" and lets:
                    pass
                elif token.text == ";" and owed:
                    owed -= 1
                else:
                    return
            self.index += 1
        if depth:
            raise NixError("a bracket that does not close")

    def value(self, depth: int) -> Any:
        """A literal string or attribute set, or None for anything else (which is skipped)."""
        if depth > self.MAX_DEPTH:
            raise NixError("nested too deeply")
        token = self.peek()
        if token is None:
            raise NixError("the file ends inside a value")
        following = self.peek(1)
        if (
            token.kind in ("string", "uri")
            and following is not None
            and following.text in (";", "}", "]")
        ):
            self.index += 1
            return token.text
        if token.text == "{" and not self.is_pattern():
            self.index += 1
            return self.attrset(depth + 1)
        self.skip_expression((";",))
        return None

    def is_pattern(self) -> bool:
        """`{ self, nixpkgs, ... }:` opens a function, not an attribute set."""
        depth = 0
        for position in range(self.index, min(len(self.tokens), self.index + 4096)):
            token = self.tokens[position]
            if token.text in ("{", "[", "(", "${"):
                depth += 1
            elif token.text in ("}", "]", ")"):
                depth -= 1
                if depth == 0:
                    after = self.tokens[position + 1] if position + 1 < len(self.tokens) else None
                    return after is not None and after.text in (":", "@")
            elif depth == 1 and token.text in ("=", ";"):
                return False
        return False

    def attrset(self, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while (token := self.peek()) is not None:
            if token.text == "}":
                self.index += 1
                return out
            if token.kind == "ident" and token.text == "inherit":
                self.skip_expression((";",))
                self.index += 1
                continue
            path: list[str] = []
            while (
                (part := self.peek()) is not None
                and part.kind in ("ident", "string")
                and part.text != "inherit"
            ):
                path.append(part.text)
                self.index += 1
                dot = self.peek()
                if dot is not None and dot.text == ".":
                    self.index += 1
                    continue
                break
            equals = self.peek()
            if not path or equals is None or equals.text != "=":
                raise NixError("an attribute that is not `name = value;`")
            self.index += 1
            value = self.value(depth + 1)
            end = self.peek()
            if end is not None and end.text == ";":
                self.index += 1
            target = out
            for segment in path[:-1]:
                inner = target.get(segment)
                if not isinstance(inner, dict):
                    inner = {}
                    target[segment] = inner
                target = inner
            existing = target.get(path[-1])
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.update(value)
            elif path[-1] not in target:
                target[path[-1]] = value
        raise NixError("an attribute set that does not close")


class FlakeRef:
    """A flake reference, as the name a package is known by and a spec the shared layers read."""

    FORGES: ClassVar[dict[str, str]] = {
        "github": "github.com",
        "gitlab": "gitlab.com",
        "sourcehut": "git.sr.ht",
    }
    ARCHIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://github\.com/([^/]+)/([^/]+)/archive/([^/?#]+?)(?:\.tar\.gz|\.zip)$"
    )

    @staticmethod
    def read(ref: str) -> tuple[str, str, bool]:
        """`(name, spec, indirect)`."""
        scheme, _, rest = ref.partition(":")
        if not rest or ref.startswith("flake:"):
            identifier = rest if ref.startswith("flake:") else ref
            return identifier.split("/")[0], f"flake:{identifier}", True
        query = {}
        if "?" in rest:
            rest, _, raw = rest.partition("?")
            query = dict(p.partition("=")[::2] for p in raw.split("&") if p)
        if scheme in FlakeRef.FORGES:
            parts = rest.strip("/").split("/")
            owner, repo = [*parts, "", ""][:2]
            ref_or_rev = (
                query.get("rev")
                or query.get("ref")
                or ("/".join(parts[2:]) if len(parts) > 2 else "")
            )
            url = f"git+https://{FlakeRef.FORGES[scheme]}/{owner}/{repo}"
            return f"{owner}/{repo}".lower(), url + (f"#{ref_or_rev}" if ref_or_rev else ""), False
        if scheme.startswith("git+") or scheme == "git":
            url = ref.split("?")[0]
            name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            pin = query.get("rev") or query.get("ref")
            return (
                name,
                (url if url.startswith("git+") else f"git+{url}") + (f"#{pin}" if pin else ""),
                False,
            )
        if scheme == "path" or ref.startswith(("./", "../", "/")):
            return (
                ref.removeprefix("path:").rstrip("/").rsplit("/", 1)[-1] or ref,
                f"path:{ref.removeprefix('path:')}",
                False,
            )
        url = ref.removeprefix("tarball+").removeprefix("file+")
        archive = FlakeRef.ARCHIVE.match(url)
        if archive:
            # A GitHub archive names a revision (pinned) or a branch or tag (which rolls).
            owner, repo, ref = archive.group(1), archive.group(2), archive.group(3)
            return f"{owner}/{repo}".lower(), f"git+https://github.com/{owner}/{repo}#{ref}", False
        name = re.sub(
            r"\.(?:tar\.gz|tar\.xz|tgz|zip)$", "", url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        )
        return name or url, url, False


class Overlays:
    """The overlays a flake or a Nix expression applies to nixpkgs.

    An overlay replaces packages: `final: prev: { openssl = ...; }` changes what every package
    built against it links. One taken from an input lets that input change any package in the
    build, which its own entry in the lock does not show. Found in `overlays = [ ... ]` lists, by
    text and never by evaluation: an input's overlay (`inputs.foo.overlays.default`, or `foo.` when
    `foo` is an input the outputs take) and a local file (`import ./overlays/x.nix`).
    """

    LIST: ClassVar[re.Pattern[str]] = re.compile(r"\boverlays\s*=\s*\[(.*?)\]", re.DOTALL)
    FROM_INPUT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.-])(?:inputs\.)?([A-Za-z_][\w-]*)\.overlays(?:\.([A-Za-z_][\w-]*))?"
    )
    LOCAL: ClassVar[re.Pattern[str]] = re.compile(r"\bimport\s+(\.{1,2}/[\w./-]+)")

    @staticmethod
    def applied(text: str, inputs: set[str]) -> list[str]:
        stripped = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        stripped = re.sub(r"(?m)(^|\s)#.*$", r"\1", stripped)
        found: list[str] = []
        for listing in Overlays.LIST.finditer(stripped):
            body = listing.group(1)
            for match in Overlays.FROM_INPUT.finditer(body):
                name, which = match.group(1), match.group(2)
                if name in inputs:
                    found.append(f"overlay from input {name}" + (f" ({which})" if which else ""))
            for match in Overlays.LOCAL.finditer(body):
                found.append(f"overlay {match.group(1)}")
        return list(dict.fromkeys(found))


class Flake:
    """flake.nix: its inputs."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            tokens = NixLexer.tokens(content.text)
            NixLexer.balanced(tokens)
            reader = NixReader(tokens)
            if not tokens or tokens[0].text != "{":
                raise NixError("a flake that is not an attribute set")
            reader.index = 1
            top = reader.attrset(0)
        except NixError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable flake.nix: {exc}")
        inputs = top.get("inputs")
        if inputs is None and "outputs" not in top:
            return BaseEcosystem._err(content, ecosystem, "a flake with neither inputs nor outputs")
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        for name, value in (inputs or {}).items() if isinstance(inputs, dict) else []:
            body = value if isinstance(value, dict) else {}
            if "url" in body and not isinstance(body["url"], str):
                # Computed (`"github:acme/${x}"`): only evaluation knows it, and nothing evaluates.
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec="*",
                        scope=Scope.BUILD,
                        field_name=f"inputs.{name}",
                        note="an input whose url is computed: it is known only by evaluating the flake, which is never done here",
                    )
                )
                continue
            url = body.get("url") if isinstance(body.get("url"), str) else None
            if url is None and isinstance(value, str):
                url = value
            nested = body.get("inputs")
            for child, child_body in nested.items() if isinstance(nested, dict) else []:
                follows = child_body.get("follows") if isinstance(child_body, dict) else None
                if isinstance(follows, str):
                    sources.append(f"input {name}.{child} follows {follows or '(nothing)'}")
            if url is None:
                if body.get("follows") is not None:
                    sources.append(f"input {name} follows {body['follows']}")
                    continue
                # No url: the input is looked up by its own name in the flake registry.
                url = name
            package, spec, indirect = FlakeRef.read(url)
            conditions = ["not a flake"] if body.get("flake") is False else []
            declared.append(
                DeclaredDependency(
                    name=package,
                    spec=spec,
                    scope=Scope.BUILD,
                    field_name=f"inputs.{name}",
                    alias=name if name != package else None,
                    platform=tuple(conditions),
                    note="an indirect input: the flake registry chose its source when the lock was made"
                    if indirect
                    else None,
                )
            )
        description = top.get("description")
        if isinstance(description, str):
            sources.insert(0, f"flake {description}")
        sources.extend(
            Overlays.applied(content.text, set(inputs) if isinstance(inputs, dict) else set())
        )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class Fetchers:
    """default.nix / shell.nix: the sources a file pins by hand."""

    FETCHERS: ClassVar[frozenset[str]] = frozenset(
        {
            "fetchFromGitHub",
            "fetchFromGitLab",
            "fetchgit",
            "fetchGit",
            "fetchTarball",
            "fetchurl",
            "fetchzip",
            "getFlake",
        }
    )

    @staticmethod
    def calls(tokens: list[Token]) -> Iterator[tuple[str, dict[str, Any] | str]]:
        for position, token in enumerate(tokens):
            if token.kind != "ident" or token.text not in Fetchers.FETCHERS:
                continue
            following = tokens[position + 1] if position + 1 < len(tokens) else None
            if following is None:
                continue
            if following.kind in ("string", "uri"):
                yield token.text, following.text
            elif following.text == "{":
                reader = NixReader(tokens)
                reader.index = position + 2
                try:
                    yield token.text, reader.attrset(0)
                except NixError:
                    continue

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            tokens = NixLexer.tokens(content.text)
            NixLexer.balanced(tokens)
        except NixError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable Nix expression: {exc}")
        declared: list[DeclaredDependency] = []
        for fetcher, argument in Fetchers.calls(tokens):
            dependency = Fetchers.dependency(fetcher, argument)
            if dependency is not None:
                declared.append(dependency)
        if any(t.kind == "path" and t.text.startswith("<") for t in tokens):
            channel = next(t.text for t in tokens if t.kind == "path" and t.text.startswith("<"))
            name = channel.strip("<>").split("/")[0]
            declared.append(
                DeclaredDependency(
                    name=name,
                    # `<nixpkgs>` is nixpkgs at no reference at all: the mutable-reference rule's case.
                    spec="git+https://github.com/NixOS/nixpkgs"
                    if name == "nixpkgs"
                    else f"channel:{channel}",
                    scope=Scope.BUILD,
                    field_name=channel,
                    note="looked up on NIX_PATH when evaluated: whatever that channel holds then, pinned to nothing",
                )
            )
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=tuple(declared))

    @staticmethod
    def dependency(fetcher: str, argument: dict[str, Any] | str) -> DeclaredDependency | None:
        if isinstance(argument, str):
            name, spec, _indirect = FlakeRef.read(argument)
            return DeclaredDependency(name=name, spec=spec, scope=Scope.BUILD, field_name=fetcher)
        text = {k: v for k, v in argument.items() if isinstance(v, str)}
        integrity = text.get("hash") or text.get("sha256") or text.get("narHash")
        if fetcher in ("fetchFromGitHub", "fetchFromGitLab") and "owner" in text and "repo" in text:
            host = "github.com" if fetcher == "fetchFromGitHub" else "gitlab.com"
            pin = text.get("rev") or text.get("tag") or ""
            name = f"{text['owner']}/{text['repo']}".lower()
            spec = f"git+https://{host}/{text['owner']}/{text['repo']}" + (f"#{pin}" if pin else "")
        elif "url" in text:
            name, spec, _indirect = FlakeRef.read(
                text["url"] if fetcher not in ("fetchgit", "fetchGit") else f"git+{text['url']}"
            )
            git_pin = text.get("rev") or text.get("ref")
            if fetcher in ("fetchgit", "fetchGit") and git_pin:
                spec = spec.split("#")[0] + f"#{git_pin}"
        else:
            return None
        return DeclaredDependency(
            name=name,
            spec=spec,
            scope=Scope.BUILD,
            field_name=fetcher,
            integrity=Fetchers.sri(integrity),
            # A commit pins it already; a hash is the only pin of an archive that names none.
            note="pinned by its hash: Nix checks the download against it"
            if integrity and not re.search(r"#[0-9a-f]{40}$", spec)
            else None,
        )

    @staticmethod
    def sri(value: str | None) -> str | None:
        """A Nix hash as written (`sha256-<base64>` SRI, or a bare base32 / hex sha256)."""
        if not value:
            return None
        return value if value.startswith(("sha256-", "sha512-")) else f"sha256:{value}"


class FlakeLock:
    """flake.lock (version 7): the recursive input graph."""

    @staticmethod
    def identity(node: dict[str, Any]) -> tuple[str, str | None]:
        """`(name, source)` of a locked node: an indirect input keeps the registry name it was
        asked as; the rest are named by their repository."""
        locked = LockJson.mapping(node.get("locked"))
        original = LockJson.mapping(node.get("original"))
        kind = str(locked.get("type") or "")
        source: str | None
        if kind in FlakeRef.FORGES:
            owner, repo = str(locked.get("owner") or ""), str(locked.get("repo") or "")
            source = f"git+https://{FlakeRef.FORGES[kind]}/{owner}/{repo}#{locked.get('rev', '')}"
            name = f"{owner}/{repo}".lower()
        elif kind == "git":
            url = str(locked.get("url") or "")
            source = f"git+{url}#{locked.get('rev', '')}"
            name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        elif kind == "path":
            path = str(locked.get("path") or "")
            return path.rstrip("/").rsplit("/", 1)[-1] or path, None
        else:
            url = str(locked.get("url") or "")
            name, _spec, _indirect = FlakeRef.read(url) if url else ("", "", False)
            source = url or None
        if original.get("type") == "indirect" and isinstance(original.get("id"), str):
            name = original["id"]
        return name, source

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        nodes = data.get("nodes")
        root_key = str(data.get("root") or "root")
        if not isinstance(nodes, dict) or not isinstance(nodes.get(root_key), dict):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a flake.lock without its nodes and root",
            )

        def target(reference: Any) -> str | None:
            """A node key, or a `follows` path walked from the root."""
            if isinstance(reference, str):
                return reference
            if isinstance(reference, list):
                current: str | None = root_key
                for step in reference:
                    inputs = (
                        nodes.get(current, {}).get("inputs")
                        if isinstance(nodes.get(current), dict)
                        else None
                    )
                    current = target(inputs.get(step)) if isinstance(inputs, dict) else None
                    if current is None:
                        return None
                return current
            return None

        # An edge names its child as `name@revision`: a lock can hold two nixpkgs.
        names: dict[str, str] = {}
        for key, node in nodes.items():
            if key != root_key and isinstance(node, dict):
                locked_node = LockJson.mapping(node.get("locked"))
                revision = locked_node.get("rev") or locked_node.get("lastModified") or ""
                names[key] = f"{FlakeLock.identity(node)[0] or key}@{revision}"
        root_inputs = nodes[root_key].get("inputs") or {}
        direct = (
            {target(v) for v in root_inputs.values()} if isinstance(root_inputs, dict) else set()
        )
        entries: list[LockEntry] = []
        for key, node in sorted(nodes.items()):
            if key == root_key or not isinstance(node, dict):
                continue
            locked = node.get("locked")
            if not isinstance(locked, dict):
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a node without its locked revision",
                )
            name, source = FlakeLock.identity(node)
            inputs = LockJson.mapping(node.get("inputs"))
            children = tuple(
                names[k] for k in (target(v) for v in inputs.values()) if k and k in names
            )
            original = LockJson.mapping(node.get("original"))
            conditions = []
            if original.get("type") == "indirect":
                conditions.append(f"indirect flake:{original.get('id')}")
            if node.get("flake") is False:
                conditions.append("not a flake")
            version = str(locked.get("rev") or locked.get("lastModified") or "")
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=str(locked["narHash"])
                    if isinstance(locked.get("narHash"), str)
                    else None,
                    resolved_from=source,
                    scope=Scope.BUILD,
                    dependencies=children,
                    direct=key in direct,
                    local=locked.get("type") == "path",
                    platform=tuple(conditions),
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class NixEcosystem(BaseEcosystem):
    """Flake inputs and hand-pinned sources."""

    id = "nix"
    purl_type = "nix"
    manifest_globs: tuple[str, ...] = ("**/flake.nix", "**/default.nix", "**/shell.nix")
    lockfile_globs: tuple[str, ...] = ("**/flake.lock",)
    registry_hosts: frozenset[str] = frozenset()
    registryless = True
    """No registry: every input is a repository or an archive, so none departs from one."""
    git_distribution = True
    locked_inputs = "inputs."
    """Declarations whose ref is an update channel that flake.lock pins: a flake's inputs."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        """A flake input is a repository or an archive by definition; there is no registry apart
        from them. A forge or HTTPS archive is the ordinary case; plain HTTP is not."""
        return bool(url) and str(url).startswith(("https://", "git+https://", "git+ssh://"))

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename == "flake.nix":
            return Flake.parse(content, self.id)
        return Fetchers.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return FlakeLock.parse(content, self.id)


__all__ = ["Fetchers", "Flake", "FlakeLock", "FlakeRef", "NixEcosystem", "NixLexer", "NixReader"]
