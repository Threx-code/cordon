"""What a vcpkg portfile downloads: the `vcpkg_from_github` and `vcpkg_download_distfile` calls with their SHA-512, read as text.

A portfile is CMake, and CMake is run only by vcpkg. This reads the calls as text and expands the variables a port sets itself
(`${VERSION}`, `${PORT}`, and `set(NAME value)` of literals). A call it cannot read to a URL and a SHA-512 is refused rather than
guessed at, and so is any helper that fetches another way (`vcpkg_from_gitlab`, `vcpkg_from_git`, ...): nothing the planner does not
hold to a hash may reach vcpkg, which the run's asset sources enforce (`planner.py`). Every call is read wherever it sits (inside an
`if` too): the planner scans a superset of what one build downloads, never fewer files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.sources.install.plan import InstallRefused


@dataclass(frozen=True)
class Source:
    """One archive a port downloads: where from, the SHA-512 vcpkg checks it against, and the name vcpkg gives it."""

    url: str
    sha512: bytes
    filename: str


class PortfileCalls:
    """The calls of a portfile as (name, tokens): a token is its text, with quotes and `[[ ]]` brackets taken off."""

    CALL: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")
    BRACKET: ClassVar[re.Pattern[str]] = re.compile(r"\[(=*)\[")

    @classmethod
    def read(cls, text: str) -> list[tuple[str, list[str]]]:
        calls: list[tuple[str, list[str]]] = []
        at = 0
        while (found := cls.CALL.search(text, at)) is not None:
            tokens, at = cls.tokens(text, found.end())
            calls.append((found.group(1).lower(), tokens))
        return calls

    @classmethod
    def tokens(cls, text: str, start: int) -> tuple[list[str], int]:
        """The arguments from just after a `(`, and the index just after its matching `)`."""
        tokens: list[str] = []
        depth = 1
        at = start
        word: list[str] = []
        while at < len(text):
            char = text[at]
            if char == '"':
                end = at + 1
                body: list[str] = []
                while end < len(text) and text[end] != '"':
                    if text[end] == "\\" and end + 1 < len(text):
                        end += 1
                    body.append(text[end])
                    end += 1
                tokens.append("".join(body))
                at = end + 1
                continue
            bracket = cls.BRACKET.match(text, at)
            if bracket is not None:
                close = f"]{bracket.group(1)}]"
                end = text.find(close, bracket.end())
                end = len(text) if end < 0 else end
                tokens.append(text[bracket.end() : end])
                at = end + len(close)
                continue
            if char == "#":
                eol = text.find("\n", at)
                at = len(text) if eol < 0 else eol
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    if word:
                        tokens.append("".join(word))
                    return tokens, at + 1
            if char.isspace():
                if word:
                    tokens.append("".join(word))
                    word = []
            else:
                word.append(char)
            at += 1
        raise InstallRefused("a portfile call is never closed")


class Portfile:
    #: Helpers that fetch a port's source another way: not read, so a port using one is refused.
    OTHER: ClassVar[frozenset[str]] = frozenset(
        {
            "vcpkg_from_gitlab",
            "vcpkg_from_bitbucket",
            "vcpkg_from_sourceforge",
            "vcpkg_from_git",
            "vcpkg_from_gitiles",
        }
    )
    #: Arguments of `vcpkg_from_github` that change where it downloads from or skip the hash.
    GITHUB_REFUSED: ClassVar[frozenset[str]] = frozenset(
        {"GITHUB_HOST", "AUTHORIZATION_TOKEN", "USE_TARBALL_API"}
    )
    DISTFILE_REFUSED: ClassVar[frozenset[str]] = frozenset(
        {"SKIP_SHA512", "ALWAYS_REDOWNLOAD", "HEADERS"}
    )
    GITHUB_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "OUT_SOURCE_PATH",
            "REPO",
            "REF",
            "SHA512",
            "HEAD_REF",
            "PATCHES",
            "FILE_DISAMBIGUATOR",
            "GITHUB_HOST",
            "AUTHORIZATION_TOKEN",
            "USE_TARBALL_API",
            "NO_REMOVE_ONLY",
        }
    )
    DISTFILE_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"URLS", "FILENAME", "SHA512", "SKIP_SHA512", "ALWAYS_REDOWNLOAD", "HEADERS", "QUIET"}
    )
    #: A `${NAME}` reference, or any `$ENV{` or unclosed `${`, which refuse; the environment name is read
    #: only as far as the message shows, so an unclosed run is never read again from inside.
    VARIABLE: ClassVar[re.Pattern[str]] = re.compile(
        r"\$\{([A-Za-z0-9_]++)\}|\$ENV\{[^}]{0,60}+|\$\{"
    )
    SHA512: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{128}")
    REPO: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    SAFE_REF: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.+/~-]+")

    @classmethod
    def sources(cls, text: str, port: str, version: str) -> list[Source]:
        """Every archive the portfile of `port` (at `version`) downloads with a hash; refused when one cannot be read."""
        variables = {"VERSION": version, "PORT": port}
        found: list[Source] = []
        for name, tokens in PortfileCalls.read(text):
            if name == "set" and tokens:
                cls.assign(tokens, variables)
            elif name in cls.OTHER:
                raise InstallRefused(
                    f"{port}: the portfile fetches with {name}, which Cordon does not read yet, so its source is not held to a hash"
                )
            elif name == "vcpkg_from_github":
                found.append(cls.github(tokens, variables, port))
            elif name == "vcpkg_download_distfile":
                found.append(cls.distfile(tokens, variables, port))
        return found

    @classmethod
    def assign(cls, tokens: list[str], variables: dict[str, str]) -> None:
        """`set(NAME value)` of one literal; any other form leaves the name unknown (so a later use is refused)."""
        name = tokens[0]
        if len(tokens) == 2:
            try:
                variables[name] = cls.expand(tokens[1], variables, "")
                return
            except InstallRefused:
                pass
        variables.pop(name, None)

    @classmethod
    def expand(cls, token: str, variables: dict[str, str], port: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name is None or name not in variables:
                raise InstallRefused(
                    f"{port}: the portfile uses {match.group(0)[:60]!r}, which Cordon cannot expand to a download"
                )
            return variables[name]

        return cls.VARIABLE.sub(replace, token)

    @classmethod
    def arguments(cls, tokens: list[str], keywords: frozenset[str]) -> dict[str, list[str]]:
        """The tokens after each keyword, up to the next one. The first token is the output variable of a distfile call."""
        out: dict[str, list[str]] = {}
        key = ""
        for token in tokens:
            if token in keywords:
                key = token
                out.setdefault(key, [])
            elif key:
                out[key].append(token)
        return out

    @classmethod
    def github(cls, tokens: list[str], variables: dict[str, str], port: str) -> Source:
        args = cls.arguments(tokens, cls.GITHUB_KEYWORDS)
        refused = cls.GITHUB_REFUSED & set(args)
        if refused:
            raise InstallRefused(
                f"{port}: vcpkg_from_github with {sorted(refused)[0]} is not read by Cordon"
            )
        repo = cls.one(args, "REPO", port, variables)
        ref = cls.one(args, "REF", port, variables)
        digest = cls.digest(args, port, variables)
        if not cls.REPO.fullmatch(repo) or not cls.SAFE_REF.fullmatch(ref) or ".." in ref:
            raise InstallRefused(
                f"{port}: vcpkg_from_github names a repository or reference Cordon cannot read"
            )
        org, name = repo.split("/")
        sanitized = ref.replace("/", "_-")
        return Source(
            f"https://github.com/{repo}/archive/{ref}.tar.gz",
            digest,
            f"{org}-{name}-{sanitized}.tar.gz",
        )

    @classmethod
    def distfile(cls, tokens: list[str], variables: dict[str, str], port: str) -> Source:
        args = cls.arguments(tokens[1:], cls.DISTFILE_KEYWORDS)
        refused = cls.DISTFILE_REFUSED & set(args)
        if refused:
            raise InstallRefused(
                f"{port}: vcpkg_download_distfile with {sorted(refused)[0]} is not held to a hash"
            )
        urls = [cls.expand(u, variables, port) for u in args.get("URLS", [])]
        secure = [u for u in urls if u.startswith("https://")]
        if not secure:
            raise InstallRefused(
                f"{port}: vcpkg_download_distfile has no https URL Cordon can read"
            )
        return Source(
            secure[0],
            cls.digest(args, port, variables),
            cls.one(args, "FILENAME", port, variables),
        )

    @classmethod
    def one(cls, args: dict[str, list[str]], key: str, port: str, variables: dict[str, str]) -> str:
        values = args.get(key, [])
        if len(values) != 1:
            raise InstallRefused(f"{port}: the portfile's download names no single {key}")
        return cls.expand(values[0], variables, port)

    @classmethod
    def digest(cls, args: dict[str, list[str]], port: str, variables: dict[str, str]) -> bytes:
        text = cls.one(args, "SHA512", port, variables)
        if cls.SHA512.fullmatch(text) is None:
            raise InstallRefused(f"{port}: the portfile's download has no SHA512 Cordon can read")
        return bytes.fromhex(text)


__all__ = ["Portfile", "PortfileCalls", "Source"]
