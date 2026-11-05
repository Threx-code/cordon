"""Glob patterns with path semantics: `*` never crosses a `/`, `**` spans directories, and a pattern
is compiled once into tokens and matched without backtracking blow-up.

Used wherever a path is matched against a pattern: the walker's excludes, a policy's paths, a
detector's file globs, an ecosystem's manifest names. Nothing here touches the file system.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from cordon_scanner.foundation.errors import ConfigError

# Directories that are never source and are always large. Excluding them is not
# a security decision, it is an acknowledgement that they are build output or a
# package manager's cache, reproducible from a manifest that IS scanned.
#
# Deliberately NOT here: `vendor`, and anything else that can contain committed
# third-party source. Vendored code is code that ships, it is rarely reviewed,
# and it is therefore one of the better places to hide a payload. Excluding it
# by default would be exactly the wrong default. `build` and `dist` are absent
# for the same reason: a built artefact is a thing that gets published.
#
# Also deliberately absent: any reading of `.gitignore`. It is a natural
# suggestion -- it would have caught the tool caches below without listing them
# -- and it is the wrong mechanism here, because `.gitignore` is written by the
# repository being scanned. Honouring it would hand the scan target a
# one-line, entirely unremarkable way to remove any file from its own scan,
# which is precisely what POLICY.COVERAGE.TARGET_EXCLUSION exists to report.
# This list is the tool's, so an attacker cannot extend it.


@dataclass(frozen=True, slots=True)
class _Token:
    """One element of a compiled glob."""

    kind: str
    """`lit` a literal run, `any` one non-separator, `star` a non-separator run,
    `globstar` any run including separators, `class` a character class."""

    text: str = ""
    negated: bool = False
    members: frozenset[str] = frozenset()
    ranges: tuple[tuple[str, str], ...] = ()

    def accepts(self, char: str) -> bool:
        if char in self.members:
            return not self.negated
        for low, high in self.ranges:
            if low <= char <= high:
                return not self.negated
        return self.negated


class GlobMatcher:
    """A compiled glob, matched without a regex engine.

    Globs used to be translated into regular expressions, and every construct
    emitted was linear on its own. A chain of them was not: `**a**a**a**a`
    became `^.*a.*a.*a.*a$`, whose cost on a non-matching path grows with the
    fourth power of its length. Measured, that is 0.2s at 168 characters and
    days at the 4096 bytes `max_path_bytes` permits -- per path, against every
    path in the tree.

    Nothing could interrupt it once started. `per_file_timeout` and
    `total_timeout` are checked between units, and Python's `re` cannot be
    interrupted mid-match; the module that documents those limits says so
    itself. And both halves were attacker-supplied: `scan.exclude` in a
    discovered config, and the directory names it runs against.

    So the regex is gone. Matching is the classic greedy wildcard walk with a
    single backtrack point, which is linear in the ordinary case and bounded by
    the product of pattern and path length in the worst -- no chain of wildcards
    can make it super-linear, because there is no backtracking tree to explode.

    The distinction the old translation made is preserved: `*` and `?` do not
    cross a separator, `**` does. That is why `src/*.py` must not match
    `src/deep/app.py`, and getting it wrong on an *exclusion* removes more than
    the author intended, which is the failure this module exists to prevent.
    """

    __slots__ = ("_pattern_segments", "_required_tail", "pattern")

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        segments: list[tuple[_Token, ...] | None] = []
        for raw in pattern.split("/"):
            if raw == "**":
                segments.append(None)
                continue
            segments.append(
                tuple(
                    _Token("star") if token.kind == "globstar" else token
                    for token in self._parse(raw)
                )
            )
        self._pattern_segments: tuple[tuple[_Token, ...] | None, ...] = tuple(segments)
        # A necessary condition, checked before the walk. When the pattern's
        # last segment ends in a literal -- `**/*.yml`, `**/Dockerfile`, which is
        # most of what a rule's `paths:` holds -- every matching path ends with
        # that literal, so `str.endswith` rejects in C what the segment walk
        # would reject in Python. The walk runs once per candidate rule per
        # file, and nearly all of those are misses.
        last = self._pattern_segments[-1] if self._pattern_segments else None
        self._required_tail: str = (
            last[-1].text if last and last[-1].kind == "lit" and last[-1].text else ""
        )

    @staticmethod
    def _parse(pattern: str) -> tuple[_Token, ...]:
        tokens: list[_Token] = []
        literal: list[str] = []
        index = 0
        size = len(pattern)

        def flush() -> None:
            if literal:
                tokens.append(_Token("lit", "".join(literal)))
                literal.clear()

        while index < size:
            char = pattern[index]
            if char == "*":
                flush()
                if pattern.startswith("**/", index):
                    # `**/` may match zero directories, so the separator it
                    # carries is optional.
                    tokens.append(_Token("globstar", "/"))
                    index += 3
                    continue
                if pattern.startswith("**", index):
                    tokens.append(_Token("globstar"))
                    index += 2
                    continue
                tokens.append(_Token("star"))
                index += 1
                continue
            if char == "?":
                flush()
                tokens.append(_Token("any"))
                index += 1
                continue
            if char == "[":
                close = pattern.find("]", index + 1)
                if close == -1:
                    literal.append(char)
                    index += 1
                    continue
                flush()
                tokens.append(GlobMatcher._character_class(pattern[index + 1 : close], pattern))
                index = close + 1
                continue
            literal.append(char)
            index += 1

        flush()
        return tuple(tokens)

    @staticmethod
    def _character_class(body: str, pattern: str) -> _Token:
        negated = body.startswith(("!", "^"))
        if negated:
            body = body[1:]
        if not body:
            # An empty class matches nothing, which is what the glob expresses.
            return _Token("class", negated=False)
        members: set[str] = set()
        ranges: list[tuple[str, str]] = []
        index = 0
        while index < len(body):
            if index + 2 < len(body) and body[index + 1] == "-":
                low, high = body[index], body[index + 2]
                if low > high:
                    raise ConfigError(
                        f"ignore pattern {pattern!r} has a reversed range [{low}-{high}]",
                        hint="A character range must run low to high, as in [a-z].",
                    )
                ranges.append((low, high))
                index += 3
                continue
            members.add(body[index])
            index += 1
        return _Token("class", negated=negated, members=frozenset(members), ranges=tuple(ranges))

    def match(self, path: str) -> _MatchResult | None:
        """Whether the whole path matches. Named to mirror `re.Pattern.match`."""
        return _MATCHED if self._walk(path) else None

    def _walk(self, path: str) -> bool:
        """Match segment by segment, then character by character within one.

        Preceded by the literal-tail rejection described in `__init__`.

        Two nested applications of the same classic algorithm, each with one
        wildcard kind, each linear. Splitting on the separator first is what
        makes that possible: a `**` segment consumes whole path segments, and
        inside a segment nothing crosses a separator, so neither level has the
        mixed wildcard kinds that force a search.

        A `**` embedded in a larger segment -- `**a**a**a**a`, the shape the
        audit used -- is matched as an ordinary `*` within that segment. It
        cannot cross a separator there anyway, and treating it as one is what
        removes the polynomial blowup that pattern existed to trigger.
        """
        if self._required_tail and not path.endswith(self._required_tail):
            return False
        return self._segments(self._pattern_segments, path.split("/"), 0, 0)

    def _segments(
        self, pattern: tuple[tuple[_Token, ...] | None, ...], parts: list[str], pi: int, si: int
    ) -> bool:
        # `None` marks a `**` segment. Greedy walk with a single backtrack
        # point, over segments rather than characters.
        star_pi = -1
        star_si = 0
        while si < len(parts):
            if pi < len(pattern) and pattern[pi] is None:
                star_pi = pi
                star_si = si
                pi += 1
                continue
            if pi < len(pattern) and self._one(pattern[pi], parts[si]):
                pi += 1
                si += 1
                continue
            if star_pi == -1:
                return False
            star_si += 1
            si = star_si
            pi = star_pi + 1
        while pi < len(pattern) and pattern[pi] is None:
            # A trailing `**` must consume at least one segment: `corpus/**`
            # means everything inside `corpus`, not `corpus` itself.
            if pi == len(pattern) - 1 and star_pi == -1 and si == len(parts):
                return False
            pi += 1
        return pi == len(pattern)

    @staticmethod
    def _one(tokens: tuple[_Token, ...] | None, part: str) -> bool:
        """Match one path segment against one pattern segment."""
        if tokens is None:  # pragma: no cover - handled by the caller
            return True
        ti = si = 0
        star_ti = -1
        star_si = 0
        while si < len(part):
            token = tokens[ti] if ti < len(tokens) else None
            if token is not None and token.kind == "lit" and part.startswith(token.text, si):
                si += len(token.text)
                ti += 1
                continue
            if token is not None and token.kind == "any":
                si += 1
                ti += 1
                continue
            if token is not None and token.kind == "class" and token.accepts(part[si]):
                si += 1
                ti += 1
                continue
            if token is not None and token.kind == "star":
                star_ti = ti
                star_si = si
                ti += 1
                continue
            if star_ti == -1:
                return False
            star_si += 1
            si = star_si
            ti = star_ti + 1
        while ti < len(tokens) and tokens[ti].kind == "star":
            ti += 1
        return ti == len(tokens)


@dataclass(frozen=True, slots=True)
class _MatchResult:
    """Stands in for `re.Match` so call sites reading a truthy result work."""


_MATCHED = _MatchResult()


class PathGlob:
    """Glob matching with path semantics, kept separate from traversal.

    ``fnmatch`` is not usable here because its ``*`` matches ``/``. That makes
    ``src/*.py`` silently match ``src/deep/app.py``, and for an *exclusion*
    pattern it means removing far more than the author intended. Silent
    over-exclusion is the exact failure this module exists to prevent, so the
    translation is done explicitly rather than delegated.

    Deliberately globs and not regular expressions at the configuration level.
    Ignore patterns are read far more often than they are written, usually by
    somebody deciding whether an exclusion is still justified, and a regex is a
    poor medium for that conversation. Keeping the surface to globs also means
    no user-supplied pattern reaches the regex engine unbounded.
    """

    @staticmethod
    @lru_cache(maxsize=1024)
    def compile(pattern: str) -> GlobMatcher:
        """Compile a glob with correct path semantics.

            ``**/``  zero or more leading path segments
            ``**``   anything, including separators
            ``*``    anything except a separator
            ``?``    one character except a separator

        Returns a `GlobMatcher` rather than a `re.Pattern`. The regex form was
        the vulnerability: a chain of `**` compiled to a chain of `.*`, whose
        cost grows with the power of their count, and nothing in the process
        could interrupt a match once it started. Callers use `.match(path)`
        either way.

        A malformed character class is reported as the configuration error it
        is. `[z-a]` used to raise `re.error`, which is not a CordonError, so it
        escaped to the top-level handler and reported "This is a bug in cordon"
        with exit 2 for what is the user's mistake, or the attacker's choice.
        """
        return GlobMatcher(pattern)

    @classmethod
    def in_package(cls, path: str, pattern: str) -> bool:
        """Match a file where it sits in its package rather than in the scan.

        A tarball member `x.tgz!package/tests/a.js` is `tests/a.js` to a rule exempting
        `tests/**`: matched as the archive holds it, and without the one folder an archive packs
        its package under (`package/`, `name-1.0/`). Root-anchored globs matched no archive
        member before (review 98 P2: 37 of them in composites.yaml). The composite evaluator
        never applies one to a hook's own script or the package's entry point, whatever its
        directory: there an exemption would be a place to hide.
        """
        _, sep, member = path.rpartition("!")
        if not sep:
            return cls.matches(path, pattern)
        _, slash, inner = member.partition("/")
        return cls.matches(member, pattern) or bool(slash and inner and cls.matches(inner, pattern))

    @classmethod
    def matches(cls, path: str, pattern: str) -> bool:
        """Match a repository-relative path against an ignore pattern."""
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            return path == prefix or path.startswith(pattern) or f"/{prefix}/" in f"/{path}"

        if cls.compile(pattern).match(path):
            return True

        # A bare name matches that name at any depth, which is what a user
        # writing `node_modules` rather than `**/node_modules/` means.
        if "/" not in pattern:
            matcher = cls.compile(pattern)
            return any(matcher.match(part) for part in path.split("/"))

        return False


__all__ = ["GlobMatcher", "PathGlob"]
