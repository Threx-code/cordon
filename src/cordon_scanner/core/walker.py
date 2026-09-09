"""Filesystem traversal.

The walker decides what gets looked at, which makes it the highest-leverage
place in the scanner for something to go wrong quietly. A file that is never
walked is never scanned, never reported, and completely indistinguishable in the
output from a file that was scanned and found clean.

Three properties follow from that:

* **Exclusions are counted and reported.** Not just applied. A scan states how
  many files each pattern removed, and an exclusion matching an implausible
  share of the tree is itself a finding.
* **An exclusion matching nothing is reported.** An entry for a path that does
  not exist is a hole held open for a file nobody would notice appearing:
  commit a file at that path and it is skipped by the very check meant to
  examine it.
* **Symlinks are never followed.** They are recorded as symlinks. Following one
  is how a scanner is induced to read a private key outside the scan root, and
  then print it as evidence into a CI log.

Ignore patterns are evaluated on directories during the walk, so a large
excluded tree is never descended into rather than being walked and filtered.
That is the difference between a fast scan and a slow one on any repository with
vendored dependencies.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.core.errors import ConfigError
from cordon_scanner.core.limits import DEFAULT_LIMITS, Limits

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

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
DEFAULT_PRUNE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        # Hypothesis writes generated example data here, including long runs of
        # escaped characters that are a true positive for the obfuscation rule.
        # Its absence made the project's own documented self-scan command fail
        # on any machine where the test suite had been run.
        ".hypothesis",
        ".eggs",
        "htmlcov",
        "node_modules",
        ".next",
        ".nuxt",
        ".turbo",
        ".parcel-cache",
        ".gradle",
        ".idea",
        ".vscode",
        "target/debug",
        "target/release",
    }
)


@dataclass(frozen=True, slots=True)
class WalkEntry:
    """One path found during traversal."""

    real_path: Path
    rel_path: str
    size: int
    is_symlink: bool = False


@dataclass
class WalkStats:
    """What the traversal did. Reported, never silently discarded."""

    files_seen: int = 0
    files_yielded: int = 0
    dirs_pruned: int = 0
    symlinks_skipped: int = 0
    excluded_by_pattern: dict[str, int] = field(default_factory=dict)
    unmatched_patterns: tuple[str, ...] = ()
    limit_hit: str | None = None
    errors: list[tuple[str, str]] = field(default_factory=list)

    # Files dropped by configuration, counted separately from `excluded_by_pattern`
    # because that dict also counts pruned *directories*. Mixing the two makes the
    # share of the tree that was skipped unreportable: one entry there can stand
    # for a directory holding ten thousand files or for none.
    files_excluded: int = 0
    files_not_included: int = 0

    pruned_dirs: dict[str, int] = field(default_factory=dict)
    """Directories the built-in prune list skipped, by name, with a count.

    Recorded because they were not. `node_modules`, `.venv`, `.vscode` and the
    rest were skipped without being counted, attributed or reported, which
    contradicts this module's own opening statement that a file never walked is
    indistinguishable in the output from one scanned and found clean.

    `node_modules` is the sharpest case. It is where an installed malicious
    dependency's code and its lifecycle scripts actually live, so a scan run
    after `npm install` -- the shape most CI pipelines use -- could not see any
    of the dependency code it was there to examine, and said nothing about it.
    `.vscode/tasks.json` and `.idea/` are execution vectors in their own right
    and were equally invisible.
    """

    @property
    def total_excluded(self) -> int:
        return sum(self.excluded_by_pattern.values())

    @property
    def files_dropped_by_config(self) -> int:
        """Files that exist and were not examined because of configuration.

        An `include` list is an exclusion written the other way round: whatever
        it does not name is dropped just as surely. Both are counted, because a
        scan blinded by `include: ["docs/**"]` and one blinded by
        `exclude: ["**/*"]` are the same result.
        """
        return self.files_excluded + self.files_not_included


# Counting excluded files stops here. Beyond this the number is no longer
# informative, and the cap is what stops a hostile exclusion pattern from making
# the accounting itself expensive.
DEFAULT_DESCEND_INTO = frozenset({".git/hooks"})
"""Pruned directories to enter anyway, by repository-relative path.

`.git` is pruned, which is right for the object store and wrong for
`.git/hooks`. A malicious `.git/hooks/pre-commit` is a classic persistence
mechanism, it survives `git clean`, and the engine already has a branch that
labels `/.git/hooks/` paths as install hooks -- a branch the walker made
unreachable. Narrow by design: this is a targeted exception, not a decision to
walk version-control internals."""

MAX_COUNTED_EXCLUDED_FILES = 100_000

MAX_RECURSIVE_WILDCARDS = 4
"""Retained as a sanity bound on pattern shape, no longer as a safety control.

It existed because globs were translated to regex and a chain of `**` became a
chain of `.*`, whose cost grew with their count. `GlobMatcher` matches segment
by segment in linear time, so the count no longer buys an attacker anything --
the audit's `**a**a**a**a.zzz` against a 12 KB path now takes two
milliseconds. The cap stays because a pattern with five `**` is almost
certainly a mistake worth naming, which is a usability reason rather than a
security one, and saying which it is matters."""


class Walker:
    """Traverses a directory tree, applying ignore rules and limits.

    Stateless between calls except for the statistics of the most recent walk,
    which are exposed on :attr:`stats`.
    """

    def __init__(
        self,
        *,
        exclude: Sequence[str] = (),
        include: Sequence[str] = (),
        limits: Limits = DEFAULT_LIMITS,
        prune_dirs: frozenset[str] = DEFAULT_PRUNE_DIRS,
        descend_into: frozenset[str] = DEFAULT_DESCEND_INTO,
        follow_symlinks: bool = False,
    ) -> None:
        self.exclude = tuple(exclude)
        self.include = tuple(include)
        self.limits = limits
        self.prune_dirs = prune_dirs
        self.descend_into = descend_into
        self.follow_symlinks = follow_symlinks
        self.stats = WalkStats()

    def walk(self, root: str | Path) -> Iterator[WalkEntry]:
        """Yield every file that should be scanned, in deterministic order.

        Sorted at every level. Filesystem order varies between systems and even
        between runs on the same system, and constraint C5 requires that two
        scans of identical content produce identical output.
        """
        root_path = Path(root).resolve()
        if root_path.is_file():
            yield from self._walk_single_file(root_path)
            return

        self.stats = WalkStats()
        matched_patterns: set[str] = set()
        total_bytes = 0
        visited: set[tuple[int, int]] = set()

        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            current = Path(dirpath)

            # Loop protection. A directory hardlink or a bind mount can make a
            # tree infinite; the inode pair makes revisits detectable.
            try:
                stat = current.stat()
                key = (stat.st_dev, stat.st_ino)
                if key in visited:
                    dirnames[:] = []
                    continue
                visited.add(key)
            except OSError as exc:
                self.stats.errors.append((str(current), str(exc)))
                dirnames[:] = []
                continue

            rel_dir = self._relative(current, root_path)
            if self._too_deep(rel_dir):
                self.stats.dirs_pruned += 1
                dirnames[:] = []
                continue

            # Prune in place so os.walk does not descend. This is what makes a
            # repository with a large dependency directory fast rather than
            # merely correct.
            kept: list[str] = []
            for name in sorted(dirnames):
                child_rel = f"{rel_dir}/{name}" if rel_dir else name
                if self._prune(name, child_rel):
                    self.stats.dirs_pruned += 1
                    # A user exclusion covering an already-pruned directory is
                    # redundant, not wrong. Recording it as matched keeps the
                    # unmatched-exclusion check from reporting correct
                    # configuration as a suspicious hole, which would teach
                    # people to delete it.
                    covering = self._excluded_by(f"{child_rel}/")
                    if covering:
                        matched_patterns.add(covering)
                    continue
                pattern = self._excluded_by(f"{child_rel}/")
                if pattern:
                    matched_patterns.add(pattern)
                    self.stats.excluded_by_pattern[pattern] = (
                        self.stats.excluded_by_pattern.get(pattern, 0) + 1
                    )
                    self.stats.dirs_pruned += 1
                    # Count what the exclusion removed. Without this the tree is
                    # pruned before its files are ever seen, so `exclude:
                    # ["src/**"]` reports a share of zero and a scan that
                    # examined almost nothing looks fully covered. Counting is a
                    # readdir pass with no stat and no file read -- far cheaper
                    # than scanning -- and it is capped, so a hostile pattern
                    # covering an enormous tree cannot turn the accounting into
                    # the denial of service it is meant to expose.
                    hidden = self._count_files(current / name)
                    self.stats.files_seen += hidden
                    self.stats.files_excluded += hidden
                    continue
                kept.append(name)
            dirnames[:] = kept

            for name in sorted(filenames):
                rel = f"{rel_dir}/{name}" if rel_dir else name
                self.stats.files_seen += 1

                # A declared limit that was never checked. An absurdly long path
                # is not a normal repository, and every downstream consumer --
                # the cache key, SARIF, a terminal -- carries it.
                if len(rel.encode("utf-8", "surrogateescape")) > self.limits.max_path_bytes:
                    self.stats.errors.append((rel[:120], "path exceeds max_path_bytes"))
                    continue

                if self.stats.files_yielded >= self.limits.max_files:
                    self.stats.limit_hit = (
                        f"max_files ({self.limits.max_files}) reached; "
                        f"traversal stopped with files remaining"
                    )
                    return

                # Inside a tree entered only to reach a wanted directory, yield
                # only what is actually under it. Entering `.git` to reach
                # `hooks` otherwise also yields `.git/HEAD`, `.git/config` and
                # every other loose file at that level.
                if (
                    self._inside_pruned(rel_dir)
                    and not any(rel.startswith(f"{wanted}/") for wanted in self.descend_into)
                    # An explicit include reaches inside a pruned tree. Without
                    # this, `--include 'node_modules/**'` walked into the
                    # directory and then dropped every file in it, scanning
                    # nothing and reporting NOTHING_SCANNED -- a default that
                    # cannot be overridden, which is not a default.
                    and not (self.include and self._included(rel))
                ):
                    continue

                pattern = self._excluded_by(rel)
                if pattern:
                    matched_patterns.add(pattern)
                    self.stats.excluded_by_pattern[pattern] = (
                        self.stats.excluded_by_pattern.get(pattern, 0) + 1
                    )
                    self.stats.files_excluded += 1
                    continue

                if self.include and not self._included(rel):
                    self.stats.files_not_included += 1
                    continue

                full = current / name
                try:
                    stat = full.lstat()
                except OSError as exc:
                    self.stats.errors.append((rel, str(exc)))
                    continue

                import stat as stat_module

                if stat_module.S_ISLNK(stat.st_mode) and not self.follow_symlinks:
                    self.stats.symlinks_skipped += 1
                    yield WalkEntry(full, rel, 0, is_symlink=True)
                    continue

                if not stat_module.S_ISREG(stat.st_mode):
                    continue

                total_bytes += stat.st_size
                if total_bytes > self.limits.max_total_bytes:
                    self.stats.limit_hit = (
                        f"max_total_bytes ({self.limits.max_total_bytes}) reached; "
                        f"traversal stopped with files remaining"
                    )
                    return

                self.stats.files_yielded += 1
                yield WalkEntry(full, rel, stat.st_size)

        # An exclusion that matched nothing is reported. It is either a mistake
        # in the configuration or a hole held open for a file that does not
        # exist yet, and both are worth surfacing.
        self.stats.unmatched_patterns = tuple(p for p in self.exclude if p not in matched_patterns)

    def _walk_single_file(self, path: Path) -> Iterator[WalkEntry]:
        self.stats = WalkStats(files_seen=1, files_yielded=1)
        yield WalkEntry(path, path.name, path.stat().st_size)

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        try:
            rel = path.relative_to(root)
        except ValueError:
            return ""
        return "" if str(rel) == "." else rel.as_posix()

    def _prune(self, name: str, child_rel: str) -> bool:
        """Whether to skip this directory entirely.

        Normally: is it in `prune_dirs`. The exception exists for `.git/hooks`.
        `.git` is pruned, which is right for the object store and wrong for the
        hooks directory -- a malicious `.git/hooks/pre-commit` is a classic
        persistence mechanism, survives `git clean`, and the engine already has
        a branch labelling `/.git/hooks/` paths as install hooks that the walker
        made unreachable.

        Descending needs two things. A pruned directory is entered when it lies
        on the path to a wanted one, and once inside such a tree every child not
        also on that path is pruned -- otherwise entering `.git` to reach
        `hooks` would walk the entire object store, which is precisely what
        pruning `.git` is for.
        """
        on_the_way = any(
            wanted == child_rel or wanted.startswith(f"{child_rel}/")
            for wanted in self.descend_into
        )
        if name in self.prune_dirs:
            # An explicit include reaches in. Pruning is a default about where
            # source usually is not, and an operator who writes
            # `--include 'node_modules/**'` has said otherwise; a default that
            # cannot be overridden is not a default. Without this, asking for
            # node_modules scanned zero files and reported NOTHING_SCANNED.
            if self._wanted_by_include(child_rel):
                return False
            if not on_the_way:
                self.stats.pruned_dirs[child_rel] = self.stats.pruned_dirs.get(child_rel, 0) + 1
            return not on_the_way

        # Inside a tree entered only to reach a wanted path.
        parent = child_rel.rpartition("/")[0]
        if parent and self._inside_pruned(parent):
            return not (
                on_the_way
                or any(child_rel.startswith(f"{w}/") or child_rel == w for w in self.descend_into)
                # ...unless an include asked for this subtree. Entering
                # `node_modules` and then pruning `node_modules/pkg` would walk
                # in and find nothing, which is the same outcome as not
                # entering.
                or self._wanted_by_include(child_rel)
            )
        return False

    def _wanted_by_include(self, rel_dir: str) -> bool:
        """Whether an include pattern explicitly asks for this directory."""
        return any(
            PathGlob.matches(rel_dir, pattern)
            or pattern.startswith(f"{rel_dir}/")
            or PathGlob.matches(f"{rel_dir}/probe", pattern)
            for pattern in self.include
        )

    def _inside_pruned(self, rel_dir: str) -> bool:
        """Whether this directory sits under one that pruning would have cut."""
        return any(part in self.prune_dirs for part in rel_dir.split("/"))

    def _too_deep(self, rel_dir: str) -> bool:
        return bool(rel_dir) and rel_dir.count("/") + 1 > self.limits.max_path_depth

    def _excluded_by(self, rel: str) -> str | None:
        """Return the exclusion pattern that removed this path, if any.

        Returns the pattern rather than a boolean so the caller can attribute
        the exclusion. Counting per pattern is what allows a scan to report
        "excluded 412 files by 6 patterns" and to flag one that removed far more
        than its author can plausibly have intended.
        """
        for pattern in self.exclude:
            if PathGlob.matches(rel, pattern):
                return pattern
        return None

    def _included(self, rel: str) -> bool:
        return any(PathGlob.matches(rel, pattern) for pattern in self.include)

    def _count_files(self, directory: Path) -> int:
        """Count the files an exclusion removed, without examining them.

        Used only for directories pruned by a *user* pattern. Default prune
        directories are not counted, because they are not a configuration choice
        anybody made about this repository and counting them would make every
        scan of a project with a dependency directory look badly covered.
        """
        total = 0
        for _, dirnames, filenames in os.walk(directory, followlinks=False):
            total += len(filenames)
            if total >= MAX_COUNTED_EXCLUDED_FILES:
                # The exact number stops mattering long before here. What the
                # report needs is "this removed an enormous amount", and the cap
                # is what keeps the accounting bounded.
                return MAX_COUNTED_EXCLUDED_FILES
            dirnames[:] = [d for d in dirnames if d not in self.prune_dirs]
        return total


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

    __slots__ = ("_pattern_segments", "pattern")

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


__all__ = [
    "DEFAULT_PRUNE_DIRS",
    "MAX_COUNTED_EXCLUDED_FILES",
    "PathGlob",
    "WalkEntry",
    "WalkStats",
    "Walker",
]
