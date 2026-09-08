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
import re
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
# by default would be exactly the wrong default.
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
"""How many `**` segments one ignore pattern may contain.

Each compiles to `.*`, which can start anywhere, so a chain of them turns
matching a single path into a polynomial search. Four is more than any real
exclusion needs and well under where the cost becomes noticeable."""


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
                if self._inside_pruned(rel_dir) and not any(
                    rel.startswith(f"{wanted}/") for wanted in self.descend_into
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
            return not on_the_way

        # Inside a tree entered only to reach a wanted path.
        parent = child_rel.rpartition("/")[0]
        if parent and self._inside_pruned(parent):
            return not (
                on_the_way
                or any(child_rel.startswith(f"{w}/") or child_rel == w for w in self.descend_into)
            )
        return False

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
    def compile(pattern: str) -> re.Pattern[str]:
        """Translate a glob into a regex with correct path semantics.

            ``**/``  zero or more leading path segments
            ``**``   anything, including separators
            ``*``    anything except a separator
            ``?``    one character except a separator

        Every construct emitted is linear-time on its own, but a chain of them
        is not: `**a**a**a...` compiles to `^.*a.*a.*a...$`, which on a
        non-matching path is polynomial and did not complete in 120 seconds with
        thirteen segments. The count of `**` is therefore capped.

        A malformed character class is reported as the configuration error it
        is. Bodies are passed through so `[a-z]` keeps working, which means a
        bad one reaches the engine; `[z-a]` and `[\\]` used to raise `re.error`,
        which is not a CordonError, so it escaped to the top-level handler and
        reported "This is a bug in cordon" with exit 2. It is the user's
        mistake, and now it says so with exit 3.
        """
        if pattern.count("**") > MAX_RECURSIVE_WILDCARDS:
            raise ConfigError(
                f"ignore pattern {pattern!r} uses ** more than {MAX_RECURSIVE_WILDCARDS} times",
                hint=(
                    "Each ** can start anywhere, so a chain of them makes matching "
                    "one path cost time polynomial in its length. Narrow the pattern."
                ),
            )

        out: list[str] = []
        i = 0
        n = len(pattern)
        while i < n:
            ch = pattern[i]
            if ch == "*":
                if pattern.startswith("**/", i):
                    # `**/` may match zero directories, so the separator is
                    # optional.
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                if pattern.startswith("**", i):
                    out.append(".*")
                    i += 2
                    continue
                out.append("[^/]*")
                i += 1
                continue
            if ch == "?":
                out.append("[^/]")
                i += 1
                continue
            if ch == "[":
                close = pattern.find("]", i + 1)
                if close == -1:
                    out.append(re.escape(ch))
                    i += 1
                    continue
                body = pattern[i + 1 : close]
                if body.startswith("!"):
                    body = "^" + body[1:]
                if not body or body == "^":
                    # An empty class is a regex error; as a glob it matches
                    # nothing, which is what this expresses.
                    out.append("(?!)")
                else:
                    out.append(f"[{body}]")
                i = close + 1
                continue
            out.append(re.escape(ch))
            i += 1

        try:
            return re.compile(f"^{''.join(out)}$")
        except re.error as exc:
            # Character-class bodies are passed through so ranges keep working,
            # which means a malformed one reaches the engine. `[z-a]` and `[\\]`
            # raised `re.error` here -- not a CordonError, so it escaped to the
            # top-level handler and reported "This is a bug in cordon" with exit
            # 2, for what is a configuration mistake or an attacker's choice. It
            # is the user's mistake, and it says so, with exit 3.
            raise ConfigError(
                f"ignore pattern {pattern!r} is not valid: {exc}",
                hint=(
                    "Check the character classes. A glob supports [abc], [a-z] "
                    "and [!abc]; the range must run low to high."
                ),
            ) from exc

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
