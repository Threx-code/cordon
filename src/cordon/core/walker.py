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

from cordon.core.limits import DEFAULT_LIMITS, Limits

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

    @property
    def total_excluded(self) -> int:
        return sum(self.excluded_by_pattern.values())


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
        follow_symlinks: bool = False,
    ) -> None:
        self.exclude = tuple(exclude)
        self.include = tuple(include)
        self.limits = limits
        self.prune_dirs = prune_dirs
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
                if name in self.prune_dirs:
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
                    continue
                kept.append(name)
            dirnames[:] = kept

            for name in sorted(filenames):
                rel = f"{rel_dir}/{name}" if rel_dir else name
                self.stats.files_seen += 1

                if self.stats.files_yielded >= self.limits.max_files:
                    self.stats.limit_hit = (
                        f"max_files ({self.limits.max_files}) reached; "
                        f"traversal stopped with files remaining"
                    )
                    return

                pattern = self._excluded_by(rel)
                if pattern:
                    matched_patterns.add(pattern)
                    self.stats.excluded_by_pattern[pattern] = (
                        self.stats.excluded_by_pattern.get(pattern, 0) + 1
                    )
                    continue

                if self.include and not self._included(rel):
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
        self.stats.unmatched_patterns = tuple(
            p for p in self.exclude if p not in matched_patterns
        )

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
            if _path_matches(rel, pattern):
                return pattern
        return None

    def _included(self, rel: str) -> bool:
        return any(_path_matches(rel, pattern) for pattern in self.include)


@lru_cache(maxsize=1024)
def _compile_glob(pattern: str) -> re.Pattern[str]:
    """Translate a glob into a regex with correct path semantics.

    ``fnmatch`` is not usable here because its ``*`` matches ``/``. That makes
    ``src/*.py`` silently match ``src/deep/app.py``, and for an *exclusion*
    pattern that means removing far more than the author intended. Silent
    over-exclusion is the exact failure this module is built to prevent, so the
    translation is done explicitly:

        ``**/``  zero or more leading path segments
        ``**``   anything, including separators
        ``*``    anything except a separator
        ``?``    one character except a separator

    Every construct emitted is linear-time. There is no nesting and no
    backtracking-prone alternation, so a pattern from a configuration file
    cannot become a CPU-exhaustion vector.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**/", i):
                # `**/` may match zero directories, so the separator is optional.
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
            out.append(f"[{body}]")
            i = close + 1
            continue
        out.append(re.escape(ch))
        i += 1
    return re.compile(f"^{''.join(out)}$")


def _path_matches(path: str, pattern: str) -> bool:
    """Match a repository-relative path against an ignore pattern.

    Deliberately not a regular expression at the configuration level. Ignore
    patterns are read far more often than written, usually by somebody deciding
    whether an exclusion is still justified, and a regex is a poor medium for
    that conversation. Keeping the surface to globs also means no user-supplied
    pattern reaches the regex engine unbounded.
    """
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return path == prefix or path.startswith(pattern) or f"/{prefix}/" in f"/{path}"

    if _compile_glob(pattern).match(path):
        return True

    # A bare name matches that name at any depth, which is what a user writing
    # `node_modules` rather than `**/node_modules/` means.
    if "/" not in pattern:
        matcher = _compile_glob(pattern)
        return any(matcher.match(part) for part in path.split("/"))

    return False


__all__ = [
    "DEFAULT_PRUNE_DIRS",
    "WalkEntry",
    "WalkStats",
    "Walker",
]
