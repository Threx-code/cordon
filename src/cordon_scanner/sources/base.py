"""Where a scan reads its files from.

Ordinarily the answer is the working tree, and there is nothing to decide. Two
situations make it a real question, and the first of them is a security control
rather than a convenience.

**The git index.** A pre-commit hook that reads the working tree can be defeated
by staging a poisoned file and then restoring the clean version on disk. The
poisoned blob is what gets committed, the clean one is what gets scanned, and the
hook reports success. Reading the index closes that gap. It cannot be done by
filtering the working tree afterwards, because the bytes themselves differ --
which is why the source is an abstraction rather than another exclusion rule.

**A narrowed set of paths.** `--tracked` and `--git-diff` restrict which files
are examined, on a large repository where scanning everything on every push is
not affordable.

Narrowing applies only to *file* analysis. Inventory, dependency and manifest
checks always run against the whole tree, because a malicious transitive
dependency appears in no diff and a lifecycle hook added to a manifest changes
how every other file in the repository is scored.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cordon_scanner.core.content import FileContent

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from cordon_scanner.core.content import Skipped
    from cordon_scanner.core.limits import Limits
    from cordon_scanner.core.walker import WalkEntry, Walker


@runtime_checkable
class FileSource(Protocol):
    """Supplies the files a scan examines, and their bytes.

    Two operations rather than one, because the pair is what makes the index
    source possible: a source may narrow *which* files are seen, or change
    *what* their content is, or both.
    """

    id: str

    def entries(self, root: Path, walker: Walker) -> Iterator[WalkEntry]:
        """Yield the files to examine, in the walker's deterministic order."""
        ...

    def load(self, entry: WalkEntry, limits: Limits) -> FileContent | Skipped:
        """Read one file's content."""
        ...

    @property
    def parallel_safe(self) -> bool:
        """Whether worker processes may re-read these files from disk.

        False for any source whose bytes are not what is on disk. A worker pool
        that re-reads by path would scan the working tree while the caller
        believes it is scanning the index -- reintroducing exactly the bypass
        the index source exists to close, and doing it silently.
        """
        ...

    def describe(self) -> str:
        """One line naming what was scanned, for the report header."""
        ...

    @property
    def empty_selection_is_normal(self) -> bool:
        """Whether selecting no files is an ordinary outcome for this source.

        True only for the git index: a pre-commit hook fires on every commit,
        including ones that stage nothing, and failing there teaches people to
        pass `--no-verify`.

        It is False everywhere else, and deliberately so. `--tracked` in a
        repository where nothing is tracked selects nothing too, and that is not
        ordinary -- it is a pipeline scanning no files and reporting success. An
        empty selection is always *reported*; this property only decides whether
        it is a warning or a note.
        """
        ...


class WorkingTreeSource:
    """The default: files as they are on disk.

    Delegates entirely to the walker. Exists so that the git sources are one
    implementation of a shared contract rather than a special case threaded
    through the engine with conditionals.
    """

    id = "worktree"

    def entries(self, root: Path, walker: Walker) -> Iterator[WalkEntry]:
        yield from walker.walk(root)

    def load(self, entry: WalkEntry, limits: Limits) -> FileContent | Skipped:
        return FileContent.load(entry.real_path, entry.rel_path, limits)

    @property
    def parallel_safe(self) -> bool:
        return True

    @property
    def empty_selection_is_normal(self) -> bool:
        return False

    def describe(self) -> str:
        return "working tree"


__all__ = ["FileSource", "WorkingTreeSource"]
