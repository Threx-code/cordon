"""`Trees.remove` leaves nothing behind, read-only entries included, and never raises.

On Windows git's read-only object files made `shutil.rmtree(ignore_errors=True)` quietly keep
every fix job's clone. A read-only DIRECTORY gives the same refusal on Linux and macOS (its
entries cannot be unlinked), so that is what these tests build; run as a non-root user, as CI is.
"""

from __future__ import annotations

import os
import stat

import pytest

from cordon_scanner.core.trees import Trees


class TreesKit:
    """This module's shared helpers."""

    @staticmethod
    def locked_tree(root):
        """A clone-shaped tree whose object directory and files are read-only."""
        objects = root / "work" / ".git" / "objects" / "ab"
        objects.mkdir(parents=True)
        blob = objects / "cdef0123"
        blob.write_bytes(b"blob")
        blob.chmod(stat.S_IREAD)
        objects.chmod(stat.S_IREAD | stat.S_IEXEC)
        return root / "work"


class TestTrees:
    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0, reason="root deletes read-only entries anyway"
    )
    def test_read_only_entries_are_removed(self, tmp_path) -> None:
        work = TreesKit.locked_tree(tmp_path)
        Trees.remove(work)
        assert not work.exists(), "the workspace is removed, read-only objects and all"

    def test_an_ordinary_tree_is_removed(self, tmp_path) -> None:
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a" / "b" / "c.txt").write_text("x")
        Trees.remove(tmp_path / "a")
        assert not (tmp_path / "a").exists()

    def test_a_path_that_is_not_there_is_not_an_error(self, tmp_path) -> None:
        Trees.remove(tmp_path / "never-created")
        Trees.remove(str(tmp_path / "never-created"))
