"""The caches' ownership checks, on POSIX and as Windows sees them.

The rule-engine caches called os.getuid() directly: on Windows that does not exist, and 11 tests of
the match and compile caches failed there with AttributeError (4 Nov, the first Windows run since
CI came back on). Ownership answers on both, and on Windows never asks for a uid."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cordon_scanner.foundation.files.ownership import Ownership


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
class TestOnPosix:
    @pytest.mark.parametrize(
        ("mode", "private", "closed_to_writers"),
        [(0o600, True, True), (0o644, False, True), (0o666, False, False), (0o620, False, False)],
    )
    def test_the_mode_decides(
        self, tmp_path: Path, mode: int, private: bool, closed_to_writers: bool
    ) -> None:
        file = tmp_path / "entry"
        file.write_bytes(b"x")
        file.chmod(mode)
        st = file.stat()
        assert Ownership.mine(st)
        assert Ownership.private(st) is private
        assert Ownership.others_cannot_write(st) is closed_to_writers


class TestAsWindowsSeesIt:
    def test_no_uid_is_asked_for_and_the_profile_acl_is_trusted(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        file = tmp_path / "entry"
        file.write_bytes(b"x")
        st = file.stat()
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.delattr(os, "getuid", raising=False)
        assert Ownership.mine(st) and Ownership.private(st) and Ownership.others_cannot_write(st)
