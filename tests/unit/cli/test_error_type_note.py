"""An internal error that ends a scan with exit 2 leaves its class name, and only that, for a harness that asks for it.

A full-scale run records one row per scan. Where the scan ended with exit 2 the row needs to say which exception did it, without the message: the message can hold a path or a line of the code
that was being scanned, which a row must not carry. The harness names a file in `CORDON_ERROR_TYPE_FILE`; the command line writes the class name there when it reports an internal error.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.account.whoami import WhoamiCommand
from cordon_scanner.cli.main import CommandLine


class Broken:
    @staticmethod
    def run_with(monkeypatch: Any, error: BaseException) -> int:
        def blow_up(args: object) -> int:
            raise error

        monkeypatch.setattr(WhoamiCommand, "run", staticmethod(blow_up))
        return CommandLine.main(["whoami"])


class TestTheErrorTypeNote:
    def test_an_internal_error_writes_its_class_name_and_exits_2(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        note = tmp_path / "type"
        monkeypatch.setenv("CORDON_ERROR_TYPE_FILE", str(note))
        assert Broken.run_with(monkeypatch, KeyError("a/secret/path.py line 3")) == 2
        assert note.read_text(encoding="utf-8") == "KeyError\n"

    @pytest.mark.parametrize(
        "error",
        [
            ValueError("x"),
            RecursionError("deep"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"),
        ],
    )
    def test_each_kind_of_error_leaves_its_own_name(
        self, tmp_path: Path, monkeypatch: Any, error: BaseException
    ) -> None:
        note = tmp_path / "type"
        monkeypatch.setenv("CORDON_ERROR_TYPE_FILE", str(note))
        Broken.run_with(monkeypatch, error)
        assert note.read_text(encoding="utf-8") == type(error).__name__ + "\n"

    def test_the_message_is_never_in_the_note(self, tmp_path: Path, monkeypatch: Any) -> None:
        note = tmp_path / "type"
        monkeypatch.setenv("CORDON_ERROR_TYPE_FILE", str(note))
        Broken.run_with(monkeypatch, RuntimeError("TOKEN=hunter2 in /home/user/code.py"))
        assert "hunter2" not in note.read_text(encoding="utf-8") and "/home" not in note.read_text(
            encoding="utf-8"
        )

    def test_without_the_variable_nothing_is_written_and_the_exit_is_the_same(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.delenv("CORDON_ERROR_TYPE_FILE", raising=False)
        monkeypatch.chdir(tmp_path)
        assert Broken.run_with(monkeypatch, RuntimeError("x")) == 2
        assert list(tmp_path.iterdir()) == []

    def test_a_note_that_cannot_be_written_does_not_change_the_exit(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv("CORDON_ERROR_TYPE_FILE", str(tmp_path / "missing" / "dir" / "type"))
        assert Broken.run_with(monkeypatch, RuntimeError("x")) == 2

    def test_an_error_the_command_line_reports_as_its_own_leaves_no_note(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from cordon_scanner.foundation.errors import ConfigError

        note = tmp_path / "type"
        monkeypatch.setenv("CORDON_ERROR_TYPE_FILE", str(note))
        Broken.run_with(monkeypatch, ConfigError("a typed refusal"))
        assert not note.exists()
