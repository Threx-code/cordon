"""The live progress line.

A scan of a large repository takes long enough that silence is
indistinguishable from a hang, and the reasonable response to a tool that
appears hung is to kill it. A scanner people interrupt reports nothing, which is
the same outcome as a scanner that finds nothing.

So this exists to be useful, and everything below exists so that it cannot be
harmful. A display feature in a security tool earns its place only if it cannot
change a result, cannot corrupt the report, and cannot be used by the thing
being scanned to rewrite what the operator sees.
"""

from __future__ import annotations

import io
import os
import re

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cli.progress import (
    MAX_PATH,
    TerminalProgress,
    display_width,
    should_show,
)
from cordon_scanner.core.config import Config
from cordon_scanner.core.engine import Engine
from cordon_scanner.core.progress import NullProgress, Progress

PAYLOAD = 'eval(atob("cGF5bG9hZA=="))\n'


def repository(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "evil.js").write_text(PAYLOAD, encoding="utf-8")
    (root / "clean.js").write_text("const a = 1;\n", encoding="utf-8")
    (root / "package.json").write_text(
        '{"name":"x","dependencies":{"left-pad":"1.0.0"}}', encoding="utf-8"
    )
    return root


class Recorder:
    """A Progress that records instead of drawing."""

    def __init__(self) -> None:
        self.phases: list[tuple[str, int | None]] = []
        self.paths: list[str] = []
        self.finished = 0

    def phase(self, name: str, total: int | None = None) -> None:
        self.phases.append((name, total))

    def advance(self, path: str = "") -> None:
        self.paths.append(path)

    def note(self, message: str) -> None:
        return None

    def finish(self) -> None:
        self.finished += 1


class TestItCannotChangeTheResult:
    """The property that makes this safe to add at all."""

    def test_findings_are_identical_with_and_without_progress(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        config = Config.default().with_overrides(use_cache=False)

        without = Scanner(config).scan(root)
        with_progress = Scanner(config, progress=Recorder()).scan(root)

        def shape(result):
            return [
                (f.rule_id, f.location.path if f.location else "", f.fingerprint)
                for f in result.findings
            ]

        assert shape(without) == shape(with_progress)
        assert shape(without), "no findings, so this comparison proves nothing"
        assert without.complete == with_progress.complete

    def test_the_default_reports_nothing(self) -> None:
        """Nothing outside the CLI has to know progress exists."""
        assert isinstance(Engine(Config.default()).progress, NullProgress)

    def test_the_null_implementation_satisfies_the_protocol(self) -> None:
        assert isinstance(NullProgress(), Progress)
        assert isinstance(Recorder(), Progress)


class TestItReachesTheRightStream:
    def test_nothing_is_written_to_stdout(self, tmp_path, capsys) -> None:
        """A report goes to stdout when --output is not given, so a byte of
        progress there corrupts the JSON or SARIF a pipeline is parsing."""
        root = repository(tmp_path / "repo")
        stream = io.StringIO()
        config = Config.default().with_overrides(use_cache=False)
        Scanner(config, progress=TerminalProgress(stream, color=False)).scan(root)

        assert capsys.readouterr().out == ""
        assert stream.getvalue(), "nothing was drawn, so this proves nothing"


class TestWhatItReports:
    def test_it_names_the_phases_in_order(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        recorder = Recorder()
        Scanner(Config.default().with_overrides(use_cache=False), progress=recorder).scan(root)
        names = [name for name, _ in recorder.phases]
        assert names.index("identifying") < names.index("reading") < names.index("scanning")

    def test_the_scanning_phase_knows_how_many_files(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        recorder = Recorder()
        Scanner(Config.default().with_overrides(use_cache=False), progress=recorder).scan(root)
        total = next(total for name, total in recorder.phases if name == "scanning")
        assert total and total >= 3

    def test_every_scanned_file_is_reported(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        recorder = Recorder()
        Scanner(Config.default().with_overrides(use_cache=False), progress=recorder).scan(root)
        assert "evil.js" in recorder.paths
        assert "clean.js" in recorder.paths

    def test_a_warm_cache_still_counts_every_file(self, tmp_path) -> None:
        """Counting only cache misses made a warm scan appear to stall at zero
        and then finish, which reads as the hang this feature rules out."""
        root = repository(tmp_path / "repo")
        config = Config.default().with_overrides(use_cache=True, cache_dir=str(tmp_path / "cd"))
        Scanner(config).scan(root)

        recorder = Recorder()
        Scanner(config, progress=recorder).scan(root)
        assert "evil.js" in recorder.paths

    def test_it_is_released_when_a_scan_succeeds(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        recorder = Recorder()
        Scanner(Config.default().with_overrides(use_cache=False), progress=recorder).scan(root)
        assert recorder.finished == 1

    def test_it_is_released_when_a_scan_raises(self, tmp_path, monkeypatch) -> None:
        """The progress line is a partial line with no newline on it. Left
        there, a traceback lands on the same row as a half-drawn bar."""
        root = repository(tmp_path / "repo")
        recorder = Recorder()
        scanner = Scanner(Config.default().with_overrides(use_cache=False), progress=recorder)

        def explode(_target):
            raise RuntimeError("detector pool died")

        monkeypatch.setattr(scanner._engine, "_scan", explode)
        with pytest.raises(RuntimeError, match="detector pool died"):
            scanner.scan(root)
        assert recorder.finished == 1


class TestItNeverTrustsAPath:
    """A path is chosen by the repository being scanned."""

    def render(self, path: str) -> str:
        stream = io.StringIO()
        # No throttle, so the frame under test is the frame that gets drawn.
        progress = TerminalProgress(stream, color=False, min_redraw=0.0)
        progress.phase("scanning", total=10)
        progress.advance(path)
        return stream.getvalue()

    def test_an_escape_sequence_in_a_filename_is_not_executed(self) -> None:
        """`\\x1b[2J` clears the screen. A filename may legally contain it, and
        writing one to a terminal lets the scan target rewrite the scanner's
        own output -- including the line saying what was found."""
        drawn = self.render("src/evil\x1b[2J\x1b[H.js")
        assert "\x1b[2J" not in drawn
        assert "\\x1b" in drawn

    def test_a_bidi_override_in_a_filename_is_neutralised(self) -> None:
        """The trojan source technique, applied to a name rather than a body.
        Cordon reports it as a finding; it must not be susceptible to it.

        The character is assembled rather than written, because Cordon scans
        its own repository and a literal right-to-left override is a true
        positive for `SUSPECT.OBFUSCATION.BIDI.001`. The tool should not need
        an exception for itself -- the same reason the credential shapes in
        `test_redact.py` are assembled."""
        override = chr(0x202E)
        drawn = self.render(f"report{override}gnp.exe")
        assert override not in drawn
        assert "\\u202e" in drawn

    def test_a_carriage_return_cannot_forge_a_second_line(self) -> None:
        drawn = self.render("a\rFAILED: nothing found\n")
        assert "\\x0d" in drawn
        assert "\\x0a" in drawn

    def test_an_ordinary_path_is_left_alone(self) -> None:
        assert "src/app/handlers.py" in self.render("src/app/handlers.py")

    def test_a_long_path_is_shortened_from_the_left(self) -> None:
        """The tail identifies the file; the head is what every path shares."""
        drawn = self.render("a/very/deep/" + "nested/" * 20 + "target.js")
        assert "target.js" in drawn
        assert "..." in drawn
        assert len(drawn.strip()) < 200


class TestWhenItDraws:
    def test_a_terminal_gets_progress(self, monkeypatch) -> None:
        monkeypatch.delenv("CI", raising=False)

        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        assert should_show(Tty(), "auto", quiet=False)

    def test_a_pipe_does_not(self, monkeypatch) -> None:
        """Carriage-return redrawing in a log produces one unreadable row."""
        monkeypatch.delenv("CI", raising=False)
        assert not should_show(io.StringIO(), "auto", quiet=False)

    def test_ci_does_not_even_with_a_pseudo_terminal(self, monkeypatch) -> None:
        """Many runners allocate a pty, which makes isatty true somewhere the
        output is only ever read as a log file."""

        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        monkeypatch.setenv("CI", "true")
        assert not should_show(Tty(), "auto", quiet=False)

    def test_always_overrides_detection(self, monkeypatch) -> None:
        monkeypatch.setenv("CI", "true")
        assert should_show(io.StringIO(), "always", quiet=False)

    def test_never_overrides_a_terminal(self, monkeypatch) -> None:
        monkeypatch.delenv("CI", raising=False)

        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        assert not should_show(Tty(), "never", quiet=False)

    def test_quiet_wins_over_everything(self) -> None:
        """--quiet asks for findings only, and a progress line is not a
        finding."""
        assert not should_show(io.StringIO(), "always", quiet=True)


class TestItCannotBreakTheScan:
    def test_a_closed_stream_does_not_raise(self, tmp_path) -> None:
        """`cordon-scanner scan . | head` closes the pipe. A progress line that
        raised there would turn a display detail into a failed scan."""
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=False)
        progress.phase("scanning", total=2)
        stream.close()
        progress.advance("a.js")
        progress.note("still fine")
        progress.finish()

    def test_a_scan_survives_a_closed_stream(self, tmp_path) -> None:
        root = repository(tmp_path / "repo")
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=False)
        progress.phase("warm", total=1)
        stream.close()
        result = Scanner(Config.default().with_overrides(use_cache=False), progress=progress).scan(
            root
        )
        assert result.findings


class TestColour:
    def test_colour_off_emits_no_escape_sequences(self) -> None:
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=False, min_redraw=0.0)
        progress.phase("scanning", total=4)
        progress.advance("a.js")
        assert "\033" not in stream.getvalue()

    def test_colour_on_emits_them(self) -> None:
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=True)
        progress.phase("scanning", total=4)
        assert "\033[" in stream.getvalue()

    def test_the_line_is_trimmed_by_visible_width(self, monkeypatch) -> None:
        """Colour codes occupy no columns. Measuring the raw string trims a
        line that fits and wraps one that does not, and a wrapped progress line
        leaves debris because the carriage return only returns to the last
        row."""
        import shutil

        monkeypatch.setattr(shutil, "get_terminal_size", lambda *a: os.terminal_size((40, 24)))
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=True, min_redraw=0.0)
        progress.phase("scanning", total=1000)
        progress.advance("a/" * 60 + "deep.js")

        for frame in stream.getvalue().split("\r"):
            visible = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", frame)
            assert len(visible) < 40, visible


class TestConstants:
    def test_the_path_budget_is_smaller_than_a_narrow_terminal(self) -> None:
        assert MAX_PATH < 80


class TestTheSuiteControlsItsOwnEnvironment:
    """The class of bug behind three failures in this file.

    `should_show` consults `CI`; `ConfigResolver` consults `CORDON_POLICY`;
    the cache consults `CORDON_CACHE_DIR` and `XDG_CACHE_HOME`. A test that
    does not set one of those is asserting whatever the machine says, which is
    how three tests here passed locally and failed on every runner.

    `tests/conftest.py` clears them for every test. This asserts that it does,
    because a fixture that silently stopped working would put the whole class
    back without anything failing.
    """

    @pytest.mark.parametrize("name", ["CI", "CORDON_POLICY", "CORDON_CACHE_DIR", "XDG_CACHE_HOME"])
    def test_the_ambient_value_is_cleared(self, name: str) -> None:
        assert name not in os.environ

    def test_a_test_can_still_set_one(self, monkeypatch) -> None:
        monkeypatch.setenv("CI", "true")
        assert os.environ["CI"] == "true"


class TestDisplayWidth:
    """A line is measured in terminal columns, not code points.

    A CJK ideograph or an emoji is one code point and two columns; a combining
    mark is one code point and none. Measuring with `len` made a line of Latin
    text fit and the identical line of Japanese wrap, and a wrapped progress
    line leaves debris because the carriage return only returns to the start of
    the last row.

    It matters more here than in most places that get it wrong, because a
    filename comes from the repository being scanned: the characters are not
    the operator's choice.
    """

    def test_ascii_is_one_column_each(self) -> None:
        assert display_width("abc") == 3

    def test_a_cjk_ideograph_is_two(self) -> None:
        assert display_width("文") == 2

    def test_an_emoji_is_two(self) -> None:
        assert display_width("\U0001f600") == 2

    def test_a_combining_mark_is_none(self) -> None:
        """`e` plus a combining acute is two code points and one column."""
        assert display_width("é") == 1

    @pytest.mark.parametrize("columns", [40, 60, 100])
    @pytest.mark.parametrize(
        "path",
        [
            "src/app/handlers.py",
            "src/文件/テストファイル名前.py",
            "src/" + "\U0001f600" * 20 + ".js",
            "src/naïve/文件/app.js",
        ],
        ids=["ascii", "cjk", "emoji", "combining"],
    )
    @pytest.mark.parametrize("color", [False, True], ids=["plain", "colour"])
    def test_no_frame_exceeds_the_terminal(
        self, path: str, columns: int, color: bool, monkeypatch
    ) -> None:
        import shutil

        monkeypatch.setattr(shutil, "get_terminal_size", lambda *a: os.terminal_size((columns, 24)))
        stream = io.StringIO()
        progress = TerminalProgress(stream, color=color, min_redraw=0.0)
        progress.phase("scanning", total=999)
        progress.advance(path)

        for frame in stream.getvalue().split("\r"):
            visible = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", frame).rstrip()
            assert display_width(visible) < columns, repr(visible)
