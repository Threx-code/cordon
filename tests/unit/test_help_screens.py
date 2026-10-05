"""The help screens: drawn on a terminal, plain everywhere else, and complete in both.

`cordon-scanner` greets a terminal with the console's CORDON wordmark, panels and status bar,
and a pipe with plain text. These hold the properties a reader and a script each rely on: every
command is on the screen, a piped screen carries no escape sequence or box drawing, the colour
rules are the report's (NO_COLOR, FORCE_COLOR, a terminal), the panels line up at any width,
and a command group run with no action shows its help instead of crashing.
"""

from __future__ import annotations

import ast
import io
import re
from pathlib import Path

import pytest

from cordon_scanner.cli.help import (
    GroupHelp,
    HelpColour,
    HelpPainter,
    HelpScreen,
    Palette,
    Wordmark,
)
from cordon_scanner.cli.main import CommandLine
from cordon_scanner.core.errors import ExitCode
from cordon_scanner.version import PROGRAM, __version__

ANSI = re.compile(r"\033\[[0-9;]*m")
SRC = Path(__file__).resolve().parents[2] / "src" / "cordon_scanner"


class HelpKit:
    """This module's shared helpers."""

    @staticmethod
    def commands() -> dict[str, str]:
        return CommandLine.build_parser().subcommands()

    @staticmethod
    def screen(
        width: int = 100, truecolor: bool = True, colour: bool = True, unicode: bool = True
    ) -> str:
        palette = Palette(colour, truecolor)
        return HelpScreen(HelpKit.commands(), palette, width=width, unicode=unicode).render()

    class Terminal(io.StringIO):
        """A stream that says it is a terminal."""

        encoding = "utf-8"

        def isatty(self) -> bool:
            return True

    class AsciiTerminal(Terminal):
        encoding = "ascii"


class NeutralColour:
    """Every test starts with no colour preference in the environment."""

    @pytest.fixture(autouse=True)
    def neutral_colour_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("NO_COLOR", "FORCE_COLOR", "COLORTERM", "WT_SESSION"):
            monkeypatch.delenv(name, raising=False)


class TestTheCommandList(NeutralColour):
    def test_every_command_is_in_a_group(self) -> None:
        assert HelpScreen.unlisted(HelpKit.commands()) == []

    def test_no_group_lists_a_command_twice(self) -> None:
        names = [name for _, members in HelpScreen.GROUPS for name in members]
        assert len(names) == len(set(names))

    def test_every_command_appears_on_both_screens(self) -> None:
        for screen in (HelpKit.screen(), HelpKit.screen(colour=False)):
            plain = ANSI.sub("", screen)
            for name in HelpKit.commands():
                assert re.search(rf"\b{re.escape(name)}\b", plain), name

    def test_a_command_no_group_lists_still_shows(self) -> None:
        commands = {**HelpKit.commands(), "brand-new": "a command added without a group"}
        plain = ANSI.sub("", HelpScreen(commands, Palette(True, True), width=100).render())
        assert "OTHER" in plain and "brand-new" in plain

    def test_the_quick_start_commands_parse(self) -> None:
        parser = CommandLine.build_parser()
        for command, _ in HelpScreen.EXAMPLES:
            parser.parse_args(command.split())


class TestPlainScreen(NeutralColour):
    def test_a_piped_screen_is_plain_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert CommandLine.run([]) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "\033[" not in out
        assert not set("█╭╮╰╯│") & set(out)
        assert f"{PROGRAM} {__version__}" in out
        assert f"/tree/v{__version__}/tutorials" in out

    def test_no_color_beats_force_color(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.setenv("NO_COLOR", "")
        assert HelpColour.enabled(HelpKit.Terminal()) is False

    def test_force_color_draws_a_pipe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert HelpColour.enabled(io.StringIO()) is True

    def test_a_terminal_is_drawn(self) -> None:
        assert HelpColour.enabled(HelpKit.Terminal()) is True

    def test_a_closed_stream_is_not_a_terminal(self) -> None:
        stream = io.StringIO()
        stream.close()
        assert HelpColour.enabled(stream) is False


class TestTerminalScreen(NeutralColour):
    def test_the_wordmark_leads(self) -> None:
        lines = ANSI.sub("", HelpKit.screen()).split("\n")
        drawn = [line for line in lines if "█" in line]
        assert len(drawn) == len(Wordmark.ROWS)
        assert lines.index(drawn[0]) < 3

    @pytest.mark.parametrize("width", [40, 64, 80, 100, 160])
    def test_panels_and_status_bar_line_up(self, width: int) -> None:
        lines = ANSI.sub("", HelpKit.screen(width=width)).split("\n")
        boxed = [line for line in lines if line.lstrip()[:1] in ("╭", "│", "╰")]
        expected = max(64, min(width, 100)) - 2
        assert boxed and {len(line) for line in boxed} == {expected}
        status = next(line for line in lines if "cordon " in line and "executed 0" in line)
        assert len(status) == expected

    def test_truecolor_uses_the_console_hex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert HelpColour.truecolor() is True
        screen = HelpKit.screen(truecolor=True)
        red, green, blue = Palette.rgb(Palette.ACCENT)
        assert f"38;2;{red};{green};{blue}m" in screen

    def test_without_truecolor_only_the_256_are_used(self) -> None:
        assert HelpColour.truecolor() is False
        screen = HelpKit.screen(truecolor=False)
        assert "38;5;" in screen and "38;2;" not in screen and "48;2;" not in screen

    def test_without_truecolor_the_wordmark_is_one_colour(self) -> None:
        palette = Palette(True, truecolor=False)
        codes = set(re.findall(r"\033\[38;5;(\d+)m", "".join(Wordmark.lines(palette, "█"))))
        assert codes == {str(Palette.index256(Wordmark.SOLID))} == {"43"}

    def test_an_ascii_terminal_gets_ascii(self) -> None:
        assert HelpColour.unicode(HelpKit.AsciiTerminal()) is False
        screen = ANSI.sub("", HelpKit.screen(unicode=False))
        screen.encode("ascii")
        assert "#" in screen and "+-" in screen


class TestPalette(NeutralColour):
    @pytest.mark.parametrize(
        ("rgb", "index"),
        [((0, 0, 0), 16), ((255, 0, 0), 196), ((255, 255, 255), 231), ((128, 128, 128), 244)],
    )
    def test_xterm256(self, rgb: tuple[int, int, int], index: int) -> None:
        assert Palette.xterm256(*rgb) == index

    def test_every_palette_colour_has_a_256_stand_in(self) -> None:
        colours = {c for fg, bg, _, _ in Palette.ROLES.values() for c in (fg, bg) if c}
        assert colours <= set(Palette.XTERM)
        assert all(16 <= index <= 255 for index in Palette.XTERM.values())

    def test_a_disabled_palette_writes_no_escape(self) -> None:
        palette = Palette(False)
        assert all(palette.paint(role, "x") == "x" for role in Palette.ROLES)

    def test_width_ignores_escapes(self) -> None:
        assert Palette.width(Palette(True, True).paint("badge", " cordon ")) == len(" cordon ")


class TestSubcommandHelp(NeutralColour):
    def test_painting_never_changes_the_text(self) -> None:
        for name in ("scan", "sbom", "agent", "suppress"):
            parser = CommandLine.build_parser().subparser(name)
            assert parser is not None
            plain = parser.render_help(io.StringIO())
            painted = HelpPainter(Palette(True, True)).paint(plain)
            assert ANSI.sub("", painted) == plain

    def test_a_terminal_gets_colour(self) -> None:
        parser = CommandLine.build_parser().subparser("scan")
        assert parser is not None
        assert "\033[" in parser.render_help(HelpKit.Terminal())

    def test_a_bad_flag_is_an_argparse_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exit_info:
            CommandLine.run(["scan", "--no-such-flag"])
        assert exit_info.value.code == 2
        err = capsys.readouterr().err
        assert "error:" in err and "\033[" not in err


class TestGroupsWithoutAnAction(NeutralColour):
    @pytest.mark.parametrize("group", sorted(GroupHelp.NEEDS_ACTION))
    def test_shows_its_help_and_exits_as_a_config_error(
        self, group: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert CommandLine.run([group]) == int(ExitCode.CONFIG_ERROR)
        err = capsys.readouterr().err
        assert "internal error" not in err
        assert f"{PROGRAM} {group}" in err and "choose an action" in err

    def test_every_listed_group_has_that_destination(self) -> None:
        parser = CommandLine.build_parser()
        for group, dest in GroupHelp.NEEDS_ACTION.items():
            sub = parser.subparser(group)
            assert sub is not None, group
            assert dest in vars(sub.parse_args([])), (group, dest)


class TestTheCommandIsNamedRight(NeutralColour):
    """No message tells a reader to run `cordon <command>`: the command is `cordon-scanner`."""

    SUBCOMMANDS = "|".join(sorted(HelpKit.commands()))

    def test_no_user_facing_string_names_a_cordon_command(self) -> None:
        pattern = re.compile(rf"(?<![\w-])cordon ({self.SUBCOMMANDS})\b")
        offenders = []
        for path in SRC.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # Docstrings and attribute docstrings: any string that is a statement by itself.
            docstrings = {
                id(node.value)
                for node in ast.walk(tree)
                if isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            }
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in docstrings
                    and pattern.search(node.value)
                ):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: {node.value[:80]}")
        assert not offenders, offenders
