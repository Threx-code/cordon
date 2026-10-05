"""The help screens: drawn on a terminal, plain everywhere else, complete and true in both.

`cordon-scanner` opens with the CORDON wordmark, an ENVIRONMENT block read from this machine and
directory, and the commands in two columns. These hold what a reader and a script each rely on:
every command is on the screen, every environment value comes from a real probe and none can
break the screen, a piped screen carries no escape sequence or block letters, the colour rules
are the report's, nothing runs past the terminal's width, `help` resolves commands and actions,
and a command group run with no action shows its help instead of crashing.
"""

from __future__ import annotations

import ast
import io
import re
from pathlib import Path

import pytest

from cordon_scanner.cli.help import (
    Environment,
    Fact,
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
FACTS = [
    Fact("Rulepack", "0.2.0"),
    Fact("Policy", "cordon.yaml · 3 suppressions", "ok"),
    Fact("Intel", "bundled · 1d old", "ok"),
    Fact("Hooks", "pre-push runs cordon", "ok"),
    Fact("Cloud", "not signed in", "off"),
    Fact("Mode", "offline by default · executes nothing"),
]


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
        return HelpScreen(
            HelpKit.commands(), palette, width=width, unicode=unicode, environment=FACTS
        ).render()

    @staticmethod
    def repository(root: Path) -> Path:
        (root / ".git" / "hooks").mkdir(parents=True)
        (root / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
        return root

    @staticmethod
    def hook(path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/usr/bin/env bash\n{body}\n")

    @staticmethod
    def fact(root: Path, label: str) -> Fact:
        return next(f for f in Environment(root).facts() if f.label == label)

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
        for name in ("NO_COLOR", "FORCE_COLOR", "COLORTERM", "WT_SESSION", "CORDON_OFFLINE"):
            monkeypatch.delenv(name, raising=False)


class TestTheCommandList(NeutralColour):
    def test_every_command_is_in_a_group(self) -> None:
        assert HelpScreen.unlisted(HelpKit.commands()) == []

    def test_no_group_lists_a_command_twice(self) -> None:
        names = [name for _, members in HelpScreen.GROUPS for name in members]
        assert len(names) == len(set(names))

    def test_every_command_has_a_short_description_that_fits(self) -> None:
        screen = HelpScreen(HelpKit.commands(), Palette(False), width=100, environment=FACTS)
        name_width = max(len(name) for name in HelpKit.commands()) + 2
        room = screen.column_width() - name_width
        for name in HelpKit.commands():
            assert name in HelpScreen.SHORT, name
            assert len(HelpScreen.SHORT[name]) <= room, name

    @pytest.mark.parametrize("width", [100, 72])
    def test_every_command_appears(self, width: int) -> None:
        plain = ANSI.sub("", HelpKit.screen(width=width))
        for name in HelpKit.commands():
            assert re.search(rf"(^|\s){re.escape(name)}\s{{2,}}\S", plain, re.M), name

    def test_a_command_no_group_lists_still_shows(self) -> None:
        commands = {**HelpKit.commands(), "brand-new": "a command added without a group"}
        screen = HelpScreen(commands, Palette(True, True), width=100, environment=FACTS).render()
        plain = ANSI.sub("", screen)
        assert "OTHER" in plain and "brand-new" in plain


class TestLayout(NeutralColour):
    @pytest.mark.parametrize("width", [40, 64, 72, 88, 100, 160])
    def test_nothing_runs_past_the_screen(self, width: int) -> None:
        drawn = max(64, min(width, 100))
        for line in ANSI.sub("", HelpKit.screen(width=width)).split("\n"):
            assert len(line) <= drawn, line

    def test_two_columns_on_a_wide_screen(self) -> None:
        plain = ANSI.sub("", HelpKit.screen(width=100))
        assert re.search(r"SCAN AND INSPECT .*POLICY", plain)
        assert re.search(r"Rulepack .*Hooks", plain)

    def test_one_column_on_a_narrow_screen(self) -> None:
        plain = ANSI.sub("", HelpKit.screen(width=72))
        assert not re.search(r"SCAN AND INSPECT .*POLICY", plain)
        assert re.search(r"^  Hooks", plain, re.M)

    def test_the_wordmark_leads_on_a_terminal(self) -> None:
        lines = ANSI.sub("", HelpKit.screen()).split("\n")
        drawn = [line for line in lines if "█" in line]
        assert len(drawn) == len(Wordmark.ROWS)
        assert lines.index(drawn[0]) < 3

    def test_the_environment_and_next_steps_are_shown(self) -> None:
        plain = ANSI.sub("", HelpKit.screen())
        for fact in FACTS:
            assert fact.label in plain and fact.value in plain
        assert f"{PROGRAM} scan ." in plain and f"{PROGRAM} help <command>" in plain
        assert f"/tree/v{__version__}/tutorials" in plain

    def test_an_ascii_terminal_gets_ascii(self) -> None:
        assert HelpColour.unicode(HelpKit.AsciiTerminal()) is False
        ANSI.sub("", HelpKit.screen(unicode=False)).encode("ascii")


class TestPlainScreen(NeutralColour):
    def test_a_piped_screen_is_plain_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert CommandLine.run([]) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "\033[" not in out and "█" not in out
        assert "ENVIRONMENT" in out and f"v{__version__}" in out

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


class TestColour(NeutralColour):
    def test_truecolor_uses_the_console_hex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert HelpColour.truecolor() is True
        red, green, blue = Palette.rgb(Palette.ACCENT)
        assert f"38;2;{red};{green};{blue}m" in HelpKit.screen(truecolor=True)

    def test_without_truecolor_only_the_256_are_used(self) -> None:
        assert HelpColour.truecolor() is False
        screen = HelpKit.screen(truecolor=False)
        assert "38;5;" in screen and "38;2;" not in screen

    def test_without_truecolor_the_wordmark_is_the_accent(self) -> None:
        palette = Palette(True, truecolor=False)
        codes = set(re.findall(r"\033\[38;5;(\d+)m", "".join(Wordmark.lines(palette, "█"))))
        assert codes == {str(Palette.index256(Wordmark.SOLID))} == {"43"}

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


class TestEnvironment(NeutralColour):
    def test_outside_a_repository(self, tmp_path: Path) -> None:
        assert HelpKit.fact(tmp_path, "Hooks") == Fact("Hooks", "not a git repository", "off")
        assert HelpKit.fact(tmp_path, "Policy").state == "off"

    def test_a_hook_that_runs_cordon(self, tmp_path: Path) -> None:
        repo = HelpKit.repository(tmp_path)
        HelpKit.hook(repo / ".git" / "hooks" / "pre-push", "cordon-scanner scan . --staged")
        assert HelpKit.fact(repo, "Hooks") == Fact("Hooks", "pre-push runs cordon", "ok")

    def test_a_shim_is_followed_to_the_tracked_hook(self, tmp_path: Path) -> None:
        repo = HelpKit.repository(tmp_path)
        HelpKit.hook(repo / ".git" / "hooks" / "pre-push", 'exec "$root/.githooks/pre-push" "$@"')
        HelpKit.hook(repo / ".githooks" / "pre-push", '"$root/scripts/security/cordon-scan.sh"')
        assert HelpKit.fact(repo, "Hooks").value == "pre-push runs cordon"

    def test_a_shim_pointing_outside_the_repository_is_not_credited(self, tmp_path: Path) -> None:
        outside = tmp_path / "elsewhere" / "pre-push"
        HelpKit.hook(outside, "cordon-scanner scan .")
        repo = HelpKit.repository(tmp_path / "repo")
        HelpKit.hook(repo / ".git" / "hooks" / "pre-push", "exec ../elsewhere/pre-push")
        assert HelpKit.fact(repo, "Hooks").state == "warn"

    def test_a_hook_that_does_not_run_cordon(self, tmp_path: Path) -> None:
        repo = HelpKit.repository(tmp_path)
        HelpKit.hook(repo / ".git" / "hooks" / "pre-commit", "npm test")
        assert HelpKit.fact(repo, "Hooks").state == "warn"

    def test_core_hooks_path_is_honoured(self, tmp_path: Path) -> None:
        repo = HelpKit.repository(tmp_path)
        (repo / ".git" / "config").write_text("[core]\n\thooksPath = tools/hooks\n")
        HelpKit.hook(repo / "tools" / "hooks" / "pre-commit", "cordon-scanner scan . --staged")
        HelpKit.hook(repo / "tools" / "hooks" / "pre-push", "cordon-scanner scan .")
        assert HelpKit.fact(repo, "Hooks").value == "pre-commit, pre-push run cordon"

    def test_a_subdirectory_finds_its_repository(self, tmp_path: Path) -> None:
        repo = HelpKit.repository(tmp_path)
        HelpKit.hook(repo / ".git" / "hooks" / "pre-push", "cordon-scanner scan .")
        (repo / "src" / "deep").mkdir(parents=True)
        assert HelpKit.fact(repo / "src" / "deep", "Hooks").state == "ok"

    def test_a_config_and_its_suppressions(self, tmp_path: Path) -> None:
        (tmp_path / "cordon.yaml").write_text("version: 1\n")
        assert HelpKit.fact(tmp_path, "Policy") == Fact(
            "Policy", "cordon.yaml · 0 suppressions", "ok"
        )

    def test_an_invalid_config_says_so(self, tmp_path: Path) -> None:
        (tmp_path / "cordon.yaml").write_text("version: 99\n")
        fact = HelpKit.fact(tmp_path, "Policy")
        assert fact.state == "bad" and "invalid" in fact.value

    def test_signed_in_and_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cloud import auth

        monkeypatch.setattr(auth.CloudAuth, "load", classmethod(lambda cls: None))
        assert HelpKit.fact(tmp_path, "Cloud") == Fact("Cloud", "not signed in", "off")

        class Stored:
            org = "acme"
            url = "https://api.example.invalid"

        monkeypatch.setattr(auth.CloudAuth, "load", classmethod(lambda cls: Stored()))
        assert HelpKit.fact(tmp_path, "Cloud") == Fact("Cloud", "signed in · acme", "ok")

    def test_stale_intel_is_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel import feed

        class Status:
            source = "package"
            age_seconds = 40 * 86400
            stale = True

        monkeypatch.setattr(feed.FeedClient, "status", classmethod(lambda cls, **_: Status()))
        assert HelpKit.fact(tmp_path, "Intel") == Fact("Intel", "bundled · 40d old · stale", "warn")

    def test_offline_mode_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CORDON_OFFLINE", "1")
        assert "CORDON_OFFLINE" in HelpKit.fact(tmp_path, "Mode").value

    def test_a_failing_probe_never_breaks_the_screen(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cloud import auth

        def explode(cls: object) -> None:
            raise RuntimeError("keychain locked")

        monkeypatch.setattr(auth.CloudAuth, "load", classmethod(explode))
        facts = Environment(tmp_path).facts()
        assert next(f for f in facts if f.label == "Cloud") == Fact("Cloud", "unavailable", "warn")
        assert len(facts) == 6

    @pytest.mark.parametrize(
        ("seconds", "text"),
        [(60, "under an hour old"), (7200, "2h old"), (86400 * 3, "3d old")],
    )
    def test_age(self, seconds: int, text: str) -> None:
        assert Environment.age(seconds) == text


class TestHelpCommand(NeutralColour):
    def test_help_is_the_home_screen(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert CommandLine.run(["help"]) == int(ExitCode.CLEAN)
        assert "ENVIRONMENT" in capsys.readouterr().out

    def test_help_for_a_command_and_an_action(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert CommandLine.run(["help", "sbom", "generate"]) == int(ExitCode.CLEAN)
        assert f"usage: {PROGRAM} sbom generate" in capsys.readouterr().out

    def test_a_misspelt_command_gets_a_suggestion(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert CommandLine.run(["help", "sbm"]) == int(ExitCode.CONFIG_ERROR)
        err = capsys.readouterr().err
        assert "no command 'sbm'" in err and f"{PROGRAM} help sbom" in err

    def test_an_unknown_action_lists_the_real_ones(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert CommandLine.run(["help", "intel", "zzzz"]) == int(ExitCode.CONFIG_ERROR)
        err = capsys.readouterr().err
        assert "status" in err and "update" in err


class TestSubcommandHelp(NeutralColour):
    def test_painting_never_changes_the_text(self) -> None:
        for name in ("scan", "sbom", "agent", "suppress", "help"):
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
