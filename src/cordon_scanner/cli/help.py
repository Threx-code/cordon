"""The help screens: the command list, each command's options, and the errors argparse raises.

On a terminal, `cordon-scanner` greets the reader the way Cordon Cloud's console terminal does
when nothing is running: CORDON in block letters (the same cell pattern as the console's
`IdleBanner`), SCANNER under it, the commands in panels grouped by what they are for, commands
worth copying, the exit codes as coloured chips, and the console's status bar along the bottom.
The colours are the console's terminal palette, in 24-bit colour where the terminal says it has
it and the nearest of the 256 standard colours where it does not.

Every subcommand's `--help` keeps argparse's layout and gains colour for its headings, flags and
values; argparse's errors are coloured the same way.

Colour follows the rules the scan report follows (`CommandLine._use_color`): `NO_COLOR` turns it
off, `FORCE_COLOR` turns it on, and otherwise it is on only when the stream is a terminal. A
piped or captured help screen is plain text with no banner and no box drawing, which is what
scripts, tests and documentation read.

Colour is applied to argparse's finished text, never inside it. argparse pads its columns by
`len()`, and an escape sequence counted as width would push every description out of line.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import textwrap
from typing import IO, TYPE_CHECKING, Any, ClassVar, NoReturn

from cordon_scanner.version import PROGRAM, RULEPACK_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterable


class HelpColour:
    """Whether, and how richly, a help screen written to `stream` may be drawn."""

    @staticmethod
    def enabled(stream: IO[str] | None) -> bool:
        if os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        isatty = getattr(stream, "isatty", None)
        try:
            return bool(isatty and isatty())
        except (OSError, ValueError):
            # A closed or detached stream: it cannot be a terminal worth painting.
            return False

    @staticmethod
    def truecolor() -> bool:
        """Whether the terminal has said it renders 24-bit colour."""
        return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or bool(
            os.environ.get("WT_SESSION")
        )

    @staticmethod
    def unicode(stream: IO[str] | None) -> bool:
        """Whether `stream` can carry the block and box-drawing characters."""
        encoding = getattr(stream, "encoding", None) or "ascii"
        try:
            "█╭─╮│╰╯·".encode(encoding)
        except (LookupError, UnicodeEncodeError):
            return False
        return True


class Palette:
    """The console terminal's colours, by role, and the one place an escape sequence is written."""

    RESET = "\033[0m"
    ANSI = re.compile(r"\033\[[0-9;]*m")

    # Cordon Cloud's terminal palette (frontend `styles/console.css`, the --term-* tokens).
    BG = "#0b1110"
    CHROME = "#151d1b"
    ACCENT = "#35c3b1"
    CYAN = "#56d4c4"
    FG = "#d6e2de"
    BRIGHT = "#f2f7f5"
    DIM = "#6d827b"
    FAINT = "#4f625c"
    RED = "#ff6b7a"
    CRIT = "#ff4d5e"
    YELLOW = "#e8c468"
    GREEN = "#8bd49c"
    MAGENTA = "#c792ea"

    XTERM: ClassVar[dict[str, int]] = {
        BG: 233,
        CHROME: 234,
        ACCENT: 43,
        CYAN: 80,
        FG: 253,
        BRIGHT: 255,
        DIM: 66,
        FAINT: 240,
        RED: 204,
        CRIT: 203,
        YELLOW: 221,
        GREEN: 114,
        MAGENTA: 177,
    }
    """Each palette colour's 256-colour stand-in, chosen by eye. The arithmetically nearest entry
    turns the accent into a grey-teal (#5fafaf); 43 (#00d7af) keeps it the console's teal."""

    # role: (foreground, background, bold, underline)
    ROLES: ClassVar[dict[str, tuple[str | None, str | None, bool, bool]]] = {
        "badge": (BG, ACCENT, True, False),
        "chrome": (DIM, CHROME, False, False),
        "chrome-title": (FG, CHROME, False, False),
        "title": (BRIGHT, None, True, False),
        "text": (FG, None, False, False),
        "muted": (DIM, None, False, False),
        "faint": (FAINT, None, False, False),
        "heading": (ACCENT, None, True, False),
        "command": (CYAN, None, True, False),
        "flag": (CYAN, None, False, False),
        "value": (YELLOW, None, False, False),
        "prompt": (GREEN, None, True, False),
        "example": (BRIGHT, None, False, False),
        "code": (GREEN, None, False, False),
        "link": (CYAN, None, False, True),
        "error": (CRIT, None, True, False),
        "border": (FAINT, None, False, False),
        "exit-0": (BG, GREEN, True, False),
        "exit-1": (BRIGHT, CRIT, True, False),
        "exit-2": (BG, MAGENTA, True, False),
        "exit-3": (BG, YELLOW, True, False),
        "exit-4": (BRIGHT, DIM, True, False),
    }

    def __init__(self, enabled: bool, truecolor: bool = False) -> None:
        self.enabled = enabled
        self.truecolor = truecolor

    @staticmethod
    def rgb(hex_colour: str) -> tuple[int, int, int]:
        value = hex_colour.lstrip("#")
        return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)

    @staticmethod
    def xterm256(red: int, green: int, blue: int) -> int:
        """The nearest of the 256 standard colours: the 6x6x6 cube or the grey ramp."""
        levels = (0, 95, 135, 175, 215, 255)

        def nearest(value: int) -> int:
            return min(range(6), key=lambda i: abs(levels[i] - value))

        r, g, b = nearest(red), nearest(green), nearest(blue)
        cube = (levels[r], levels[g], levels[b])
        cube_index = 16 + 36 * r + 6 * g + b
        grey_step = max(0, min(23, round((red + green + blue) / 3 - 8) // 10))
        grey = 8 + 10 * grey_step

        def distance(colour: tuple[int, int, int]) -> int:
            return sum((a - c) ** 2 for a, c in zip(colour, (red, green, blue), strict=True))

        if distance((grey, grey, grey)) < distance(cube):
            return 232 + grey_step
        return cube_index

    @classmethod
    def index256(cls, hex_colour: str) -> int:
        """The 256-colour entry for `hex_colour`: the chosen stand-in, else the nearest."""
        return cls.XTERM.get(hex_colour) or cls.xterm256(*cls.rgb(hex_colour))

    def colour(self, hex_colour: str, background: bool = False) -> str:
        red, green, blue = self.rgb(hex_colour)
        layer = 48 if background else 38
        if self.truecolor:
            return f"\033[{layer};2;{red};{green};{blue}m"
        return f"\033[{layer};5;{self.index256(hex_colour)}m"

    def paint(self, role: str, text: str) -> str:
        if not self.enabled or not text:
            return text
        fg, bg, bold, underline = self.ROLES[role]
        codes = ("\033[1m" if bold else "") + ("\033[4m" if underline else "")
        if fg:
            codes += self.colour(fg)
        if bg:
            codes += self.colour(bg, background=True)
        return f"{codes}{text}{self.RESET}"

    def tint(self, hex_colour: str, text: str, bold: bool = False) -> str:
        if not self.enabled or not text:
            return text
        return f"{chr(27) + '[1m' if bold else ''}{self.colour(hex_colour)}{text}{self.RESET}"

    @classmethod
    def width(cls, text: str) -> int:
        """How many columns `text` takes on screen, escape sequences not counted."""
        return len(cls.ANSI.sub("", text))


class HelpPainter:
    """Colour for argparse's own help text, applied after argparse has laid it out."""

    # An option line: two to six spaces, then the invocation, ended by two spaces or the line.
    OPTION = re.compile(r"^( {2,6})(-[^\s].*?)(?=  |$)")
    # A subcommand in a `<command>` / `<action>` list: four spaces, a name, two spaces.
    CHOICE = re.compile(r"^( {4})([a-z][a-z0-9-]*)(?=  |$)")
    # A subcommand group's choices on a line of their own: `  {inventory,report}`.
    CHOICES = re.compile(r"^ {2}\{[a-z0-9,-]+\}$")
    FLAG = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")
    VALUE = re.compile(r"(\{[^}]*\}|<[^>]+>|\b[A-Z][A-Z_]+(?:\[:[A-Z]+\])?)")
    EXIT_CODE = re.compile(r"^(  )([0-4])(  )(\S.*?)(?=  |$)")
    LINK = re.compile(r"https?://\S+")
    CODE = re.compile(r"`[^`\n]+`")

    def __init__(self, palette: Palette) -> None:
        self.palette = palette

    def paint(self, text: str) -> str:
        if not self.palette.enabled:
            return text
        return "\n".join(self._line(line) for line in text.split("\n"))

    def _line(self, line: str) -> str:
        p = self.palette
        if line.startswith("usage:"):
            rest = line[len("usage:") :]
            head, _, tail = rest.partition(f" {PROGRAM}")
            if _:
                # The subcommand path after the program (`sbom generate`) reads as commands.
                path = re.match(r"((?: [a-z][a-z0-9-]*)*)(.*)$", tail, re.S)
                words, tail = (path.group(1), path.group(2)) if path else ("", tail)
                rest = f"{head} {p.paint('title', PROGRAM)}{p.paint('command', words)}{tail}"
            rest = self.FLAG.sub(lambda m: p.paint("flag", m.group(1)), rest)
            return p.paint("heading", "usage:") + rest
        if line and not line.startswith(" ") and line.endswith(":"):
            return p.paint("heading", line)
        match = self.EXIT_CODE.match(line)
        if match:
            code = match.group(2)
            # The chip takes the space either side of the digit, so the line keeps its width.
            return (
                f" {p.paint(f'exit-{code}', f' {code} ')} "
                f"{p.paint('title', match.group(4))}{p.paint('text', line[match.end() :])}"
            )
        match = self.OPTION.match(line)
        if match:
            invocation = self.VALUE.sub(lambda m: p.paint("value", m.group(1)), match.group(2))
            invocation = self.FLAG.sub(lambda m: p.paint("flag", m.group(1)), invocation)
            return match.group(1) + invocation + self._prose(line[match.end() :])
        if self.CHOICES.match(line):
            return p.paint("value", line)
        match = self.CHOICE.match(line)
        if match:
            return (
                match.group(1)
                + p.paint("command", match.group(2))
                + self._prose(line[match.end() :])
            )
        return self._prose(line)

    def _prose(self, text: str) -> str:
        p = self.palette
        text = self.LINK.sub(lambda m: p.paint("link", m.group(0)), text)
        return self.CODE.sub(lambda m: p.paint("code", m.group(0)), text)


class Wordmark:
    """CORDON in block letters, the cell pattern of the console's `IdleBanner`."""

    ROWS = (
        " ######  ######  ######  ######   ######  ###    ##",
        "##      ##    ## ##   ## ##   ## ##    ## ####   ##",
        "##      ##    ## ######  ##   ## ##    ## ## ##  ##",
        "##      ##    ## ##   ## ##   ## ##    ## ##  ## ##",
        " ######  ######  ##   ## ######   ######  ##   ####",
    )
    START = "#2fb3a2"
    END = "#86e6d6"
    SOLID = Palette.ACCENT
    """Without 24-bit colour the gradient rounds to unrelated shades of the 256, so the letters
    are drawn in the console's accent alone."""

    @classmethod
    def lines(cls, palette: Palette, block: str) -> list[str]:
        """Each row drawn in `block`, shaded left to right from the accent to a lighter teal."""
        span = max(len(row) for row in cls.ROWS) - 1
        start, end = Palette.rgb(cls.START), Palette.rgb(cls.END)
        out = []
        for row in cls.ROWS:
            cells = []
            for x, cell in enumerate(row):
                if cell != "#":
                    cells.append(" ")
                    continue
                if not palette.enabled:
                    cells.append(block)
                    continue
                if not palette.truecolor:
                    cells.append(palette.colour(cls.SOLID) + block)
                    continue
                t = x / span
                shade = "#{:02x}{:02x}{:02x}".format(
                    *(round(a + (b - a) * t) for a, b in zip(start, end, strict=True))
                )
                cells.append(palette.colour(shade) + block)
            line = "".join(cells)
            out.append(line + palette.RESET if palette.enabled else line)
        return out

    @classmethod
    def width(cls) -> int:
        return max(len(row) for row in cls.ROWS)


class HelpScreen:
    """The screen `cordon-scanner` and `cordon-scanner --help` print."""

    TAGLINE = "Language-agnostic software supply-chain security scanner."

    GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("SCAN AND INSPECT", ("scan", "inventory", "deps", "sbom", "report")),
        ("POLICY", ("rules", "config", "baseline", "suppress", "guard")),
        ("THREAT INTEL", ("advisories", "intel", "bundle")),
        ("CORDON CLOUD", ("login", "logout", "whoami", "runner", "agent")),
        ("SHELL", ("completion",)),
    )
    """Every command, once, under what it is for. A test fails if a command is added to the
    parser and not to a group here, so none can silently drop off the screen."""

    EXAMPLES: tuple[tuple[str, str], ...] = (
        ("scan .", "scan this repository"),
        ("scan . --fail-on high", "fail the build at high or above"),
        ("scan . -f sarif:cordon.sarif", "also write SARIF for code scanning"),
        ("deps . --online", "the dependency graph, checked online"),
        ("sbom generate -o sbom.json", "write a CycloneDX bill of materials"),
        ("guard install", "install fail-closed git hooks"),
    )

    EXIT_CODES: tuple[tuple[int, str, str], ...] = (
        (0, "clean", "the scan completed and nothing met the failure policy"),
        (1, "findings", "the scan completed and something met the failure policy"),
        (2, "scanner error", "cordon-scanner itself failed"),
        (3, "config error", "invalid configuration, policy, or a forbidden override"),
        (4, "incomplete", "the scan was degraded and --fail-on-incomplete was set"),
    )

    NOTE = (
        f"A plain `if {PROGRAM} scan .` is correct with no flags, and any non-zero code fails "
        'safe. A pipeline that cannot tell "the scanner broke" from "your code is bad" gets '
        "configured to ignore both."
    )

    TUTORIALS = f"https://github.com/Threx-code/cordon/tree/v{__version__}/tutorials"

    INDENT = "  "

    def __init__(
        self,
        commands: dict[str, str],
        palette: Palette,
        width: int | None = None,
        rich: bool | None = None,
        unicode: bool = True,
    ) -> None:
        self.commands = commands
        self.palette = palette
        columns = width if width is not None else shutil.get_terminal_size((100, 24)).columns
        self.width = max(64, min(columns, 100))
        self.rich = palette.enabled if rich is None else rich
        self.unicode = unicode
        self.box = tuple("╭─╮│╰╯" if unicode else "+-+|++")
        self.block = "█" if unicode else "#"
        self.dot = "·" if unicode else "-"

    @classmethod
    def unlisted(cls, names: Iterable[str]) -> list[str]:
        """Commands the parser has that no group lists."""
        grouped = {name for _, members in cls.GROUPS for name in members}
        return sorted(set(names) - grouped)

    def _groups(self) -> list[tuple[str, list[str]]]:
        listed = {name for _, members in self.GROUPS for name in members}
        groups = [
            (title, [n for n in members if n in self.commands]) for title, members in self.GROUPS
        ]
        extra = [name for name in self.commands if name not in listed]
        if extra:
            groups.append(("OTHER", extra))
        return [(title, members) for title, members in groups if members]

    def render(self) -> str:
        return self._rich() if self.rich else self._plain()

    # -- the terminal screen ---------------------------------------------------------------------

    def _rich(self) -> str:
        p = self.palette
        out: list[str] = [""]
        for line in Wordmark.lines(p, self.block):
            out.append(self._centre(line))
        out.append("")
        out.append(self._centre(p.paint("heading", " ".join("SCANNER"))))
        out.append(self._centre(p.paint("muted", self.TAGLINE)))
        facts = f"{PROGRAM} {__version__}  {self.dot}  rulepack {RULEPACK_VERSION}"
        if len(facts) + len(f"  {self.dot}  executes nothing it scans") <= self.width:
            facts += f"  {self.dot}  executes nothing it scans"
        out.append(self._centre(p.paint("faint", facts)))
        out.append("")
        room = self._inner() - 2
        usage = [
            f"{p.paint('prompt', '$')} {p.paint('title', PROGRAM)} {p.paint('value', '<command>')} "
            f"{p.paint('muted', '[options]')}"
        ]
        help_line = f"$ {PROGRAM} <command> --help   "
        usage += self._columns(
            f"{p.paint('prompt', '$')} {p.paint('title', PROGRAM)} {p.paint('value', '<command>')} "
            f"{p.paint('flag', '--help')}   ",
            len(help_line),
            "every option of one command",
            "muted",
            room,
        )
        out += self._panel("USAGE", usage)
        name_width = max(len(name) for name in self.commands) + 3
        for title, members in self._groups():
            rows: list[str] = []
            for name in members:
                rows += self._entry(name, self.commands[name], name_width, self._inner() - 2)
            out += self._panel(title, rows)
        examples: list[str] = []
        command_width = max(len(c) for c, _ in self.EXAMPLES) + len(PROGRAM) + 3
        for command, meaning in self.EXAMPLES:
            line = f"{PROGRAM} {command}"
            left = f"{p.paint('prompt', '$')} {p.paint('example', line)}{' ' * (command_width - len(line))}"
            examples += self._columns(left, 2 + command_width, meaning, "muted", room)
        out += self._panel("QUICK START", examples)
        codes: list[str] = []
        for code, name, meaning in self.EXIT_CODES:
            left = f"{p.paint(f'exit-{code}', f' {code} ')} {p.paint('title', f'{name:<14}')}"
            codes += self._columns(left, 4 + 14, meaning, "text", room)
        codes.append("")
        codes += [p.paint("muted", line) for line in textwrap.wrap(self.NOTE, room)]
        out += self._panel("EXIT CODES", codes)
        title = f"TUTORIALS FOR {__version__}"
        if len(self.TUTORIALS) <= room:
            out += self._panel(title, [p.paint("link", self.TUTORIALS)])
        else:
            # A link split across lines stops being one, so a narrow screen prints it unboxed.
            out += [
                f"{self.INDENT}{p.paint('heading', title)}",
                f"{self.INDENT}{p.paint('link', self.TUTORIALS)}",
                "",
            ]
        out.append(self._status_bar())
        out.append("")
        return "\n".join(out)

    def _inner(self) -> int:
        """Columns inside a panel's borders."""
        return self.width - len(self.INDENT) * 2 - 2

    def _centre(self, text: str) -> str:
        room = self.width - Palette.width(text)
        return " " * max(room // 2, 0) + text

    def _panel(self, title: str, rows: list[str]) -> list[str]:
        p = self.palette
        tl, h, tr, v, bl, br = self.box
        inner = self._inner()
        label = f" {title} "
        top = (
            p.paint("border", f"{tl}{h}")
            + p.paint("heading", label)
            + p.paint("border", h * max(inner - len(label) - 1, 0) + tr)
        )
        lines = [self.INDENT + top]
        for row in rows:
            pad = max(inner - 2 - Palette.width(row), 0)
            lines.append(
                f"{self.INDENT}{p.paint('border', v)}  {row}{' ' * pad}{p.paint('border', v)}"
            )
        lines.append(self.INDENT + p.paint("border", bl + h * inner + br))
        return lines

    def _status_bar(self) -> str:
        """The console terminal's bottom bar: the mode, the screen, and the facts that matter."""
        p = self.palette
        bar = self.width - len(self.INDENT) * 2
        left = p.paint("badge", " cordon ") + p.paint("chrome-title", " help ")
        segments = [f"v{__version__}", f"rulepack {RULEPACK_VERSION}", "executed 0"]
        sep = "│" if self.unicode else "|"
        right = "".join(p.paint("chrome", f" {sep} {segment}") for segment in segments)
        right += p.paint("chrome", " ")
        fill = max(bar - Palette.width(left) - Palette.width(right), 0)
        return self.INDENT + left + p.paint("chrome", " " * fill) + right

    def _columns(self, left: str, left_width: int, right: str, role: str, room: int) -> list[str]:
        """`left`, then `right` wrapped under its own column; on its own lines when too narrow."""
        p = self.palette
        space = room - left_width
        if space >= 20:
            wrapped = textwrap.wrap(right, space) or [""]
            return [left + p.paint(role, wrapped[0])] + [
                " " * left_width + p.paint(role, line) for line in wrapped[1:]
            ]
        return [left.rstrip()] + [
            "    " + p.paint(role, line) for line in textwrap.wrap(right, room - 4)
        ]

    def _entry(self, name: str, help_text: str, name_width: int, room: int) -> list[str]:
        p = self.palette
        lines = textwrap.wrap(help_text, max(room - name_width, 20)) or [""]
        first = (
            f"{p.paint('command', name)}{' ' * (name_width - len(name))}{p.paint('text', lines[0])}"
        )
        return [first] + [f"{' ' * name_width}{p.paint('text', line)}" for line in lines[1:]]

    # -- the plain screen ------------------------------------------------------------------------

    def _plain(self) -> str:
        out = [f"{PROGRAM} {__version__}", self.TAGLINE, "", "usage:"]
        out.append(f"{self.INDENT}{PROGRAM} <command> [options]")
        out.append(f"{self.INDENT}{PROGRAM} <command> --help   every option of one command")
        out.append("")
        name_width = max(len(name) for name in self.commands) + 3
        room = self.width - len(self.INDENT)
        for title, members in self._groups():
            out.append(f"{title.lower()}:")
            for name in members:
                out += [
                    self.INDENT + line
                    for line in self._entry(name, self.commands[name], name_width, room)
                ]
            out.append("")
        out.append("quick start:")
        command_width = max(len(c) for c, _ in self.EXAMPLES) + len(PROGRAM) + 3
        for command, meaning in self.EXAMPLES:
            line = f"{PROGRAM} {command}"
            out.append(f"{self.INDENT}{line}{' ' * (command_width - len(line))}{meaning}")
        out.append("")
        out.append("exit codes:")
        for code, name, meaning in self.EXIT_CODES:
            out.append(f"{self.INDENT}{code}  {name:<14}{meaning}")
        out.append("")
        out += [
            self.INDENT + line for line in textwrap.wrap(self.NOTE, self.width - len(self.INDENT))
        ]
        out.append("")
        out.append(f"tutorials for this version ({__version__}):")
        out.append(f"{self.INDENT}{self.TUTORIALS}")
        out.append("")
        return "\n".join(out)


class ColourArgumentParser(argparse.ArgumentParser):
    """An ArgumentParser whose help and errors are drawn on a terminal and plain elsewhere.

    Subparsers made by `add_subparsers` take their parent's class, so one root built from this
    gives every subcommand the same treatment.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)

    def subcommands(self) -> dict[str, str]:
        """This parser's subcommands and their one-line help, in the order they were added."""
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                return {choice.dest: choice.help or "" for choice in action._choices_actions}
        return {}

    def subparser(self, name: str) -> ColourArgumentParser | None:
        """The parser behind subcommand `name`, if this parser has one."""
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                found = action.choices.get(name)
                return found if isinstance(found, ColourArgumentParser) else None
        return None

    def is_root(self) -> bool:
        return self.prog == PROGRAM

    def render_help(self, stream: IO[str] | None) -> str:
        palette = Palette(HelpColour.enabled(stream), HelpColour.truecolor())
        if self.is_root():
            return HelpScreen(
                self.subcommands(), palette, unicode=HelpColour.unicode(stream)
            ).render()
        return HelpPainter(palette).paint(super().format_help())

    def format_help(self) -> str:
        return self.render_help(None)

    def print_help(self, file: Any = None) -> None:
        stream = file if file is not None else sys.stdout
        self._print_message(self.render_help(stream), stream)

    def error(self, message: str) -> NoReturn:
        palette = Palette(HelpColour.enabled(sys.stderr), HelpColour.truecolor())
        usage = HelpPainter(palette).paint(self.format_usage().rstrip("\n"))
        self._print_message(f"{usage}\n", sys.stderr)
        self.exit(2, f"{palette.paint('error', f'{self.prog}: error:')} {message}\n")


class GroupHelp:
    """A command group run with no action shows its own help instead of failing obscurely."""

    NEEDS_ACTION: ClassVar[dict[str, str]] = {
        "config": "config_command",
        "report": "report_command",
        "baseline": "baseline_command",
        "bundle": "bundle_command",
        "advisories": "advisories_command",
        "agent": "agent_command",
        "intel": "intel_command",
        "sbom": "sbom_command",
    }
    """Groups with no sensible default action. Before this, a bare `config`, `report` or
    `baseline` died with an AttributeError reported as a bug in cordon. `rules` (lists the
    rules) and `guard` (verifies the guard) keep their defaults."""

    @classmethod
    def missing(cls, args: argparse.Namespace) -> str | None:
        """The group `args` names without an action, or None."""
        dest = cls.NEEDS_ACTION.get(getattr(args, "command", None) or "")
        if dest is None or getattr(args, dest, None):
            return None
        return str(args.command)

    @classmethod
    def show(cls, parser: ColourArgumentParser, group: str, stream: IO[str]) -> None:
        sub = parser.subparser(group)
        if sub is not None:
            sub.print_help(stream)
            print(file=stream)
        palette = Palette(HelpColour.enabled(stream), HelpColour.truecolor())
        print(
            f"{palette.paint('error', f'{PROGRAM} {group}:')} choose an action from the list above",
            file=stream,
        )


__all__ = [
    "ColourArgumentParser",
    "GroupHelp",
    "HelpColour",
    "HelpPainter",
    "HelpScreen",
    "Palette",
    "Wordmark",
]
