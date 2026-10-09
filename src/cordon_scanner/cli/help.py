"""The help screens: the home screen, each command's options, and the errors argparse raises.

`cordon-scanner` (and `cordon-scanner help`) opens with CORDON in block letters, the cell
pattern of Cordon Cloud's idle terminal, and then answers the question a person running a
security tool has first: what state is this machine and this repository in? The ENVIRONMENT
block reports the rulepack, how old the threat intel is, which policy file applies here and how
many suppressions it carries, whether the git hooks run cordon, the Cloud sign-in, and the mode.
Every value is read locally at that moment; nothing is fetched and nothing is assumed. The
commands follow in two columns, grouped by what they are for.

Every subcommand's `--help` keeps argparse's layout and gains colour for its headings, flags and
values; argparse's errors are coloured the same way.

Colour is the console's terminal palette, exact in 24-bit colour and chosen 256-colour stand-ins
elsewhere, and it follows the rules the scan report follows (`CommandLine._use_color`):
`NO_COLOR` turns it off, `FORCE_COLOR` turns it on, and otherwise it is on only when the stream
is a terminal. A piped or captured screen carries no escape sequence and no block letters.

Colour is applied to argparse's finished text, never inside it. argparse pads its columns by
`len()`, and an escape sequence counted as width would push every description out of line.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, ClassVar, NoReturn

from cordon_scanner.version import PROGRAM, RULEPACK_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


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
        """Whether `stream` can carry the block letters and rules."""
        encoding = getattr(stream, "encoding", None) or "ascii"
        try:
            "█─·".encode(encoding)
        except (LookupError, UnicodeEncodeError):
            return False
        return True


class Palette:
    """The console terminal's colours, by role, and the one place an escape sequence is written."""

    RESET = "\033[0m"
    ANSI = re.compile(r"\033\[[0-9;]*m")

    # Cordon Cloud's terminal palette (frontend `styles/console.css`, the --term-* tokens).
    BG = "#0b1110"
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
        "title": (BRIGHT, None, True, False),
        "text": (FG, None, False, False),
        "muted": (DIM, None, False, False),
        "faint": (FAINT, None, False, False),
        "heading": (ACCENT, None, True, False),
        "command": (CYAN, None, True, False),
        "flag": (CYAN, None, False, False),
        "value": (YELLOW, None, False, False),
        "code": (GREEN, None, False, False),
        "link": (CYAN, None, False, True),
        "error": (CRIT, None, True, False),
        "ok": (GREEN, None, False, False),
        "warn": (YELLOW, None, False, False),
        "bad": (RED, None, True, False),
        "off": (DIM, None, False, False),
        "exit-0": (GREEN, None, True, False),
        "exit-1": (CRIT, None, True, False),
        "exit-2": (MAGENTA, None, True, False),
        "exit-3": (YELLOW, None, True, False),
        "exit-4": (DIM, None, True, False),
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
        grey_step = max(0, min(23, round((red + green + blue) / 3 - 8) // 10))
        grey = 8 + 10 * grey_step

        def distance(colour: tuple[int, int, int]) -> int:
            return sum((a - c) ** 2 for a, c in zip(colour, (red, green, blue), strict=True))

        if distance((grey, grey, grey)) < distance(cube):
            return 232 + grey_step
        return 16 + 36 * r + 6 * g + b

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
            head, found, tail = rest.partition(f" {PROGRAM}")
            if found:
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
            return (
                f"{match.group(1)}{p.paint(f'exit-{code}', code)}{match.group(3)}"
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
        span = cls.width() - 1
        start, end = Palette.rgb(cls.START), Palette.rgb(cls.END)
        out = []
        for row in cls.ROWS:
            cells = []
            for x, cell in enumerate(row):
                if cell != "#":
                    cells.append(" ")
                elif not palette.enabled:
                    cells.append(block)
                elif not palette.truecolor:
                    cells.append(palette.colour(cls.SOLID) + block)
                else:
                    t = x / span
                    shade = "#{:02x}{:02x}{:02x}".format(
                        *(round(a + (b - a) * t) for a, b in zip(start, end, strict=True))
                    )
                    cells.append(palette.colour(shade) + block)
            line = "".join(cells).rstrip()
            out.append(line + palette.RESET if palette.enabled else line)
        return out

    @classmethod
    def width(cls) -> int:
        return max(len(row) for row in cls.ROWS)


@dataclass(frozen=True)
class Fact:
    """One line of the ENVIRONMENT block: what, its value, and how it should read."""

    label: str
    value: str
    state: str = "text"
    """`text`, `ok`, `warn`, `bad` or `off`: the palette role the value is drawn in."""


class Environment:
    """What the home screen reports about this machine and this directory, read locally.

    Each fact is read independently and none may stop the screen: a probe that fails reports
    `unavailable` instead of raising, and none touches the network.
    """

    HOOKS = ("pre-commit", "pre-push")

    def __init__(self, cwd: Path | None = None) -> None:
        self.cwd = (cwd or Path.cwd()).resolve()

    def facts(self) -> list[Fact]:
        probes = (
            ("Rulepack", self._rulepack),
            ("Policy", self._policy),
            ("Intel", self._intel),
            ("Hooks", self._hooks),
            ("Cloud", self._cloud),
            ("Mode", self._mode),
        )
        out = []
        for label, probe in probes:
            try:
                value, state = probe()
            except Exception:
                value, state = "unavailable", "warn"
            out.append(Fact(label, value, state))
        return out

    @staticmethod
    def _rulepack() -> tuple[str, str]:
        return RULEPACK_VERSION, "text"

    @staticmethod
    def age(seconds: int) -> str:
        if seconds < 3600:
            return "under an hour old"
        if seconds < 86400:
            return f"{seconds // 3600}h old"
        return f"{seconds // 86400}d old"

    @classmethod
    def _intel(cls) -> tuple[str, str]:
        from cordon_scanner.intel import feed

        status = feed.FeedClient.status(use_feed=False, max_age=None)
        source = "bundled" if status.source == "package" else status.source
        age = cls.age(status.age_seconds) if status.age_seconds is not None else "age unknown"
        if status.stale:
            return f"{source} · {age} · stale", "warn"
        return f"{source} · {age}", "ok"

    def _policy(self) -> tuple[str, str]:
        from cordon_scanner.core.config import CONFIG_FILENAMES, Config
        from cordon_scanner.core.errors import CordonError

        name = next((n for n in CONFIG_FILENAMES if (self.cwd / n).is_file()), None)
        if name is None:
            return "no config here · defaults apply", "off"
        try:
            config = Config.discover(self.cwd)
        except CordonError:
            return f"{name} is invalid · run `config validate`", "bad"
        count = len(config.suppressions)
        return f"{name} · {count} suppression{'' if count == 1 else 's'}", "ok"

    def _repository(self) -> Path | None:
        for candidate in (self.cwd, *self.cwd.parents):
            if (candidate / ".git").exists():
                return candidate
        return None

    def _hooks_dir(self, repository: Path) -> Path:
        """`core.hooksPath` when the repository sets it, else `.git/hooks`."""
        git = repository / ".git"
        if git.is_file():
            # A worktree or submodule: `.git` names the real git directory.
            pointer = git.read_text(encoding="utf-8", errors="replace").strip()
            if pointer.startswith("gitdir:"):
                git = (repository / pointer.split(":", 1)[1].strip()).resolve()
        config = git / "config"
        if config.is_file():
            section = ""
            for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if line.startswith("["):
                    section = line.lower()
                elif section == "[core]" and line.lower().replace(" ", "").startswith("hookspath="):
                    configured = Path(line.split("=", 1)[1].strip().strip('"')).expanduser()
                    return configured if configured.is_absolute() else repository / configured
        return git / "hooks"

    @staticmethod
    def _runs_cordon(text: str) -> bool:
        from cordon_scanner.core.guard import SHIM_MARKER

        return SHIM_MARKER in text or "cordon-scanner" in text or "cordon-scan" in text

    def _delegate(self, repository: Path, hook: str, text: str) -> Path | None:
        """The tracked hook a shim hands over to, when the shim names one inside the repository.

        Hook managers install a small shim in `.git/hooks` that `exec`s the reviewable hook in
        the tree (`.githooks/pre-push`, `.husky/pre-push`). Only a path the shim itself names is
        followed, and only one level, so a shim cannot be credited with a hook it never runs.
        """
        for match in re.finditer(rf"([\w.-]+(?:/[\w.-]+)*/{re.escape(hook)})\b", text):
            parts = match.group(1).split("/")
            # `$root/.githooks/pre-push` reads as `root/.githooks/pre-push`: drop leading parts
            # until what is left names a file in the repository.
            for start in range(len(parts) - 1):
                candidate = (repository / "/".join(parts[start:])).resolve()
                if candidate.is_relative_to(repository) and candidate.is_file():
                    return candidate
        return None

    def _hooks(self) -> tuple[str, str]:
        """Which hooks git will run here, and which of them can be shown to run cordon.

        Installed means present and executable, because git skips a hook it cannot execute.
        "Runs cordon" is claimed only when the hook, or the tracked hook its shim hands over to,
        says so. A hook that reaches cordon deeper down (a script that runs a script) is
        reported as installed, not credited: telling `ci-local.sh` from `ci-local.sh format`
        needs the arguments understood, and an under-claim is the honest failure here.
        """
        repository = self._repository()
        if repository is None:
            return "not a git repository", "off"
        hooks = self._hooks_dir(repository)
        running: list[str] = []
        installed: list[str] = []
        for hook in self.HOOKS:
            path = hooks / hook
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")[:65536]
            if not self._runs_cordon(text):
                tracked = self._delegate(repository, hook, text)
                if tracked is not None:
                    text = tracked.read_text(encoding="utf-8", errors="replace")[:262144]
            (running if self._runs_cordon(text) else installed).append(hook)
        parts = []
        if running:
            parts.append(f"{', '.join(running)} run{'s' if len(running) == 1 else ''} cordon")
        if installed:
            parts.append(f"{', '.join(installed)} installed")
        if parts:
            return " · ".join(parts), "ok" if running else "text"
        return "not installed (see guard install)", "warn"

    @staticmethod
    def _cloud() -> tuple[str, str]:
        from cordon_scanner.cloud import auth

        stored = auth.CloudAuth.load()
        if stored is None:
            return "not signed in", "off"
        return f"signed in · {stored.org or stored.url}", "ok"

    @staticmethod
    def _mode() -> tuple[str, str]:
        # What a default scan does on the network: since 0.6.0 it asks OSV what changed since
        # the bundled intel was built, unless told not to. "Offline by default" stopped being true.
        if os.environ.get("CORDON_OFFLINE"):
            return "offline (CORDON_OFFLINE) · executes nothing", "text"
        if os.environ.get("CORDON_NO_ADVISORY_REFRESH"):
            return "no advisory refresh · executes nothing", "text"
        return "reads only · asks OSV what changed · executes nothing", "text"


class HelpScreen:
    """The screen `cordon-scanner` and `cordon-scanner help` print."""

    TAGLINE = "Software supply-chain security scanner"

    GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "SCAN AND INSPECT",
            ("scan", "clone", "pull", "inventory", "deps", "review", "sbom", "report"),
        ),
        ("POLICY", ("rules", "config", "baseline", "suppress", "guard")),
        ("THREAT INTEL", ("advisories", "intel", "bundle")),
        ("CORDON CLOUD", ("login", "logout", "whoami", "runner", "agent")),
        ("GENERAL", ("help", "completion")),
    )
    """Every command, once, under what it is for. A test fails if a command is added to the
    parser and not to a group here, so none can silently drop off the screen."""

    SHORT: ClassVar[dict[str, str]] = {
        "scan": "scan a directory, file or archive",
        "inventory": "what the repository is, and why",
        "deps": "dependency graph and findings",
        "review": "what a dependency update adds",
        "clone": "clone, scanned before checkout",
        "pull": "pull, scanned before the merge",
        "sbom": "CycloneDX or SPDX bill of materials",
        "report": "re-render a saved JSON result",
        "rules": "list, test and show the rules",
        "config": "check the repository configuration",
        "baseline": "record findings, adopt gradually",
        "suppress": "reviewed, expiring exceptions",
        "guard": "git hooks and self-integrity",
        "advisories": "the advisory database",
        "intel": "the signed threat-intel feed",
        "bundle": "offline bundle for air-gapped use",
        "login": "sign in to Cordon Cloud (SSO)",
        "logout": "end the Cordon Cloud sign-in",
        "whoami": "the Cordon Cloud sign-in in use",
        "runner": "run Cloud jobs in your network",
        "agent": "AI agents and MCP servers, for MDM",
        "help": "this screen, or one command's help",
        "completion": "shell completion script",
    }
    """The two-column screen's descriptions, short enough for half a terminal. The full help
    line from the parser is used for anything not here and on a narrow screen."""

    EXIT_CODES: tuple[tuple[int, str], ...] = (
        (0, "clean"),
        (1, "findings"),
        (2, "scanner error"),
        (3, "config error"),
        (4, "incomplete"),
    )

    TUTORIALS = f"https://github.com/Threx-code/cordon/tree/v{__version__}/tutorials"

    INDENT = "  "
    GAP = 4
    TWO_COLUMNS_FROM = 88
    LABEL_WIDTH = 10

    def __init__(
        self,
        commands: dict[str, str],
        palette: Palette,
        width: int | None = None,
        rich: bool | None = None,
        unicode: bool = True,
        environment: Sequence[Fact] | None = None,
    ) -> None:
        self.commands = commands
        self.palette = palette
        columns = width if width is not None else shutil.get_terminal_size((100, 24)).columns
        self.width = max(64, min(columns, 100))
        self.rich = palette.enabled if rich is None else rich
        self.unicode = unicode
        self.environment = list(environment) if environment is not None else Environment().facts()
        self.block = "█" if unicode else "#"
        self.rule = "─" if unicode else "-"
        self.dot = "·" if unicode else "-"

    @classmethod
    def unlisted(cls, names: Iterable[str]) -> list[str]:
        """Commands the parser has that no group lists."""
        grouped = {name for _, members in cls.GROUPS for name in members}
        return sorted(set(names) - grouped)

    def two_columns(self) -> bool:
        return self.width >= self.TWO_COLUMNS_FROM

    def column_width(self) -> int:
        return (self.width - len(self.INDENT) - self.GAP) // 2

    def render(self) -> str:
        out: list[str] = [""]
        out += self._header()
        out.append("")
        out += self._section("ENVIRONMENT", self._facts())
        out.append("")
        out += self._commands()
        out += self._footer()
        out.append("")
        text = "\n".join(out)
        return text if self.unicode else text.replace("·", "-")

    # -- the header ------------------------------------------------------------------------------

    def _header(self) -> list[str]:
        p = self.palette
        version = f"v{__version__}"
        if self.rich:
            lines = [self.INDENT + line for line in Wordmark.lines(p, self.block)]
            tagline = self.TAGLINE
        else:
            lines = []
            tagline = f"CORDON  {self.TAGLINE}"
        room = Wordmark.width() if self.rich else self.width - len(self.INDENT)
        pad = max(room - len(tagline) - len(version), 2)
        lines.append(
            f"{self.INDENT}{p.paint('muted', tagline)}{' ' * pad}{p.paint('title', version)}"
        )
        return lines

    # -- the environment -------------------------------------------------------------------------

    def _fact(self, fact: Fact, width: int) -> str:
        p = self.palette
        room = width - self.LABEL_WIDTH
        value = fact.value if len(fact.value) <= room else fact.value[: room - 1] + "…"
        label = f"{fact.label:<{self.LABEL_WIDTH}}"
        return p.paint("muted", label) + p.paint(fact.state, value)

    def _facts(self) -> list[str]:
        facts = self.environment
        if not self.two_columns():
            return [self._fact(f, self.width - len(self.INDENT)) for f in facts]
        width = self.column_width()
        # A value too long for half the screen gets a full row after the grid, not an ellipsis:
        # a fact cut short is a fact the reader cannot use.
        short = [f for f in facts if len(f.value) <= width - self.LABEL_WIDTH]
        long = [f for f in facts if f not in short]
        half = (len(short) + 1) // 2
        left, right = short[:half], short[half:]
        rows = []
        for i, fact in enumerate(left):
            cell = self._fact(fact, width)
            line = cell + " " * (width - Palette.width(cell) + self.GAP)
            if i < len(right):
                line += self._fact(right[i], width)
            rows.append(line.rstrip())
        rows += [self._fact(f, self.width - len(self.INDENT)) for f in long]
        return rows

    # -- the commands ----------------------------------------------------------------------------

    def _groups(self) -> list[tuple[str, list[str]]]:
        listed = {name for _, members in self.GROUPS for name in members}
        groups = [(t, [n for n in members if n in self.commands]) for t, members in self.GROUPS]
        extra = [name for name in self.commands if name not in listed]
        if extra:
            groups.append(("OTHER", extra))
        return [(title, members) for title, members in groups if members]

    def _heading(self, title: str, width: int) -> str:
        p = self.palette
        return (
            p.paint("heading", title)
            + " "
            + p.paint("faint", self.rule * max(width - len(title) - 1, 0))
        )

    def _block(self, title: str, members: list[str], width: int, short: bool) -> list[str]:
        p = self.palette
        name_width = max(len(n) for _, ms in self._groups() for n in ms) + 2
        room = width - name_width
        lines = [self._heading(title, width)]
        for name in members:
            text = self.SHORT.get(name, self.commands[name]) if short else self.commands[name]
            if len(text) > room:
                text = text[: room - 1] + "…"
            lines.append(p.paint("command", f"{name:<{name_width}}") + p.paint("text", text))
        return lines

    def _commands(self) -> list[str]:
        groups = self._groups()
        out: list[str] = []
        if not self.two_columns():
            width = self.width - len(self.INDENT)
            for title, members in groups:
                out += [self.INDENT + line for line in self._block(title, members, width, False)]
                out.append("")
            return out
        width = self.column_width()
        for i in range(0, len(groups), 2):
            left = self._block(*groups[i], width, True)
            right = self._block(*groups[i + 1], width, True) if i + 1 < len(groups) else []
            for row in range(max(len(left), len(right))):
                cell = left[row] if row < len(left) else ""
                line = cell + " " * (width - Palette.width(cell) + self.GAP)
                if row < len(right):
                    line += right[row]
                out.append((self.INDENT + line).rstrip())
            out.append("")
        return out

    # -- the footer ------------------------------------------------------------------------------

    def _footer(self) -> list[str]:
        p = self.palette
        codes = [
            f"{p.paint(f'exit-{code}', str(code))} {p.paint('text', name)}"
            for code, name in self.EXIT_CODES
        ]
        rows: list[tuple[str, list[str]]] = [
            ("Usage", [f"{p.paint('title', PROGRAM)} {p.paint('value', '<command>')} [flags]"]),
            ("Get started", [p.paint("code", f"{PROGRAM} scan .")]),
            ("Command help", [p.paint("code", f"{PROGRAM} help <command>")]),
            ("Docs", [p.paint("link", self.TUTORIALS)]),
            ("Exit codes", codes),
        ]
        label_width = max(len(label) for label, _ in rows) + 2
        room = self.width - len(self.INDENT) - label_width
        separator = f"  {p.paint('faint', self.dot)}  "
        out = [self._section_heading("NEXT")]
        for label, items in rows:
            lines = self._flow(items, separator, room)
            if len(lines) == 1 and Palette.width(lines[0]) > room:
                # A link split across lines stops being one: it takes a line of its own.
                out.append(f"{self.INDENT}{p.paint('muted', label)}")
                out.append(f"{self.INDENT}{lines[0]}")
                continue
            for n, line in enumerate(lines):
                head = p.paint("muted", f"{label:<{label_width}}") if n == 0 else " " * label_width
                out.append(f"{self.INDENT}{head}{line}")
        return out

    @staticmethod
    def _flow(items: list[str], separator: str, room: int) -> list[str]:
        """`items` joined by `separator`, wrapped to `room` columns between items, never inside."""
        lines: list[str] = []
        current = ""
        for item in items:
            joined = f"{current}{separator}{item}" if current else item
            if current and Palette.width(joined) > room:
                lines.append(current)
                current = item
            else:
                current = joined
        lines.append(current)
        return lines

    def _section_heading(self, title: str) -> str:
        return self.INDENT + self._heading(title, self.width - len(self.INDENT))

    def _section(self, title: str, rows: list[str]) -> list[str]:
        return [self._section_heading(title)] + [self.INDENT + row for row in rows]


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


class HelpCommand:
    """`cordon-scanner help [COMMAND...]`: the home screen, or one command's help."""

    @staticmethod
    def run(args: argparse.Namespace, *, parser: ColourArgumentParser) -> int:
        from cordon_scanner.core.errors import ExitCode

        topic: list[str] = list(getattr(args, "topic", None) or [])
        current = parser
        for depth, word in enumerate(topic):
            found = current.subparser(word)
            if found is None:
                choices = list(current.subcommands())
                palette = Palette(HelpColour.enabled(sys.stderr), HelpColour.truecolor())
                where = " ".join([PROGRAM, *topic[:depth]])
                print(
                    f"{palette.paint('error', f'{PROGRAM} help:')} {where} has no command {word!r}",
                    file=sys.stderr,
                )
                close = difflib.get_close_matches(word, choices, n=1)
                if close:
                    suggestion = " ".join([PROGRAM, "help", *topic[:depth], close[0]])
                    print(f"  did you mean: {palette.paint('code', suggestion)}", file=sys.stderr)
                elif choices:
                    print(f"  choose from: {', '.join(choices)}", file=sys.stderr)
                return int(ExitCode.CONFIG_ERROR)
            current = found
        current.print_help()
        return int(ExitCode.CLEAN)


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
    "Environment",
    "Fact",
    "GroupHelp",
    "HelpColour",
    "HelpCommand",
    "HelpPainter",
    "HelpScreen",
    "Palette",
    "Wordmark",
]
