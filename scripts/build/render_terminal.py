"""The README's terminal: real cordon-scanner sessions, replayed as an animated SVG.

    python scripts/build/render_terminal.py            # docs/assets/terminal.svg

Each session is a recording `scripts/build/record_terminal.sh` made of the scanner itself, run in a
pseudo-terminal: what it wrote (`docs/assets/terminal/<name>.typescript`) and when
(`<name>.timing`, util-linux `script -T`). Nothing here is written by hand except the typing of
each command, which a recording cannot hold: its output is replayed through a small terminal
(carriage returns, erase-line, colour), at its own pace with long waits shortened, and drawn on a
character grid so the severity badges line up in whatever monospace font the viewer has.

An SVG plays its CSS animations inside an <img>, which is all a README allows, and it is text: a
change to the image is a change to a recording, readable in a diff. Deterministic: the same
recordings render the same bytes.
"""

from __future__ import annotations

import codecs
import html
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

ROOT = next(
    (p for p in (Path.cwd(), *Path.cwd().parents) if (p / "src" / "cordon_scanner").is_dir()), None
) or sys.exit("run this from inside the Cordon repository")
RECORDINGS = ROOT / "docs" / "assets" / "terminal"
OUT = ROOT / "docs" / "assets" / "terminal.svg"


@dataclass(frozen=True)
class Session:
    """One recording, and the command shown typed before it."""

    name: str
    command: str
    hold: int  # ms the finished screen stays before the next session


SESSIONS = (
    Session("home", "cordon-scanner", 5200),
    Session("repo", "cordon-scanner scan .", 7000),
    Session("npm", "cordon-scanner scan pkg:npm/express --online", 5200),
    Session("image", "cordon-scanner scan pkg:docker/nginx@1.27 --online", 6500),
)


PROMPT_MARK = "\u276f "  # the shell prompt the recordings are typed after


class Grid:
    COLS = 112
    ROWS = 42
    CW = 7.92  # character width, px
    LH = 18  # line height, px
    FONT = 13.2
    PAD = 18
    BAR = 36  # title bar

    @staticmethod
    def width() -> int:
        return round(Grid.COLS * Grid.CW + 2 * Grid.PAD)

    @staticmethod
    def height() -> int:
        return round(Grid.BAR + Grid.ROWS * Grid.LH + 2 * Grid.PAD)


class Timing:
    PROMPT = 650  # the prompt alone, before typing
    PER_CHAR = 42
    AFTER_TYPING = 380
    MAX_GAP = 650  # a recorded wait longer than this is shortened to it
    MIN_STEP = 40  # versions of a line closer than this are merged
    CLEAR = 450  # blank screen between sessions
    LINE = 18  # each line of a chunk, as it scrolls past on a real terminal


class Palette:
    """The scanner's own terminal colours (`cli/help.py` Palette, `report/text.py` badges)."""

    BG = "#0b1110"
    BAR = "#121a18"
    EDGE = "#22302c"
    FG = "#d6e2de"
    DIM = "#6d827b"
    PROMPT = "#35c3b1"
    FG_CODES: ClassVar[dict[int, str]] = {
        30: "#0b1110", 31: "#ff6b7a", 32: "#8bd49c", 33: "#e8c468", 34: "#7aa2f7",
        35: "#c792ea", 36: "#56d4c4", 37: "#d6e2de", 90: "#4f625c", 91: "#ff8a8a",
        92: "#8bd49c", 93: "#f0d58a", 94: "#8fb3ff", 95: "#d7aefb", 96: "#7fe3d6", 97: "#f2f7f5",
    }  # fmt: skip
    BG_CODES: ClassVar[dict[int, str]] = {
        40: "#0b1110", 41: "#d42b3c", 42: "#3f8f5a", 43: "#e8c468", 44: "#3d5a99",
        45: "#8e5bb5", 46: "#56d4c4", 47: "#c9d4d0", 100: "#4f625c", 101: "#ff8a8a",
    }  # fmt: skip


@dataclass(frozen=True)
class Style:
    fg: str | None = None
    bg: str | None = None
    bold: bool = False
    dim: bool = False

    def apply(self, codes: list[int]) -> Style:
        fg, bg, bold, dim = self.fg, self.bg, self.bold, self.dim
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg, bg, bold, dim = None, None, False, False
            elif c == 1:
                bold = True
            elif c == 2:
                dim = True
            elif c == 22:
                bold = dim = False
            elif c == 39:
                fg = None
            elif c == 49:
                bg = None
            elif c in Palette.FG_CODES:
                fg = Palette.FG_CODES[c]
            elif c in Palette.BG_CODES:
                bg = Palette.BG_CODES[c]
            elif c in (38, 48) and i + 4 < len(codes) + 0 and codes[i + 1 : i + 2] == [2]:
                rgb = "#{:02x}{:02x}{:02x}".format(*codes[i + 2 : i + 5])
                fg, bg = (rgb, bg) if c == 38 else (fg, rgb)
                i += 4
            elif c in (38, 48) and codes[i + 1 : i + 2] == [5]:
                i += 2  # 256-colour: not written by the scanner; skipped
            i += 1
        return Style(fg, bg, bold, dim)


Cell = tuple[str, Style]


@dataclass
class Screen:
    """The terminal a recording is replayed into: rows that only grow (the scrollback), a cursor,
    and for each row the times its content changed."""

    rows: list[list[Cell]] = field(default_factory=list)
    row: int = 0
    col: int = 0
    style: Style = field(default_factory=Style)
    history: dict[int, list[tuple[int, tuple[Cell, ...]]]] = field(default_factory=dict)
    dirty: set[int] = field(default_factory=set)
    pending: str = ""  # an escape sequence a write ended in the middle of

    def _line(self, r: int) -> list[Cell]:
        while len(self.rows) <= r:
            self.rows.append([])
        return self.rows[r]

    def put(self, ch: str) -> None:
        if self.col >= Grid.COLS:
            self.row, self.col = self.row + 1, 0
        line = self._line(self.row)
        while len(line) < self.col:
            line.append((" ", Style()))
        cell = (ch, self.style)
        if self.col < len(line):
            line[self.col] = cell
        else:
            line.append(cell)
        self.col += 1
        self.dirty.add(self.row)

    def feed(self, text: str) -> None:
        text = self.pending + text
        tail = re.search(r"\x1b(?:\[[0-9;?]*)?$", text)
        self.pending = tail.group(0) if tail else ""
        text = text[: tail.start()] if tail else text
        for m in re.finditer(
            r"\x1b\[([0-9;?]*)([A-Za-z])|\x1b.|([\r\n\b\t])|([^\x1b\r\n\b\t]+)", text
        ):
            params, final, ctrl, chars = m.groups()
            if chars:
                for ch in chars:
                    if ch >= " ":
                        self.put(ch)
            elif ctrl == "\r":
                self.col = 0
            elif ctrl == "\n":
                self.row += 1
                self._line(self.row)
            elif ctrl == "\b":
                self.col = max(0, self.col - 1)
            elif ctrl == "\t":
                self.col = (self.col // 8 + 1) * 8
            elif final == "m":
                self.style = self.style.apply(
                    [int(x) for x in (params or "0").split(";") if x.isdigit()]
                )
            elif final == "K":
                line = self._line(self.row)
                mode = int(params) if params and params.isdigit() else 0
                if mode == 0:
                    del line[self.col :]
                elif mode == 2:
                    line.clear()
                self.dirty.add(self.row)

    def commit(self, t: int) -> None:
        for r in sorted(self.dirty):
            snap = tuple(self._line(r))
            versions = self.history.setdefault(r, [])
            if versions and versions[-1][1] == snap:
                continue
            if versions and t - versions[-1][0] < Timing.MIN_STEP:
                versions[-1] = (versions[-1][0], snap)
            else:
                versions.append((t, snap))
        self.dirty.clear()


class Recording:
    """A `script -T` recording: the typescript's bytes, cut by its timing file into
    (delay seconds, text) chunks."""

    @staticmethod
    def chunks(name: str) -> list[tuple[float, str]]:
        data = (RECORDINGS / f"{name}.typescript").read_bytes()
        start = data.index(b"\n") + 1  # the "Script started" header line
        out, at = [], start
        decoder = codecs.getincrementaldecoder("utf-8")(
            "replace"
        )  # a character may span two writes
        for line in (RECORDINGS / f"{name}.timing").read_text(encoding="utf-8").splitlines():
            delay, count = line.split()
            piece = data[at : at + int(count)]
            at += int(count)
            out.append((float(delay), decoder.decode(piece)))
        return out


@dataclass
class Played:
    """One session on the timeline: its rows' versions, its scroll offsets, and the cursor."""

    start: int
    end: int
    history: dict[int, list[tuple[int, tuple[Cell, ...]]]]
    scroll: list[tuple[int, int]]  # (time, top row)
    cursor: list[tuple[int, int, int, bool]]  # (time, row, col, visible)


class Timeline:
    @staticmethod
    def play(session: Session, t0: int) -> Played:
        screen = Screen()
        prompt = Style(fg=Palette.PROMPT, bold=True)
        screen.style = prompt
        for ch in PROMPT_MARK:
            screen.put(ch)
        screen.style = Style()
        screen.commit(t0)
        cursor = [(t0, 0, screen.col, True)]
        t = t0 + Timing.PROMPT
        for ch in session.command:
            screen.put(ch)
            screen.commit(t)
            cursor.append((t, 0, screen.col, True))
            t += Timing.PER_CHAR
        t += Timing.AFTER_TYPING
        screen.row, screen.col = 1, 0
        cursor.append((t, 1, 0, False))
        scroll = [(t0, 0)]
        for delay, text in Recording.chunks(session.name):
            t += min(round(delay * 1000), Timing.MAX_GAP)
            # A line at a time, and a progress bar's redraws (a carriage return without a newline)
            # one at a time, so the bar fills rather than appearing finished.
            for i, piece in enumerate(re.split(r"(?<=\n)|(?=\r(?!\n))", text)):
                if not piece:
                    continue
                t += Timing.LINE if i else 0
                screen.feed(piece)
                screen.commit(t)
                top = max(0, screen.row - Grid.ROWS + 1)
                if top != scroll[-1][1]:
                    scroll.append((t, top))
        # The shell's next prompt, and the finished screen held.
        last = screen.row if screen.col == 0 else screen.row + 1
        screen.row, screen.col = last, 0
        screen.style = prompt
        for ch in PROMPT_MARK:
            screen.put(ch)
        screen.style = Style()
        screen.commit(t)
        cursor.append((t, last, 2, True))
        top = max(0, last - Grid.ROWS + 1)
        if top != scroll[-1][1]:
            scroll.append((t, top))
        return Played(t0, t + session.hold, screen.history, scroll, cursor)


class Svg:
    def __init__(self, total: int) -> None:
        self.total = total
        self.css: list[str] = []
        self.n = 0

    def pct(self, t: int) -> str:
        return f"{100 * t / self.total:.3f}%"

    def keyed(self, frames: list[tuple[int, str]], prop: str) -> str:
        """A class whose `prop` steps through frames ((time, value), first at its own start)."""
        name = f"k{self.n}"
        self.n += 1
        body = "".join(f"{self.pct(t)}{{{prop}:{v}}}" for t, v in frames)
        self.css.append(
            f"@keyframes {name}{{{body}}}.{name}{{animation:{name} {self.total}ms step-end infinite}}"
        )
        return name

    def visible(self, a: int, b: int) -> str:
        frames = [(0, "0"), (a, "1"), (b, "0")] if a > 0 else [(0, "1"), (b, "0")]
        if b < self.total:
            frames.append((self.total, "0"))
        return self.keyed(frames, "opacity")

    @staticmethod
    def runs(cells: tuple[Cell, ...]) -> list[tuple[int, str, Style]]:
        """Runs of one style; block characters always in runs of their own, which are drawn solid."""
        out: list[tuple[int, str, Style]] = []
        for col, (ch, st) in enumerate(cells):
            last = out[-1] if out else None
            if (
                last
                and last[2] == st
                and last[0] + len(last[1]) == col
                and (ch == "█") == (last[1][-1] == "█")
            ):
                out[-1] = (last[0], last[1] + ch, st)
            else:
                out.append((col, ch, st))
        return out

    @staticmethod
    def line(cells: tuple[Cell, ...], y: float) -> str:
        rects, spans = [], []
        for col, text, st in Svg.runs(cells):
            x = Grid.PAD + col * Grid.CW
            if st.bg:
                rects.append(
                    f'<rect x="{x:.1f}" y="{y - Grid.LH + 4:.1f}" width="{len(text) * Grid.CW:.1f}" '
                    f'height="{Grid.LH:.0f}" rx="2" fill="{st.bg}"/>'
                )
            if set(text) == {
                "█"
            }:  # the wordmark's block letters: solid cells, as a terminal draws them
                rects.append(
                    f'<rect x="{x:.1f}" y="{y - Grid.LH + 5:.1f}" width="{len(text) * Grid.CW + 0.6:.1f}" '
                    f'height="{Grid.LH + 0.6:.1f}" fill="{st.fg or Palette.FG}"/>'
                )
                continue
            if not text.strip():
                continue
            fill = st.fg or (Palette.DIM if st.dim else Palette.FG)
            if st.dim and st.fg:
                fill = Palette.DIM
            weight = ' font-weight="700"' if st.bold else ""
            lead = len(text) - len(text.lstrip(" "))
            spans.append(
                f'<tspan x="{x + lead * Grid.CW:.1f}" fill="{fill}"{weight}>{html.escape(text.strip(" "))}</tspan>'
            )
        text = f'<text y="{y:.1f}" xml:space="preserve">{"".join(spans)}</text>' if spans else ""
        return "".join(rects) + text

    def session(self, p: Played) -> str:
        out = [f'<g class="{self.visible(p.start, p.end)}">']
        frames = [(t, f"translateY({-top * Grid.LH}px)") for t, top in p.scroll]
        frames = [(0, "translateY(0px)"), *frames] if frames[0][0] > 0 else frames
        out.append(f'<g class="{self.keyed(frames, "transform")}">')
        top_y = Grid.BAR + Grid.PAD
        for r in sorted(p.history):
            versions = p.history[r]
            y = top_y + (r + 1) * Grid.LH - 5
            for i, (t, cells) in enumerate(versions):
                end = versions[i + 1][0] if i + 1 < len(versions) else p.end
                body = self.line(cells, y)
                if body:
                    out.append(f'<g class="{self.visible(t, end)}">{body}</g>')
        out.append(self.cursor(p, top_y))
        out.append("</g></g>")
        return "".join(out)

    def cursor(self, p: Played, top_y: float) -> str:
        """A block cursor that follows the typing, hidden while the scanner writes."""
        place = [
            (t, f"translate({col * Grid.CW:.1f}px,{row * Grid.LH}px)")
            for t, row, col, _ in p.cursor
        ]
        shown = [(t, "1" if on else "0") for t, _, _, on in p.cursor]
        if place[0][0] > 0:
            place.insert(0, (0, place[0][1]))
            shown.insert(0, (0, "0"))
        shown.append((p.end, "0"))
        rect = (
            f'<rect x="{Grid.PAD}" y="{top_y + 3}" width="{Grid.CW:.1f}" height="{Grid.LH - 2}" '
            f'fill="{Palette.PROMPT}" opacity="0.85"/>'
        )
        return (
            f'<g class="{self.keyed(place, "transform")}"><g class="{self.keyed(shown, "opacity")}">'
            f"{rect}</g></g>"
        )


class Render:
    @staticmethod
    def svg() -> str:
        played, t = [], 0
        for s in SESSIONS:
            p = Timeline.play(s, t)
            played.append(p)
            t = p.end + Timing.CLEAR
        svg = Svg(t)
        sessions = [svg.session(p) for p in played]
        w, h = Grid.width(), Grid.height()
        dots = "".join(
            f'<circle cx="{22 + 20 * i}" cy="{Grid.BAR / 2}" r="6" fill="{c}"/>'
            for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840"))
        )
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            'role="img" aria-label="cordon-scanner in a terminal: its home screen, then a repository, an npm '
            'package and a container image scanned, recorded from the scanner itself">'
            "<title>cordon-scanner, recorded</title>"
            '<style>text{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,'
            f'"Liberation Mono",monospace;font-size:{Grid.FONT}px}}g{{transform-box:view-box}}'
            + "".join(svg.css)
            + "</style>"
            f'<rect width="{w}" height="{h}" rx="12" fill="{Palette.BG}"/>'
            f'<rect width="{w}" height="{Grid.BAR}" rx="12" fill="{Palette.BAR}"/>'
            f'<rect y="{Grid.BAR - 12}" width="{w}" height="12" fill="{Palette.BAR}"/>'
            f'<line x1="0" y1="{Grid.BAR}" x2="{w}" y2="{Grid.BAR}" stroke="{Palette.EDGE}"/>'
            + dots
            + f'<text x="{w / 2}" y="{Grid.BAR / 2 + 4.5}" text-anchor="middle" fill="{Palette.DIM}">'
            "cordon-scanner — recorded from real scans</text>"
            f'<svg x="0" y="{Grid.BAR}" width="{w}" height="{h - Grid.BAR}" '
            f'viewBox="0 {Grid.BAR} {w} {h - Grid.BAR}" overflow="hidden">'
            + "".join(sessions)
            + "</svg></svg>\n"
        )


if __name__ == "__main__":
    OUT.write_text(Render.svg(), encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)}: {OUT.stat().st_size:,} bytes")
