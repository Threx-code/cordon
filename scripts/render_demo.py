#!/usr/bin/env python3
"""Render captured terminal output into an SVG for the README.

**Why SVG rather than a GIF or a PNG.** This project reports committed binaries
and asks people to review what they install. Shipping an opaque binary in its
own repository, to advertise itself, would be arguing against its own point --
and its binary detector would flag the file. An SVG is text: it diffs, it can be
read before it is trusted, it stays sharp at any size, and it costs a few
kilobytes.

**Why generated rather than drawn.** The output in the image has to be output the
tool actually produced. A screenshot can be edited and a hand-written mock-up is
a claim about behaviour rather than evidence of it, which is exactly the thing
this project refuses to do elsewhere. So this reads real captured text --
including the ANSI colours the terminal emitted -- and lays it out verbatim.

Regenerate with `make demo`, or:

    cordon-scanner scan <target> --no-cache | python scripts/render_demo.py \
        --command "cordon-scanner scan ." --out docs/assets/demo.svg
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# One terminal cell, at the font size below. Measured rather than guessed:
# these are the advance width and line height of DejaVu Sans Mono at 13px,
# which is what the fallback stack resolves to almost everywhere.
CELL_WIDTH = 7.8
LINE_HEIGHT = 18.0
FONT_SIZE = 13

PADDING_X = 18.0
PADDING_Y = 14.0
CHROME_HEIGHT = 34.0

# A dark palette, fixed rather than theme-aware. GitHub serves README images
# through a proxy that does not pass the reader's colour scheme, so a
# "theme-aware" terminal image is a terminal image that is unreadable for half
# of its audience.
BACKGROUND = "#11141a"
CHROME = "#1b1f27"
FOREGROUND = "#c9d1d9"
MUTED = "#6e7681"

ANSI_COLOURS = {
    30: "#484f58",
    31: "#ff7b72",
    32: "#3fb950",
    33: "#d29922",
    34: "#58a6ff",
    35: "#bc8cff",
    36: "#39c5cf",
    37: "#b1bac4",
    90: "#6e7681",
    91: "#ffa198",
    92: "#56d364",
    93: "#e3b341",
    94: "#79c0ff",
    95: "#d2a8ff",
    96: "#56d4dd",
    97: "#f0f6fc",
}

SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@dataclass(frozen=True, slots=True)
class Span:
    """A run of text sharing one colour and weight."""

    text: str
    colour: str
    bold: bool


def parse(line: str) -> list[Span]:
    """Split one line into coloured spans, honouring SGR codes.

    Only the codes a terminal reporter actually emits are handled -- colour,
    bold, and reset. Anything else is dropped rather than approximated, because
    a half-understood escape rendered as text is worse than no colour.
    """
    spans: list[Span] = []
    colour, bold = FOREGROUND, False
    position = 0

    for match in SGR.finditer(line):
        chunk = line[position : match.start()]
        if chunk:
            spans.append(Span(chunk, colour, bold))
        for code in (match.group(1) or "0").split(";"):
            value = int(code or 0)
            if value == 0:
                colour, bold = FOREGROUND, False
            elif value == 1:
                bold = True
            elif value == 22:
                bold = False
            elif value in ANSI_COLOURS:
                colour = ANSI_COLOURS[value]
        position = match.end()

    tail = line[position:]
    if tail:
        spans.append(Span(tail, colour, bold))
    return spans


def render(lines: list[str], command: str, title: str) -> str:
    """An SVG of a terminal window containing these lines."""
    body = [f"$ {command}", "", *lines]
    width = max(len(OTHER_ESCAPES.sub("", SGR.sub("", line))) for line in body) if body else 80
    width = max(width, len(command) + 2)

    pixel_width = round(width * CELL_WIDTH + PADDING_X * 2)
    pixel_height = round(len(body) * LINE_HEIGHT + PADDING_Y * 2 + CHROME_HEIGHT)

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{pixel_width}" '
        f'height="{pixel_height}" viewBox="0 0 {pixel_width} {pixel_height}" '
        f'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, '
        f'&quot;DejaVu Sans Mono&quot;, monospace" font-size="{FONT_SIZE}">',
        f"<title>{html.escape(title)}</title>",
        f'<rect width="{pixel_width}" height="{pixel_height}" rx="8" fill="{BACKGROUND}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{pixel_width - 16}a8 8 0 0 1 8 8v{CHROME_HEIGHT - 8}H0z" '
        f'fill="{CHROME}"/>',
    ]
    for index, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(f'<circle cx="{18 + index * 18}" cy="17" r="6" fill="{colour}"/>')
    out.append(
        f'<text x="{pixel_width / 2}" y="21" fill="{MUTED}" font-size="11" '
        f'text-anchor="middle">{html.escape(title)}</text>'
    )

    for row, line in enumerate(body):
        y = CHROME_HEIGHT + PADDING_Y + row * LINE_HEIGHT + FONT_SIZE
        column = 0
        pieces: list[str] = []
        for span in parse(OTHER_ESCAPES.sub("", line)):
            text = span.text
            if text.strip():
                x = PADDING_X + column * CELL_WIDTH
                weight = ' font-weight="bold"' if span.bold else ""
                pieces.append(
                    f'<tspan x="{x:.1f}" fill="{span.colour}"{weight}>{html.escape(text)}</tspan>'
                )
            column += len(text)
        if pieces:
            out.append(f'<text y="{y:.1f}" xml:space="preserve">{"".join(pieces)}</text>')

    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command", required=True, help="the command line to show above the output"
    )
    parser.add_argument("--title", default="cordon-scanner", help="text in the window chrome")
    parser.add_argument("--out", required=True, help="where to write the SVG")
    parser.add_argument(
        "--max-lines", type=int, default=44, help="truncate longer output, with a marker"
    )
    args = parser.parse_args()

    lines = sys.stdin.read().rstrip("\n").split("\n")
    if len(lines) > args.max_lines:
        hidden = len(lines) - args.max_lines
        lines = [*lines[: args.max_lines], "", f"    ... {hidden} more lines"]

    Path(args.out).write_text(render(lines, args.command, args.title), encoding="utf-8")
    print(f"wrote {args.out} ({len(lines)} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
