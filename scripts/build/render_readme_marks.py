"""The README's ecosystems and AI agents, each shown by its mark beside its name.

    python scripts/build/render_readme_marks.py     # docs/assets/marks/<key>.svg, and the README

The marks are the website's (`docs/assets/marks/marks.json` says where each comes from). Each is
written to its own small SVG on a white tile with a hairline border, so a black mark reads on GitHub's
dark theme and a white one on its light theme, and the README's lists (between the
`<!-- marks:... -->` comments) are rewritten from the tables below, as small tables of a mark beside
each name. Standard library only, deterministic.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path
from typing import ClassVar

ROOT = next(
    (p for p in (Path.cwd(), *Path.cwd().parents) if (p / "src" / "cordon_scanner").is_dir()), None
) or sys.exit("run this from inside the Cordon repository")
ASSETS = ROOT / "docs" / "assets" / "marks"

#: Every ecosystem the scanner reads (`foundation.dependencies.ECOSYSTEM_IDS`), as the README names
#: it, with its mark. Hackage is shown by Haskell's, the language it serves.
PACKAGES = (
    ("npm", "npm"), ("PyPI", "pypi"), ("Cargo", "cargo"), ("Go modules", "gomod"),
    ("Maven", "maven"), ("Gradle", "gradle"), ("NuGet", "nuget"), ("RubyGems", "rubygems"),
    ("Composer", "composer"), ("Hex", "hex"), ("Pub", "pub"), ("CocoaPods", "cocoapods"),
    ("Swift", "swift"), ("Conan", "conan"), ("vcpkg", "vcpkg"), ("Conda", "conda"),
    ("CRAN", "cran"), ("Hackage", "haskell"), ("Julia", "julia"), ("opam", "opam"),
    ("Nix", "nix"), ("Homebrew", "homebrew"), ("Bazel", "bazel"),
)  # fmt: skip
INFRASTRUCTURE = (
    ("GitHub Actions", "githubactions"), ("Terraform", "terraform"), ("Helm", "helm"),
    ("Ansible", "ansible"), ("container images", "docker"),
)  # fmt: skip
#: Every agent whose configuration the scanner reads (the website's `constants/agents.ts`).
AGENTS = (
    ("Claude Code", "claude"), ("Cursor", "cursor"), ("GitHub Copilot", "copilot"),
    ("Windsurf", "windsurf"), ("Gemini CLI", "gemini"), ("OpenAI Codex", "openai"),
    ("Kiro", "kiro"), ("Amazon Q", "aws"), ("JetBrains Junie", "jetbrains"),
    ("Augment", "augment"), ("Trae", "trae"), ("Roo Code", "roo"), ("Continue", "continue"),
    ("Zed", "zed"), ("goose", "goose"), ("opencode", "opencode"), ("Cline", "cline"),
)  # fmt: skip


class Mark:
    """One mark, as a nested <svg> placed in a box."""

    MARKS: ClassVar[dict[str, str]] = {
        k: v for k, v in json.loads((ASSETS / "marks.json").read_text("utf-8")).items() if k != "_"
    }

    @staticmethod
    def placed(key: str, x: float, y: float, size: float) -> str:
        svg = Mark.MARKS[key]
        root = re.match(r"<svg\b([^>]*)>(.*)</svg>\s*$", svg, re.S)
        if root is None:
            raise ValueError(f"{key}: not an <svg> element")
        attributes, body = root.groups()
        box = re.search(r'viewBox="([^"]+)"', attributes)
        fill = re.search(r'\sfill="([^"]+)"', attributes)
        # Every id, and every reference to one, made unique to this mark.
        body = re.sub(r'\bid="([^"]+)"', rf'id="{key}-\1"', body)
        body = re.sub(r"url\(#([^)]+)\)", rf"url(#{key}-\1)", body)
        body = re.sub(r'(href)="#([^"]+)"', rf'\1="#{key}-\2"', body)
        return (
            f'<svg x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" '
            f'viewBox="{box.group(1) if box else "0 0 24 24"}"'
            + (f' fill="{fill.group(1)}"' if fill else "")
            + f">{body}</svg>"
        )


class Tile:
    SIZE = 32
    INSET = 5

    @staticmethod
    def svg(key: str) -> str:
        s, i = Tile.SIZE, Tile.INSET
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 {s} {s}">'
            f'<rect x=".5" y=".5" width="{s - 1}" height="{s - 1}" rx="7" fill="#ffffff" stroke="#d0d7de"/>'
            + Mark.placed(key, i, i, s - 2 * i)
            + "</svg>\n"
        )


class Readme:
    PATH = ROOT / "README.md"

    PER_ROW = 6

    @staticmethod
    def items(entries: tuple[tuple[str, str], ...]) -> str:
        """A table, PER_ROW to a row, each cell a mark beside its name: a list of inline images
        wraps wherever the line ends and leaves a mark on one line and its name on the next."""
        cells = [
            f'<td><img src="docs/assets/marks/{key}.svg" width="20" height="20" align="center" alt=""> '
            f"{html.escape(name)}</td>"
            for name, key in entries
        ]
        rows = [cells[i : i + Readme.PER_ROW] for i in range(0, len(cells), Readme.PER_ROW)]
        return "<table>\n" + "\n".join("<tr>" + "".join(r) + "</tr>" for r in rows) + "\n</table>"

    @staticmethod
    def fill(text: str, section: str, entries: tuple[tuple[str, str], ...]) -> str:
        block = re.compile(rf"(<!-- marks:{section} -->\n)(?:.*?\n)??(<!-- /marks -->)", re.S)
        if not block.search(text):
            raise SystemExit(f"README.md has no <!-- marks:{section} --> block")
        return block.sub(lambda m: m.group(1) + Readme.items(entries) + "\n" + m.group(2), text)


if __name__ == "__main__":
    keys = {key for _, key in (*PACKAGES, *INFRASTRUCTURE, *AGENTS)}
    for key in sorted(keys):
        (ASSETS / f"{key}.svg").write_text(Tile.svg(key), encoding="utf-8")
    text = Readme.PATH.read_text(encoding="utf-8")
    text = Readme.fill(text, "packages", PACKAGES)
    text = Readme.fill(text, "infrastructure", INFRASTRUCTURE)
    text = Readme.fill(text, "agents", AGENTS)
    Readme.PATH.write_text(text, encoding="utf-8")
    print(f"{len(keys)} marks in {ASSETS.relative_to(ROOT)}; README lists rewritten")
