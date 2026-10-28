"""The README's ecosystem and agent panels, each name shown with its mark.

    python scripts/build/render_readme_marks.py     # docs/assets/readme/{ecosystems,agents}.svg

The marks are the website's (`docs/assets/readme/marks.json` says where each comes from), drawn
inline rather than linked: an SVG shown through an <img> may load nothing outside itself. Each sits
on a light tile, as an app icon does, so a black mark stays visible on the dark card, and its ids are
prefixed so two marks' gradients cannot collide. Text only, standard library only, deterministic.
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
ASSETS = ROOT / "docs" / "assets" / "readme"

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


class Panel:
    WIDTH = 1200
    PAD = 48
    CHIP_H = 40
    GAP = 10
    CHAR = 8.45  # width of a 14 px monospace character
    STYLE = (
        '<style>text{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,'
        '"Liberation Mono",monospace}'
        ".chip{opacity:0;animation:in .45s ease-out forwards}"
        "@keyframes in{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}"
        "@media (prefers-reduced-motion:reduce){.chip{animation:none;opacity:1;transform:none}}"
        "</style>"
    )

    @staticmethod
    def chips(
        items: tuple[tuple[str, str], ...], y: float, delay: float
    ) -> tuple[list[str], float]:
        """Chips laid out left to right, wrapping; the y the next row would start at."""
        out, x = [], float(Panel.PAD)
        for name, key in items:
            width = 46 + len(name) * Panel.CHAR + 14
            if x + width > Panel.WIDTH - Panel.PAD:
                x, y = float(Panel.PAD), y + Panel.CHIP_H + Panel.GAP
            out.append(
                f'<g class="chip" style="animation-delay:{delay:.2f}s">'
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{Panel.CHIP_H}" rx="10" '
                'fill="#121a18" stroke="#2c3d38"/>'
                f'<rect x="{x + 7:.1f}" y="{y + 7:.1f}" width="26" height="26" rx="6" fill="#f2f7f5"/>'
                + Mark.placed(key, x + 10, y + 10, 20)
                + f'<text x="{x + 44:.1f}" y="{y + 25:.1f}" fill="#d6e2de" font-size="14">'
                f"{html.escape(name)}</text></g>"
            )
            x += width + Panel.GAP
            delay += 0.03
        return out, y + Panel.CHIP_H

    @staticmethod
    def card(title: str, subtitle: str, body: list[str], height: float, label: str) -> str:
        w, h = Panel.WIDTH, round(height)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'role="img" aria-label="{html.escape(label)}"><title>{html.escape(title)}</title>'
            + Panel.STYLE
            + f'<rect width="{w}" height="{h}" rx="18" fill="#0b1110"/>'
            f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="17.5" fill="none" stroke="#22302c"/>'
            f'<text x="{Panel.PAD}" y="64" fill="#f2f7f5" font-size="26" font-weight="700">'
            f"{html.escape(title)}</text>"
            f'<text x="{Panel.PAD}" y="92" fill="#8fa49d" font-size="14">{html.escape(subtitle)}</text>'
            + "".join(body)
            + "</svg>\n"
        )


class Render:
    @staticmethod
    def label(y: float, text: str) -> str:
        return (
            f'<text x="{Panel.PAD}" y="{y:.1f}" fill="#6d827b" font-size="12" letter-spacing="1">'
            f"{text}</text>"
        )

    @staticmethod
    def ecosystems() -> str:
        body = [Render.label(130, "PACKAGE MANAGERS")]
        chips, y = Panel.chips(PACKAGES, 142, 0.0)
        body += [*chips, Render.label(y + 34, "INFRASTRUCTURE")]
        chips, y = Panel.chips(INFRASTRUCTURE, y + 46, 0.75)
        names = ", ".join(n for n, _ in (*PACKAGES, *INFRASTRUCTURE))
        return Panel.card(
            "Twenty-eight ecosystems",
            "Manifests, lockfiles and what they resolve to, each with the checks its format allows.",
            body + chips,
            y + 40,
            f"Twenty-eight ecosystems: {names}",
        )

    @staticmethod
    def agents() -> str:
        chips, y = Panel.chips(AGENTS, 122, 0.0)
        names = ", ".join(n for n, _ in AGENTS)
        return Panel.card(
            "Seventeen AI coding agents",
            "Instruction files, skills, MCP servers and their source, hooks and approvals, and agents in CI.",
            chips,
            y + 40,
            f"The AI coding agents whose configuration Cordon reads: {names}",
        )


if __name__ == "__main__":
    for name, svg in (("ecosystems", Render.ecosystems()), ("agents", Render.agents())):
        path = ASSETS / f"{name}.svg"
        path.write_text(svg, encoding="utf-8")
        print(f"{path.relative_to(ROOT)}: {len(svg.encode()):,} bytes")
