"""The release page for the version being cut exists, and is written the way the READMEs are.

The release workflow publishes `docs/releases/<version>.md` as the GitHub release body and stops
if it is missing. This test is the same requirement held a step earlier, on every pull request,
so a release is never the first thing to find the page absent.
"""

from __future__ import annotations

import re
from pathlib import Path

from cordon_scanner import __version__

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs" / "releases" / f"{__version__}.md"


class TestReleaseNotes:
    def test_the_current_version_has_a_release_page(self) -> None:
        assert PAGE.is_file(), f"write {PAGE.relative_to(ROOT)} before tagging v{__version__}"

    def test_the_page_names_its_version(self) -> None:
        assert f"# Cordon {__version__}" in PAGE.read_text(encoding="utf-8")

    def test_the_page_links_the_full_changelog_section(self) -> None:
        text = PAGE.read_text(encoding="utf-8")
        assert f"CHANGELOG.md#{__version__.replace('.', '')}" in text
        assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_the_page_uses_diagrams_not_markdown_tables(self) -> None:
        text = PAGE.read_text(encoding="utf-8")
        assert "```" in text, "the page is drawn as ASCII diagrams in code blocks"
        outside = re.sub(r"```.*?```", "", text, flags=re.S)
        tables = [line for line in outside.splitlines() if re.match(r"^\s*\|.*\|\s*$", line)]
        assert not tables, tables
