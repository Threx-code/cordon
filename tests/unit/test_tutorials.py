"""The tutorial set must be reachable from its own index.

`tutorials/README.md` is the map the root README points at and every tutorial
links back to. Six tutorials were added in one commit without being added to it,
so a third of the set was reachable only by browsing the directory -- the same
drift `docs/05-COVERAGE-MATRIX.md` is generated to avoid, in the one document
that nothing checked.

Not generated, because a tutorial map is prose: the grouping and the one-line
descriptions are written, not derived. What is checked is the part that can be
wrong without anyone noticing -- that every tutorial is listed, that every entry
resolves to a file, and that the chain of `Next:` links walks the whole set in
order.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest

TUTORIALS = Path(__file__).resolve().parents[2] / "tutorials"
INDEX = TUTORIALS / "README.md"

NUMBERED = re.compile(r"^(\d{2})-[a-z0-9-]+\.md$")
MAP_ENTRY = re.compile(r"^\s*[├└]─ (\d{2})\s{2}(.+?)\s\.{2,}\s", re.M)
NEXT_LINK = re.compile(r"^Next: \*\*\[(\d{2}) · [^\]]+\]\((\d{2}-[a-z0-9-]+\.md)\)\*\*", re.M)


def tutorial_files() -> list[Path]:
    return sorted(p for p in TUTORIALS.glob("*.md") if NUMBERED.match(p.name))


@pytest.mark.skipif(not INDEX.exists(), reason="tutorials/ is not shipped in the sdist")
class TestTheIndexIsComplete:
    def test_every_tutorial_is_listed(self) -> None:
        listed = {number for number, _title in MAP_ENTRY.findall(INDEX.read_text(encoding="utf-8"))}
        present = {p.name[:2] for p in tutorial_files()}
        assert present == listed, (
            f"tutorials/README.md lists {sorted(listed)} and the directory holds "
            f"{sorted(present)}. A tutorial nobody can find from the map is a "
            f"tutorial nobody reads."
        )

    def test_the_numbering_has_no_gaps(self) -> None:
        numbers = [int(p.name[:2]) for p in tutorial_files()]
        assert numbers == list(range(1, len(numbers) + 1)), (
            f"tutorial numbering is {numbers}; the files are the reading order, so a "
            f"gap or a repeat means the directory and the map disagree."
        )

    def test_every_link_between_tutorials_resolves(self) -> None:
        names = {p.name for p in tutorial_files()} | {"README.md"}
        for path in [*tutorial_files(), INDEX]:
            for target in re.findall(
                r"\]\(([0-9a-zA-Z._-]+\.md)\)", path.read_text(encoding="utf-8")
            ):
                assert target in names, f"{path.name} links to {target}, which does not exist"


@pytest.mark.skipif(not INDEX.exists(), reason="tutorials/ is not shipped in the sdist")
class TestTheChainWalksTheWholeSet:
    def test_each_tutorial_points_at_the_next_one(self) -> None:
        files = tutorial_files()
        for current, following in itertools.pairwise(files):
            match = NEXT_LINK.search(current.read_text(encoding="utf-8"))
            assert match is not None, f"{current.name} has no `Next:` line"
            number, target = match.groups()
            assert target == following.name, (
                f"{current.name} points at {target}; the next tutorial is {following.name}"
            )
            assert number == following.name[:2]

    def test_the_last_one_does_not(self) -> None:
        """It ends the tour, so a `Next:` there would point at nothing."""
        assert NEXT_LINK.search(tutorial_files()[-1].read_text(encoding="utf-8")) is None

    def test_the_heading_agrees_with_the_filename(self) -> None:
        for path in tutorial_files():
            heading = path.read_text(encoding="utf-8").splitlines()[0]
            assert heading.startswith(f"# {path.name[:2]} · "), (
                f"{path.name} is titled {heading!r}; a renumbering that missed the "
                f"heading leaves the page introducing itself as another tutorial."
            )
