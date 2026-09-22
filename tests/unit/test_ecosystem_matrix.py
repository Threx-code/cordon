"""The ecosystem table must describe what ships.

`docs/07-ECOSYSTEMS.md` answers the first question anyone asks a supply-chain
scanner -- which package managers does it read -- so it is the document most
worth keeping true and the easiest to leave behind. Six ecosystems were added in
one commit and the prose that listed them was not touched, which is what this
prevents happening again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from ecosystems import render, rows

DOCUMENT = Path(__file__).resolve().parents[2] / "docs" / "07-ECOSYSTEMS.md"


@pytest.mark.skipif(not DOCUMENT.exists(), reason="docs/ is not shipped in the sdist")
class TestTheEcosystemTableIsCurrent:
    def test_it_matches_what_the_tool_ships(self) -> None:
        assert DOCUMENT.read_text(encoding="utf-8") == render(), (
            "docs/07-ECOSYSTEMS.md is out of date. Regenerate it:\n"
            "    python tests/ecosystems.py > docs/07-ECOSYSTEMS.md"
        )

    def test_every_registered_ecosystem_appears(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        missing = [eco for eco in EcosystemRegistry.BY_ID if f"`{eco}`" not in text]
        assert not missing, f"ecosystems absent from the table: {sorted(missing)}"


class TestTheTableIsNotVacuous:
    """Guards the comparison above from passing on an empty enumeration."""

    def test_every_row_names_at_least_one_file_to_read(self) -> None:
        for row in rows():
            ecosystem, manifests, lockfiles = row[0], row[1], row[2]
            assert manifests != "--" or lockfiles != "--", (
                f"{ecosystem} is registered but matches no manifest and no lockfile, "
                f"so nothing in a scanned repository can reach it."
            )

    def test_it_covers_every_registered_ecosystem(self) -> None:
        assert len(rows()) == len(EcosystemRegistry.BY_ID)
        assert len(rows()) >= 17
