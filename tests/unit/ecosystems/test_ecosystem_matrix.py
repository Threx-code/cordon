"""The ecosystem table must describe what ships.

`docs/07-ECOSYSTEMS.md` answers the first question anyone asks a supply-chain
scanner -- which package managers does it read -- so it is the document most
worth keeping true and the easiest to leave behind. Six ecosystems were added in
one commit and the prose that listed them was not touched, which is what this
prevents happening again.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect.supply.provenance import SUPPORTED_ECOSYSTEMS
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.dependencies import (
    ECOSYSTEM_IDS,
    PROVENANCE_ECOSYSTEMS,
    PROVENANCE_NOT_PUBLISHED,
)
from kits.ecosystems import EcosystemsPage
from support import ROOT as REPO

DOCUMENT = REPO / "docs" / "07-ECOSYSTEMS.md"


@pytest.mark.skipif(not DOCUMENT.exists(), reason="docs/ is not shipped in the sdist")
class TestTheEcosystemTableIsCurrent:
    def test_it_matches_what_the_tool_ships(self) -> None:
        assert DOCUMENT.read_text(encoding="utf-8") == EcosystemsPage.render(), (
            "docs/07-ECOSYSTEMS.md is out of date. Regenerate it:\n"
            "    python tests/kits/ecosystems.py > docs/07-ECOSYSTEMS.md"
        )

    def test_every_registered_ecosystem_appears(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        missing = [eco for eco in EcosystemRegistry.BY_ID if f"`{eco}`" not in text]
        assert not missing, f"ecosystems absent from the table: {sorted(missing)}"


class TestTheDomainKnowsEveryEcosystem:
    """A policy's `accept_no_feed` is checked against `foundation.dependencies.ECOSYSTEM_IDS`, so the
    domain needs no import of this layer; the two must stay the same set."""

    def test_the_ids_are_the_registry_ids(self) -> None:
        assert {e.id for e in EcosystemRegistry.all_ecosystems()} == ECOSYSTEM_IDS


class TestTheTableIsNotVacuous:
    """Guards the comparison above from passing on an empty enumeration."""

    def test_every_row_names_at_least_one_file_to_read(self) -> None:
        for row in EcosystemsPage.rows():
            ecosystem, manifests, lockfiles = row[0], row[1], row[2]
            assert manifests != "--" or lockfiles != "--", (
                f"{ecosystem} is registered but matches no manifest and no lockfile, "
                f"so nothing in a scanned repository can reach it."
            )

    def test_it_covers_every_registered_ecosystem(self) -> None:
        assert len(EcosystemsPage.rows()) == len(EcosystemRegistry.BY_ID)
        assert len(EcosystemsPage.rows()) >= 17


class TestProvenanceIsAskedOrTheRegistryPublishesNone:
    """S22: an ecosystem is verified for build provenance, or its registry is on the written list of registries that publish nothing to verify;
    the rest are owed, and the structural guard (`coverage/`) keeps the owed list from growing."""

    def test_the_inventory_and_the_detector_read_one_set(self) -> None:
        assert SUPPORTED_ECOSYSTEMS is PROVENANCE_ECOSYSTEMS

    def test_what_is_verified_is_a_real_ecosystem(self) -> None:
        assert PROVENANCE_ECOSYSTEMS <= ECOSYSTEM_IDS

    def test_a_reason_names_a_real_ecosystem_that_is_not_verified_and_says_what_was_read(
        self,
    ) -> None:
        assert set(PROVENANCE_NOT_PUBLISHED) <= ECOSYSTEM_IDS
        assert not set(PROVENANCE_NOT_PUBLISHED) & PROVENANCE_ECOSYSTEMS
        assert all(
            len(why) >= 60 and why.endswith(".") for why in PROVENANCE_NOT_PUBLISHED.values()
        )

    def test_a_registry_with_nothing_found_cites_a_page_a_date_and_says_so(self) -> None:
        for eco in ("cargo", "composer", "cocoapods", "pub", "cran", "vcpkg", "julia"):
            why = PROVENANCE_NOT_PUBLISHED[eco]
            assert "no verifiable per-release signature was found" in why.lower(), eco
            assert "checked 2026-" in why, eco
