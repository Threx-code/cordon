"""An editor extension presenting itself as a popular one under another identity (review 98)."""

from __future__ import annotations

from cordon_scanner.detect.agents import ExtensionNames

POPULAR = {"juanblanco.solidity", "vscode-icons-team.vscode-icons", "solomonkinard.git-blame"}


class TestImitation:
    def test_a_publisher_spelled_with_look_alike_letters(self):
        found = ExtensionNames.imitated("juanbianco.soli989", "solidity", [], POPULAR)
        assert found and found[0] == "juanblanco.solidity"

    def test_a_display_name_that_is_a_popular_extensions_name(self):
        found = ExtensionNames.imitated("someone.blan-co", "Solidity", [], POPULAR)
        assert found and "display name" in found[1]

    def test_an_entry_bundle_named_after_a_popular_extension(self):
        found = ExtensionNames.imitated(
            "bphpburnsus.iconesvscode", "Iconesvscode", ["dist/src/vscode-icons.bundle.js"], POPULAR
        )
        assert found and found[0] == "vscode-icons-team.vscode-icons"

    def test_an_extension_naming_itself_is_not(self):
        assert ExtensionNames.imitated("haochenxin.git-blame", "Git Blame", [], POPULAR) is None

    def test_invisible_characters_in_a_display_name_are_found(self):
        assert ExtensionNames.INVISIBLE.sub("", "solidity​") == "solidity"
