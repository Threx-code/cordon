"""Brewfile conditions, Brewfile.lock.json and install receipts on the shapes written less often (`ecosystems/packages/homebrew.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["homebrew"]


class TestBrewfile:
    def test_an_else_and_an_elsif_change_the_condition_the_entries_between_them_sit_under(
        self,
    ) -> None:
        text = (
            "if OS.mac?\n  brew 'a'\nelsif OS.linux?\n  brew 'b'\nelse\n  brew 'c'\nend\n"
            "unless ENV['CI']\n  brew 'd'\nend\n"
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("Brewfile", text))
        platforms = {d.name: d.platform for d in manifest.dependencies}
        assert any("OS.mac?" in p for p in platforms["a"])
        assert any("OS.linux?" in p for p in platforms["b"])
        assert any(p.startswith("not ") for p in platforms["c"])
        assert any("CI" in p for p in platforms["d"])


class TestBrewfileLock:
    def lock(self, data: Any) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc("Brewfile.lock.json", json.dumps(data)))

    def test_a_lock_without_entries_is_refused(self) -> None:
        assert self.lock({}).parse_error == "a Brewfile.lock.json without its entries"

    def test_an_entry_that_is_not_an_object_is_skipped(self) -> None:
        graph = self.lock(
            {
                "entries": {
                    "brew": {"junk": "text", "jq": {"version": "1.7", "bottle": {"files": {}}}}
                }
            }
        )
        assert [e.name for e in graph.entries] == ["jq"]


class TestInstallReceipt:
    def read(self, path: str, data: Any) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(path, json.dumps(data)))

    def test_a_receipt_outside_a_cellar_keg_is_refused(self) -> None:
        graph = self.read(
            "opt/jq/INSTALL_RECEIPT.json", {"source": {}, "installed_on_request": True}
        )
        assert "outside a Cellar" in graph.parse_error

    def test_a_receipt_without_its_source_and_how_it_was_installed_is_refused(self) -> None:
        graph = self.read("brew/Cellar/jq/1.7/INSTALL_RECEIPT.json", {"source": {}})
        assert "without its source and how it was installed" in graph.parse_error
