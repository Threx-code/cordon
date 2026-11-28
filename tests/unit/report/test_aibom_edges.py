"""The AI bill of materials on inputs that are broken, repeated or unreadable: it records what it can read and skips the rest (`report/aibom.py`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.report import aibom
from cordon_scanner.report.aibom import AiBom, AiInventory


class TestInventory:
    def test_the_same_reference_added_twice_is_one_entry(self) -> None:
        inventory = AiInventory()
        inventory.add({"bom-ref": "a", "name": "first"})
        inventory.add({"bom-ref": "a", "name": "second"})
        assert [c["name"] for c in inventory.components] == ["first"]

    def test_a_subagent_file_is_a_subagent(self) -> None:
        assert AiBom._kind_of_instruction(".claude/agents/reviewer.md") == "subagent"

    def test_a_file_past_the_hash_limit_is_listed_without_a_hash(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        path = tmp_path / "big.bin"
        path.write_bytes(b"x")
        monkeypatch.setattr(aibom, "MAX_HASH_BYTES", 0)
        assert AiBom._sha256(path, 1) == []
        monkeypatch.setattr(aibom, "MAX_HASH_BYTES", 10)
        assert AiBom._sha256(path, 1)[0]["alg"] == "SHA-256"


class TestMcpConfigs:
    def read(self, raw: bytes) -> AiInventory:
        inventory = AiInventory()
        AiBom._mcp(inventory, ".mcp.json", raw)
        return inventory

    def test_text_that_is_not_json_adds_nothing(self) -> None:
        inv = self.read(b"{nope")
        assert inv.components == [] and inv.services == []

    def test_a_server_that_is_not_an_object_or_has_no_command_or_url_adds_nothing(self) -> None:
        raw = json.dumps({"mcpServers": {"a": "text", "b": {"command": 5}, "c": {}}}).encode()
        inv = self.read(raw)
        assert inv.components == [] and inv.services == []

    def test_a_url_server_is_a_service_with_its_endpoint_and_a_command_server_a_component(
        self,
    ) -> None:
        raw = json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://u:p@mcp.example.invalid:8443/v1?key=secret"},
                    "local": {"command": "npx", "args": ["-y", "pkg@1.0.0", 7]},
                }
            }
        ).encode()
        inv = self.read(raw)
        assert inv.services[0]["endpoints"] == ["https://mcp.example.invalid:8443/v1"]
        assert inv.components[0]["bom-ref"] == "mcp-server:.mcp.json#local"


class TestSettingsAndWorkflows:
    def test_settings_that_are_not_json_are_still_listed_as_a_file(self) -> None:
        inventory = AiInventory()
        AiBom._settings(inventory, ".claude/settings.json", b"{nope", [])
        assert [c["bom-ref"] for c in inventory.components] == ["file:.claude/settings.json"]

    def test_an_action_that_is_not_an_agent_is_not_listed_and_one_that_is_is(self) -> None:
        inventory = AiInventory()
        text = "steps:\n  - uses: actions/checkout@v4\n  - uses: anthropics/claude-code-action@v1\n"
        AiBom._workflow(inventory, ".github/workflows/a.yml", text)
        assert [c["name"] for c in inventory.components] == ["anthropics/claude-code-action"]


class TestReadingTheTree:
    def test_a_file_that_cannot_be_read_is_skipped_and_the_rest_are_listed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers": {"s": {"command": "npx"}}}', encoding="utf-8"
        )
        real = Path.read_bytes

        def read_bytes(self: Path) -> bytes:
            if self.name == ".mcp.json":
                raise OSError("denied")
            return real(self)

        monkeypatch.setattr(Path, "read_bytes", read_bytes)
        found = AiBom.inventory(tmp_path)
        refs = {c["bom-ref"] for c in found.components}
        assert "file:CLAUDE.md" in refs
        assert not any(ref.startswith("mcp-server:") for ref in refs)
