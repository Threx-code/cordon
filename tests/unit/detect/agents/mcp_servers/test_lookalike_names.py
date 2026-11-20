"""An MCP server's own package named like a popular server's, and a tool named one letter from a well-known tool."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.agents.mcp_servers.lookalike_names import (
    OwnPackageName,
    ToolNameLookalike,
)
from cordon_scanner.foundation.config.settings import Config

SERVER_RULE = "SUSPECT.MCP.LOOKALIKE.002"
TOOL_RULE = "SUSPECT.MCP.TOOL_NAME_LOOKALIKE.001"
TS_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({ name: "notes", version: "1.0.0" });\n'
)


class LookalikeKit:
    @staticmethod
    def rules(target: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return {f.rule_id for f in result.findings}

    @staticmethod
    def npm_server(tmp_path: Path, name: str, tool: str = "lookup_note") -> Path:
        manifest = {
            "name": name,
            "version": "1.0.0",
            "dependencies": {"@modelcontextprotocol/sdk": "^1.17.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (tmp_path / "server.ts").write_text(
            TS_SERVER
            + f'server.registerTool("{tool}", {{ description: "Look up a note." }}, async () => ({{}}));\n',
            encoding="utf-8",
        )
        return tmp_path


class TestToolNameLookalike:
    def test_one_letter_from_a_well_known_tool(self) -> None:
        assert ToolNameLookalike.imitates("read_fle") == "read_file"
        assert ToolNameLookalike.imitates("git_stauts") is None  # two edits
        assert ToolNameLookalike.imitates("git_statsu") is None

    def test_the_tool_itself_in_any_spelling_is_not_a_lookalike(self) -> None:
        for name in ("read_file", "read-file", "readFile", "READ_FILE"):
            assert ToolNameLookalike.imitates(name) is None

    def test_a_plural_is_the_tool_own_name(self) -> None:
        assert ToolNameLookalike.imitates("read_files") is None
        assert ToolNameLookalike.imitates("list_table") is None

    def test_short_names_are_left_alone(self) -> None:
        assert ToolNameLookalike.imitates("git_ad") is None

    def test_the_scan_reports_it(self, tmp_path: Path) -> None:
        assert TOOL_RULE in LookalikeKit.rules(
            LookalikeKit.npm_server(tmp_path, "notes-mcp", "read_fle")
        )
        assert TOOL_RULE not in LookalikeKit.rules(
            LookalikeKit.npm_server(tmp_path, "notes-mcp", "read_file")
        )


class TestOwnPackageName:
    def test_names_from_each_manifest(self) -> None:
        assert (
            OwnPackageName.of(
                "pyproject.toml", '[project]\nname = "x-mcp"\ndependencies = ["mcp>=1.10"]\n'
            )
            == "x-mcp"
        )
        assert (
            OwnPackageName.of(
                "Cargo.toml", '[package]\nname = "x"\n\n[dependencies]\nrmcp = "0.2"\n'
            )
            == "x"
        )
        assert (
            OwnPackageName.of(
                "go.mod",
                "module example.invalid/x\n\nrequire github.com/mark3labs/mcp-go v0.32.0\n",
            )
            == "example.invalid/x"
        )

    def test_a_package_that_is_no_mcp_server_is_not_read(self) -> None:
        assert (
            OwnPackageName.of(
                "package.json", json.dumps({"name": "x", "dependencies": {"left-pad": "1"}})
            )
            is None
        )

    def test_a_malformed_manifest_names_nothing(self) -> None:
        assert OwnPackageName.of("Cargo.toml", "rmcp = [\n") is None

    def test_the_scan_reports_a_server_named_like_the_official_one(self, tmp_path: Path) -> None:
        rules = LookalikeKit.rules(
            LookalikeKit.npm_server(tmp_path, "@modelcontextprotocol/server-filesytem")
        )
        assert SERVER_RULE in rules

    def test_the_official_server_itself_is_not(self, tmp_path: Path) -> None:
        rules = LookalikeKit.rules(
            LookalikeKit.npm_server(tmp_path, "@modelcontextprotocol/server-filesystem")
        )
        assert SERVER_RULE not in rules

    def test_a_server_with_its_own_name_is_not(self, tmp_path: Path) -> None:
        assert SERVER_RULE not in LookalikeKit.rules(
            LookalikeKit.npm_server(tmp_path, "notes-mcp-server")
        )


class TestPythonExplicitToolName:
    def test_a_decorator_name_is_the_tool_name(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "notes-mcp"\ndependencies = ["mcp>=1.10"]\n', encoding="utf-8"
        )
        (tmp_path / "server.py").write_text(
            "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('notes')\n\n\n"
            '@mcp.tool(name="read_fle")\ndef handler(path: str) -> str:\n    """Read a file."""\n    return "note"\n',
            encoding="utf-8",
        )
        assert TOOL_RULE in LookalikeKit.rules(tmp_path)
