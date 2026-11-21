"""`cordon-scanner mcp config --client NAME` prints a configuration that parses and names the command and its arguments.

Every client the scanner protects has one (`detect/agents/paths.py`); each body is read the way the agent reads it (JSON, YAML or
TOML), and every name is accepted by the command's `--client` option."""

from __future__ import annotations

import argparse
import json
import re

import pytest

from cordon_scanner.foundation.formats.datayaml import DataYaml
from cordon_scanner.mcp.clients import CLIENTS, Clients
from cordon_scanner.mcp.options import McpOptions

NEW = ("roo", "kiro", "amazonq", "augment", "junie", "trae", "opencode", "goose")


class Command:
    """The executable a body names: a path from either platform, with or without `.exe`."""

    @staticmethod
    def is_scanner(command: str) -> bool:
        name = re.split(r"[/\\]", command)[-1].lower()
        return name.removesuffix(".exe") == "cordon-scanner"


class Reader:
    """The body of a printed configuration: what follows the notes, the comment lines taken out."""

    @staticmethod
    def body(client: str, **kwargs: bool) -> str:
        return "\n".join(
            line
            for line in Clients.snippet(client, **kwargs).splitlines()
            if not line.lstrip().startswith("#")
        )


class TestEveryClientHasOne:
    def test_the_count_is_the_agents_the_scanner_protects(self) -> None:
        assert len(CLIENTS) == 19
        assert set(NEW) <= set(CLIENTS)

    def test_the_option_accepts_every_name(self) -> None:
        parser = McpOptions.configure(argparse.ArgumentParser())
        for name in CLIENTS:
            assert parser.parse_args(["config", "--client", name]).client == name

    @pytest.mark.parametrize("client", NEW)
    def test_a_new_client_names_where_it_goes_and_the_project_note(self, client: str) -> None:
        text = Clients.snippet(client)
        assert text.startswith(f"# {client}: ")
        assert "--root" in text  # no workspace variable: the note that tells where to add it prints

    @pytest.mark.parametrize("client", ["roo", "kiro", "amazonq", "augment", "junie", "trae"])
    def test_the_common_body_names_the_command_and_its_arguments(self, client: str) -> None:
        entry = json.loads(Reader.body(client))["mcpServers"]["cordon"]
        assert Command.is_scanner(entry["command"])
        assert entry["args"] == ["mcp"]

    def test_the_online_option_reaches_every_body(self) -> None:
        for client in NEW:
            assert "--allow-online" in Clients.snippet(client, allow_online=True), client


class TestOpencode:
    def test_the_current_shape_has_the_servers_level_and_a_command_list(self) -> None:
        body = json.loads(Reader.body("opencode"))
        entry = body["mcp"]["servers"]["cordon"]
        assert body["$schema"] == "https://opencode.ai/config.json"
        assert entry["type"] == "local" and Command.is_scanner(entry["command"][0])
        assert entry["command"][1:] == ["mcp"]

    def test_the_comment_says_where_the_entry_goes_on_one_point_x(self) -> None:
        assert "opencode 1.x" in Clients.snippet("opencode")


class TestGoose:
    def test_the_body_is_the_extension_entry(self) -> None:
        entry = DataYaml.load(Reader.body("goose"))["extensions"]["cordon"]
        assert entry["name"] == "cordon" and entry["type"] == "stdio"
        assert Command.is_scanner(entry["cmd"]) and entry["args"] == ["mcp"]
        assert entry["enabled"] is True and entry["timeout"] == "300"

    def test_the_online_option_is_an_argument(self) -> None:
        entry = DataYaml.load(Reader.body("goose", allow_online=True))["extensions"]["cordon"]
        assert entry["args"] == ["mcp", "--allow-online"]


class TestTheOnesThatWereThere:
    @pytest.mark.parametrize(
        "client", sorted(set(CLIENTS) - set(NEW) - {"codex", "continue", "claude-code", "gemini"})
    )
    def test_the_json_ones_still_parse(self, client: str) -> None:
        assert "cordon" in json.dumps(json.loads(Reader.body(client)))


class TestContinue:
    def test_the_body_is_the_server_entry(self) -> None:
        document = DataYaml.load(Reader.body("continue"))
        entry = document["mcpServers"][0]
        assert entry["name"] == "cordon" and entry["type"] == "stdio"
        assert Command.is_scanner(entry["command"]) and entry["args"][0] == "mcp"


class TestTheCommandCheck:
    @pytest.mark.parametrize(
        "command",
        [
            "cordon-scanner",
            "/usr/local/bin/cordon-scanner",
            r"C:\Python\Scripts\cordon-scanner.EXE",
            "C:/x/Cordon-Scanner.exe",
        ],
    )
    def test_the_scanner_on_any_platform(self, command: str) -> None:
        assert Command.is_scanner(command)

    @pytest.mark.parametrize(
        "command", ["scanner", "/bin/cordon-scanner-old", r"C:\x\other.exe", ""]
    )
    def test_anything_else_is_not(self, command: str) -> None:
        assert not Command.is_scanner(command)
