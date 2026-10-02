"""`cordon agent`: reads only its fixed list, sends inventory and findings, never a secret."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.cloud import CloudError, device

SECRET = "sk-live-" + "9" * 32


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "home"
    files = {
        ".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash(*)"]}}),
        ".claude.json": json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    }
                },
                "projects": {
                    "/work/app": {
                        "mcpServers": {
                            "docs": {"type": "http", "url": "https://mcp.example.com/sse?key=x"}
                        }
                    }
                },
            }
        ),
        ".cursor/mcp.json": json.dumps(
            {
                "mcpServers": {
                    "pay": {"command": "node", "args": ["s.js"], "env": {"API_KEY": SECRET}}
                }
            }
        ),
        ".codex/config.toml": '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git==0.6.2"]\n',
        ".npmrc": "registry=https://npm.internal.example/\n//npm.internal.example/:_authToken="
        + SECRET
        + "\n",
        ".vscode/extensions/anthropic.claude-code-2.0.1/package.json": "{}",
        "notes/secret-plans.md": "never read",
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / ".config"))
    return root


class TestCollect:
    def test_the_inventory(self, home) -> None:
        payload = device.DeviceInventory.collect(home)
        inventory = payload["inventory"]
        assert inventory["tools"] == ["claude-code", "codex", "cursor", "npm", "vscode"]
        servers = {s["name"]: s for s in inventory["mcp_servers"]}
        assert (
            servers["fs"]["package"] == "@modelcontextprotocol/server-filesystem"
            and servers["fs"]["pinned"] is False
        )
        assert servers["docs"]["endpoint"] == "https://mcp.example.com"
        assert servers["git"]["ecosystem"] == "pypi"
        assert inventory["registries"] == [
            {"manager": "npm", "registry": "https://npm.internal.example"}
        ]
        assert inventory["extensions"] == ["anthropic.claude-code-2.0.1"]

    def test_findings_come_from_the_agent_chain_rules(self, home) -> None:
        rules = {f["rule_id"] for f in device.DeviceInventory.collect(home)["findings"]}
        assert "SECRET.MCP.INLINE_CREDENTIAL.001" in rules
        assert "SUSPECT.MCP.UNPINNED.001" in rules

    def test_no_secret_and_no_unlisted_file_leaves(self, home) -> None:
        payload = json.dumps(device.DeviceInventory.collect(home))
        assert SECRET not in payload
        assert "secret-plans" not in payload and "never read" not in payload
        assert str(home) not in payload, "only logical paths are sent"
        assert "key=x" not in payload

    def test_every_path_read_is_on_the_fixed_list(self, home) -> None:
        listed = {s.logical for s in device.DeviceInventory.sources(home)}
        assert set(device.DeviceInventory.collect(home)["read"]) <= listed


class TestReport:
    def test_it_needs_the_device_token(self, home, monkeypatch) -> None:
        monkeypatch.delenv("CORDON_DEVICE_TOKEN", raising=False)
        with pytest.raises(CloudError, match="CORDON_DEVICE_TOKEN"):
            device.DeviceInventory.report({}, url="https://api.cordon.test")

    def test_it_sends_the_same_payload_inventory_prints(self, home, monkeypatch, capsys) -> None:
        sent: list[bytes] = []

        def transport(method, url, *, body, headers):
            assert url == "https://api.cordon.test/v1/devices/inventory"
            assert headers["Authorization"] == "Bearer dt"
            sent.append(body)
            return 202, b'{"receipt": "r1"}'

        monkeypatch.setattr("cordon_scanner.cloud.transport.CloudTransport._urllib", transport)
        monkeypatch.setenv("CORDON_DEVICE_TOKEN", "dt")
        assert CommandLine.main(["agent", "inventory"]) == 0
        printed = json.loads(capsys.readouterr().out)
        assert CommandLine.main(["agent", "report", "--url", "https://api.cordon.test"]) == 0
        assert json.loads(sent[0]) == printed
        assert "receipt r1" in capsys.readouterr().out
