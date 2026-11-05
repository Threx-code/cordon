"""`cordon agent`: reads only its fixed list, sends inventory and findings, never a secret."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.cloud import CloudError, device

SECRET = "sk-live-" + "9" * 32


class DeviceFixtures:
    """Fixtures for the tests in test_device.py; every test class here inherits them."""

    @pytest.fixture
    def home(self, tmp_path, monkeypatch) -> Path:
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


class TestCollect(DeviceFixtures):
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

    def test_no_time_budget_cuts_the_agent_findings(self, home, monkeypatch) -> None:
        """However small per_file_timeout is, the detector runs to its end: a device scan's
        answer does not depend on how busy the machine is (2026-10-31)."""
        from cordon_scanner.foundation.config import settings

        real = settings.Config.default

        def tiny() -> settings.Config:
            config = real()
            return config.with_overrides(limits=config.limits.merged(per_file_timeout=1e-9))

        # one file whose run yields several findings: a cut keeping only a run's first shows here
        (home / ".cursor" / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        name: {
                            "command": "npx",
                            "args": ["-y", f"@acme/{name}"],
                            "env": {"API_KEY": SECRET},
                        }
                        for name in ("pay", "ledger", "audit")
                    }
                }
            ),
            encoding="utf-8",
        )

        def keyed(findings: list[dict]) -> list[tuple]:
            return sorted((f["rule_id"], f["path"], f["line"]) for f in findings)

        default = keyed(device.DeviceInventory.collect(home)["findings"])
        monkeypatch.setattr(settings.Config, "default", staticmethod(tiny))
        tight = keyed(device.DeviceInventory.collect(home)["findings"])
        in_one = [k for k in default if k[1].endswith("mcp.json")]
        assert len(in_one) >= 2 and tight == default  # every finding, not each run's first

    def test_no_secret_and_no_unlisted_file_leaves(self, home) -> None:
        payload = json.dumps(device.DeviceInventory.collect(home))
        assert SECRET not in payload
        assert "secret-plans" not in payload and "never read" not in payload
        assert str(home) not in payload, "only logical paths are sent"
        assert "key=x" not in payload

    def test_every_path_read_is_on_the_fixed_list(self, home) -> None:
        listed = {s.logical for s in device.DeviceInventory.sources(home)}
        assert set(device.DeviceInventory.collect(home)["read"]) <= listed


class TestReport(DeviceFixtures):
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


class TestExtensionFolderBound:
    """An extension folder's name is read by its pattern only up to 255 bytes (2026-10-30)."""

    class Refuse:
        def match(self, text: str) -> None:
            raise AssertionError(f"the pattern was called on {len(text)} characters")

    #: The names a backtracking pattern works hardest on, each repeated up to the bound.
    WORST = ("0.--0.0.0", "0.-0.0.0-", "a.-1.1.1", "-1", ".-", "0.0.0-", "a-a-")
    #: Worst case over an ordinary name of the same length, in CPU time. Measured at the bound under
    #: load (1 Nov): the pattern's worst cases 46-97x (quadratic, bounded by NAME_BYTES); the
    #: exponential mutant at 21 characters 8,299-8,598x. The line sits about 10x above the one and 8x
    #: below the other.
    WORST_LINE = 1000

    @staticmethod
    def cpu(probe, calls: int = 300) -> float:
        """`probe`'s CPU time over `calls` calls, the best of three, floored at 0.1 ms."""
        best = float("inf")
        for _ in range(3):
            start = time.process_time()
            for _ in range(calls):
                probe()
            best = min(best, time.process_time() - start)
        return max(best, 1e-4)

    def test_a_256_byte_name_is_unrecognised_without_the_pattern(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        name = "a." + "1" * 248 + "-1.0.0"
        assert len(name.encode()) == device.DeviceInventory.NAME_BYTES + 1
        monkeypatch.setattr(device.DeviceInventory, "EXTENSION_FOLDER", self.Refuse())
        folder = tmp_path / "x"
        assert device.DeviceInventory._extension_identity(folder.with_name(name)) == (
            name.lower(),
            "",
        )

    def test_the_bound_reads_as_before_and_its_worst_case_is_quick(self, tmp_path: Path) -> None:
        assert device.DeviceInventory._extension_identity(
            tmp_path / "ms-python.python-2024.1.0-darwin-arm64"
        ) == (
            "ms-python.python",
            "2024.1.0",
        )
        # The pattern is superlinear on these names (each grows about 100x for 10x the length), which is
        # why only NAME_BYTES of a name reach it: the claim is that at the bound its worst case stays a
        # modest multiple of an ordinary name of the same length, in CPU time, never wall time.
        pattern, bound = device.DeviceInventory.EXTENSION_FOLDER, device.DeviceInventory.NAME_BYTES
        # Calls enough that the ordinary name takes a measurable time: Windows' process clock ticks
        # every 15.6 ms, so 300 calls read as 0, the floor made the ratio 1,406 (4 Nov).
        calls = 300
        while (
            TestExtensionFolderBound.cpu(
                lambda: pattern.match("a." + "x" * (bound - 3) + "\x01"), calls
            )
            < 0.05
            and calls < 1 << 20
        ):
            calls *= 4
        ordinary = TestExtensionFolderBound.cpu(
            lambda: pattern.match("a." + "x" * (bound - 3) + "\x01"), calls
        )
        for unit in TestExtensionFolderBound.WORST:
            name = ("a." + unit * bound)[: bound - 1] + "\x01"
            ratio = (
                TestExtensionFolderBound.cpu(lambda name=name: pattern.match(name), calls)
                / ordinary
            )
            assert ratio < TestExtensionFolderBound.WORST_LINE, (unit, ratio)

    def test_the_measure_catches_a_catastrophic_pattern(self) -> None:
        """An exponential pattern exceeds the line by orders of magnitude, so the measure tells a
        bounded worst case from a catastrophic one."""
        exponential = re.compile(r"^(a|a?)+$")
        ordinary = TestExtensionFolderBound.cpu(lambda: exponential.match("a" * 21), calls=3)
        worst = TestExtensionFolderBound.cpu(lambda: exponential.match("a" * 20 + "b"), calls=3)
        assert worst / ordinary > TestExtensionFolderBound.WORST_LINE
