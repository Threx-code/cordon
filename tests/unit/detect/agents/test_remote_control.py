"""A package that lets a remote party drive the local coding agent or terminal (`detect/agents/bridges`, `decide/remote_control.py`).

```
  EXEC  drives a coding agent (its SDK, its program spawned by name, its non-interactive flags) or a terminal   ┐
  CHAN  an outbound client channel (WebSocket, socket.io client, EventSource) that is not loopback only         ├─► SUSPECT.AGENT.REMOTE_CONTROL.001
  HIST  names an agent's history store                                                                         ┘
  two of the three, or all three in tests and dependencies only                                                 ──► nothing
```
First-party JavaScript only, read across the whole package: each file leaves one internal record, one package step decides, and no
record ever reaches a report. Inert fixtures: archives of text built here, never run; the hosts are `.invalid`; sensitive names are
written in parts, as the rest of the suite writes them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.remote_control import RemoteControl
from cordon_scanner.detect.agents.bridges.shape import BridgeShape
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.rules.patterns import PatternCompiler
from unit.detect.code.capability.test_npm_payload_execution import Npm

RULE = RemoteControl.RULE
AGENT = "claude"
SDK = "@anthropic-ai/claude-" + "agent-sdk"
PTY = "node-" + "pty"
REMOTE = "wss://relay.example" + ".invalid/session"


class Js:
    """The three halves, as small modules."""

    SDK = f"import {{ query }} from '{SDK}';\nexport const run = (prompt) => query({{ prompt }});\n"
    SPAWN = (
        "const { spawn } = require('child_process');\nexport const start = () => spawn('"
        + AGENT
        + "', ['-p']);\n"
    )
    TERM = f"import pty from '{PTY}';\nexport const shell = () => pty.spawn('bash', []);\n"
    CLIENT = f"export const open = () => new WebSocket('{REMOTE}');\n"
    SOCKETIO = (
        "import { io } from 'socket.io-"
        + "client';\nexport const open = () => io('https://relay.example.invalid');\n"
    )
    STREAM = "export const open = () => new EventSource('https://relay.example.invalid/events');\n"
    LOOPBACK = "export const open = () => new WebSocket('ws://127.0.0.1:8123/local');\n"
    SERVER = "import http from 'node:http';\nexport const serve = () => http.createServer().listen(8123);\n"
    HISTORY = "export const where = () => path.join(os.homedir(), '.claude', 'projects');\n"
    CODEX = "export const where = () => path.join(os.homedir(), '.codex/sessions');\n"
    GEMINI = "export const where = () => path.join(os.homedir(), '.gemini/');\n"


class Package:
    @staticmethod
    def scan(tmp_path: Path, files: dict[str, str]) -> list:
        archive = Npm.build(
            tmp_path,
            "demo-bridge",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": "module.exports = {};\n", **files},
        )
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(archive).findings

    @staticmethod
    def found(findings: list) -> list:
        return [f for f in findings if f.rule_id == RULE]


class TestTheThreeTogether:
    @pytest.mark.parametrize(
        "files",
        [
            {"agent.js": Js.SDK, "link.js": Js.CLIENT, "store.js": Js.HISTORY},
            {"agent.js": Js.SPAWN, "link.js": Js.SOCKETIO, "store.js": Js.CODEX},
            {"agent.js": Js.TERM, "link.js": Js.CLIENT, "store.js": Js.GEMINI},
            {"bridge.js": Js.SDK + Js.STREAM + Js.HISTORY},
        ],
        ids=[
            "sdk-websocket-claude",
            "spawn-socketio-codex",
            "terminal-websocket-gemini",
            "one-file",
        ],
    )
    def test_it_blocks(self, tmp_path: Path, files: dict[str, str]) -> None:
        found = Package.found(Package.scan(tmp_path, files))
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH
        assert found[0].category is Category.SUSPICIOUS

    def test_a_loopback_channel_beside_a_remote_one_still_counts(self, tmp_path: Path) -> None:
        files = {"a.js": Js.SDK, "b.js": Js.LOOPBACK + Js.CLIENT, "c.js": Js.HISTORY}
        assert Package.found(Package.scan(tmp_path, files))

    def test_the_finding_says_which_agent_which_channel_which_store_and_nothing_else(
        self, tmp_path: Path
    ) -> None:
        found = Package.found(
            Package.scan(tmp_path, {"a.js": Js.SDK, "b.js": Js.CLIENT, "c.js": Js.HISTORY})
        )[0]
        text = found.message.lower()
        assert "through its sdk" in text and "websocket" in text and "claude" in text
        assert "relay.example" not in text and "wss://" not in text and "/projects" not in text
        assert not re.search(r"internal\.", text)


class TestWhatIsNot:
    @pytest.mark.parametrize(
        "files",
        [
            {"a.js": Js.SDK, "b.js": Js.CLIENT},
            {"a.js": Js.SDK, "b.js": Js.HISTORY},
            {"b.js": Js.CLIENT, "c.js": Js.HISTORY},
            {"a.js": Js.SDK, "b.js": Js.LOOPBACK, "c.js": Js.HISTORY},
            {"a.js": Js.SDK, "b.js": Js.SERVER, "c.js": Js.HISTORY},
        ],
        ids=["no-history", "no-channel", "no-agent", "loopback-only", "server-only"],
    )
    def test_two_of_three_do_not_block(self, tmp_path: Path, files: dict[str, str]) -> None:
        assert not Package.found(Package.scan(tmp_path, files))

    def test_tests_and_dependencies_are_not_the_package(self, tmp_path: Path) -> None:
        files = {
            "tests/a.test.js": Js.SDK,
            "node_modules/dep/index.js": Js.CLIENT,
            "examples/store.js": Js.HISTORY,
        }
        assert not Package.found(Package.scan(tmp_path, files))

    def test_a_package_that_holds_all_three_only_outside_its_code_is_not_one(
        self, tmp_path: Path
    ) -> None:
        files = {"a.js": Js.SDK, "b.js": Js.CLIENT, "node_modules/x/c.js": Js.HISTORY}
        assert not Package.found(Package.scan(tmp_path, files))


class TestTheRecords:
    def test_no_record_reaches_a_report(self, tmp_path: Path) -> None:
        findings = Package.scan(tmp_path, {"a.js": Js.SDK, "b.js": Js.CLIENT, "c.js": Js.HISTORY})
        assert not [f for f in findings if f.rule_id.startswith("INTERNAL.")]

    def test_a_file_with_none_of_the_signals_leaves_no_record(self) -> None:
        assert BridgeShape.signals("export const add = (a, b) => a + b;\n") is None

    def test_a_record_survives_the_trip_and_an_unknown_one_is_refused(self) -> None:
        signals = BridgeShape.signals(Js.SDK + Js.CLIENT + Js.HISTORY)
        assert signals is not None
        message = BridgeShape.encode(signals)
        assert BridgeShape.decode(message) == signals
        assert BridgeShape.decode("v9 " + message) is None
        assert BridgeShape.decode("x" * 600) is None

    def test_the_package_step_needs_all_three_across_the_records(self) -> None:
        agent = BridgeShape.signals(Js.SDK)
        link = BridgeShape.signals(Js.CLIENT)
        store = BridgeShape.signals(Js.HISTORY)
        assert agent and link and store
        assert RemoteControl.fires([agent, link, store])
        assert not RemoteControl.fires([agent, link])
        assert not RemoteControl.fires([agent, store])
        assert not RemoteControl.fires([])


class TestThePatterns:
    @pytest.mark.parametrize("pattern", BridgeShape.patterns())
    def test_each_pattern_passes_the_engine_check_for_catastrophic_backtracking(
        self, pattern: str
    ) -> None:
        PatternCompiler.validate_pattern(pattern, rule_id=RULE)

    def test_a_long_hostile_line_reads_in_a_short_time(self) -> None:
        import time

        line = "a" * 200_000 + " new WebSocket(" + "." * 200_000 + "http://" + "a." * 100_000
        started = time.monotonic()
        BridgeShape.signals(line)
        assert time.monotonic() - started < 5.0

    @pytest.mark.parametrize("pattern", BridgeShape.patterns())
    def test_no_match_is_longer_than_the_overlap_a_segment_reads_past_its_end(
        self, pattern: str
    ) -> None:
        from re import _parser  # type: ignore[attr-defined]

        from cordon_scanner.foundation.text.segments import OVERLAP_CHARS

        assert _parser.parse(pattern).getwidth()[1] <= OVERLAP_CHARS


def padding(chars: int) -> str:
    """Comment lines that say nothing, `chars` characters in all."""
    line = "// " + "x" * 77 + "\n"
    whole, rest = divmod(chars, len(line))
    return line * whole + ("/" * (rest - 1) + "\n" if rest else "")


class TestAFileBeyondThreeMillionCharacters:
    """A file over three million characters was given no record at all: a bridge padded past that was no bridge."""

    @pytest.mark.parametrize("before", [3_000_100, 3_500_000])
    def test_what_it_does_past_that_is_read(self, before: int) -> None:
        signals = BridgeShape.signals(padding(before) + Js.SDK + Js.CLIENT + Js.HISTORY)
        assert signals is not None
        assert signals.execs and signals.chans and signals.hists

    def test_what_straddles_a_segment_edge_is_read(self) -> None:
        edge = 1 << 20
        signals = BridgeShape.signals(padding(edge - 40) + Js.SDK + padding(100))
        assert signals is not None
        assert signals.execs

    def test_a_long_file_that_does_none_of_it_leaves_no_record(self) -> None:
        assert BridgeShape.signals(padding(3_500_000)) is None


class TestTheCatalogue:
    def test_the_rule_is_in_the_catalogue_at_high(self) -> None:
        from cordon_scanner.detect.agents.rule_catalogue import RULES

        assert RULES[RULE].severity is Severity.HIGH
        assert "agent" in RULES[RULE].title.lower()
