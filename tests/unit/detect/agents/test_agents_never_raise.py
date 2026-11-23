"""No file the agents detector reads can make it raise: an unreadable part is a gap or is read around, never `OPERATIONAL.DETECTOR.FAILED`.

Every file the detector reads (instruction files with their front matter, skill files, MCP configurations, agent and editor settings, Codex TOML, CI workflows, extension lists) is
written from invented hostile values: numbers past the integer-string limit, NaN and infinities, dates that are not dates, lone surrogates, NUL bytes, very deep and very wide nesting,
and wrong types where a list or a string is expected. A scan of each must end with the detector having answered.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

EXAMPLES = int(os.environ.get("CORDON_AGENT_FUZZ_EXAMPLES", "6"))
HUGE = "9" * 5_000
KEYS = (
    "mcpServers",
    "servers",
    "context_servers",
    "mcp",
    "command",
    "args",
    "env",
    "url",
    "headers",
    "type",
    "transport",
    "cwd",
    "timeout",
    "port",
    "tools",
    "disabled",
    "autoApprove",
    "alwaysAllow",
    "hooks",
    "matcher",
    "permissions",
    "allow",
    "deny",
    "ask",
    "enabledPlugins",
    "extraKnownMarketplaces",
    "plugins",
    "source",
    "version",
    "name",
    "description",
    "model",
    "allowed-tools",
    "recommendations",
    "unwantedRecommendations",
    "mcp_servers",
    "date",
    "created",
    "expires",
    "max_tokens",
    "temperature",
    "priority",
    "globs",
    "alwaysApply",
)
LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**70), 2**70),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=30),
    st.sampled_from(
        [
            "",
            "0",
            "-1",
            "1e999",
            "NaN",
            "2026-13-45",
            "2026-02-30T25:61:61Z",
            "0x",
            "١٢٣",
            "\x00",
            "a\x00b",
            "\ud800",
            "\U0010ffff",
            "%zz",
            "%",
            "::",
            "[",
            "]]",
            HUGE,
            "@@HUGE@@",
        ]
    ),
)
KEY = st.one_of(st.sampled_from(KEYS), st.text(max_size=12))


class Texts:
    @staticmethod
    def structures(depth: int = 4) -> st.SearchStrategy[Any]:
        return st.recursive(
            LEAVES,
            lambda inner: st.one_of(
                st.lists(inner, max_size=5), st.dictionaries(KEY, inner, max_size=6)
            ),
            max_leaves=24,
        )

    @staticmethod
    @st.composite
    def json_text(draw: st.DrawFn) -> str:
        text = json.dumps(draw(Texts.structures()), ensure_ascii=draw(st.booleans()))
        if draw(st.booleans()):
            text = text.replace('"@@HUGE@@"', HUGE)
        return text

    @staticmethod
    @st.composite
    def front_matter(draw: st.DrawFn) -> str:
        lines = [
            f"{draw(KEY)}: {draw(st.one_of(LEAVES.map(str), st.text(max_size=30)))}"
            for _ in range(draw(st.integers(0, 6)))
        ]
        body = draw(st.text(max_size=200))
        return (
            "---\n" + "\n".join(lines) + draw(st.sampled_from(["\n---\n", "\n", "\n...\n"])) + body
        )

    @staticmethod
    @st.composite
    def toml_text(draw: st.DrawFn) -> str:
        rows = [
            f"{draw(st.sampled_from(['[mcp_servers.x]', '[mcp_servers]', '[[hooks]]', '[profiles.p]', 'a.b.c']))}\n{draw(KEY)} = {draw(LEAVES.map(repr))}"
            for _ in range(draw(st.integers(0, 5)))
        ]
        return "\n".join(rows) + draw(st.text(max_size=60))

    @staticmethod
    @st.composite
    def yaml_text(draw: st.DrawFn) -> str:
        rows = [
            f"{draw(KEY)}: {draw(st.one_of(LEAVES.map(str), st.text(max_size=20)))}"
            for _ in range(draw(st.integers(0, 8)))
        ]
        return (
            "on: push\njobs:\n  a:\n    steps:\n"
            + "\n".join(f"      - {row}" for row in rows)
            + draw(st.text(max_size=60))
        )


JSON_FILES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".vscode/settings.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".zed/settings.json",
    "opencode.json",
    ".claude-plugin/marketplace.json",
    ".vscode/extensions.json",
    ".cursor/hooks.json",
    "hooks/hooks.json",
    "package.json",
)
TEXT_FILES = (
    "CLAUDE.md",
    "AGENTS.md",
    "skills/s/SKILL.md",
    ".claude/skills/s/SKILL.md",
    ".claude/agents/a.md",
    ".claude/commands/c.md",
    ".cursorrules",
    ".cursor/rules/r.mdc",
    ".github/copilot-instructions.md",
)
YAML_FILES = (".github/workflows/w.yml", ".gitpod.yml", ".continue/config.yaml")


class Hostile:
    @staticmethod
    def failed(tmp: Path, name: str, text: str) -> list[str]:
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="surrogatepass")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp)
        return [
            f"{f.rule_id}: {f.message[:200]}"
            for f in result.findings
            if f.rule_id == "OPERATIONAL.DETECTOR.FAILED"
        ]


FUZZ = settings(
    max_examples=EXAMPLES, deadline=None, database=None, suppress_health_check=list(HealthCheck)
)


class TestNoFileMakesTheAgentsDetectorRaise:
    @FUZZ
    @given(name=st.sampled_from(JSON_FILES), text=Texts.json_text())
    def test_a_json_file_with_hostile_values(
        self, tmp_path_factory: pytest.TempPathFactory, name: str, text: str
    ) -> None:
        assert Hostile.failed(tmp_path_factory.mktemp("j"), name, text) == []

    @FUZZ
    @given(
        name=st.sampled_from(TEXT_FILES),
        text=st.one_of(Texts.front_matter(), st.text(max_size=400)),
    )
    def test_an_instruction_or_skill_file_with_hostile_front_matter(
        self, tmp_path_factory: pytest.TempPathFactory, name: str, text: str
    ) -> None:
        assert Hostile.failed(tmp_path_factory.mktemp("t"), name, text) == []

    @FUZZ
    @given(text=Texts.toml_text())
    def test_a_codex_config(self, tmp_path_factory: pytest.TempPathFactory, text: str) -> None:
        assert Hostile.failed(tmp_path_factory.mktemp("c"), ".codex/config.toml", text) == []

    @FUZZ
    @given(name=st.sampled_from(YAML_FILES), text=Texts.yaml_text())
    def test_a_workflow_or_yaml_config(
        self, tmp_path_factory: pytest.TempPathFactory, name: str, text: str
    ) -> None:
        assert Hostile.failed(tmp_path_factory.mktemp("y"), name, text) == []


class TestValuesTheGeneralFuzzDoesNotReach:
    """Hostile values at the places a number, a URL or a pin is read out of a file: each is read around, never raised."""

    @pytest.mark.parametrize(
        "literal",
        [
            "https://[your-host]/hook",
            "http://[::1/x",
            "https://[abc",
            "http://\u2100.com/x",
            "https://hooks.slack.com/services/T0/B0/" + "x" * 30,
        ],
    )
    def test_a_url_literal_that_does_not_parse_is_no_sink_and_does_not_raise(
        self, literal: str
    ) -> None:
        from cordon_scanner.detect.agents.mcp_servers.protocol.literal_sinks import McpLiteralSinks

        McpLiteralSinks.sink_kind(literal)

    @pytest.mark.parametrize(
        "literal", ["https://[your-host]/hook", "https://[abc", "http://\u2100.com/x"]
    )
    def test_an_mcp_server_source_with_such_a_literal_is_scanned_to_the_end(
        self, tmp_path: Path, literal: str
    ) -> None:
        source = f'const {{ Server }} = require("@modelcontextprotocol/sdk/server/index.js");\nconst target = "{literal}";\n'
        assert Hostile.failed(tmp_path, "server.js", source) == []

    def test_a_workflow_that_pins_an_agent_action_at_a_version_of_thousands_of_digits(
        self, tmp_path: Path
    ) -> None:
        workflow = f"on: push\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1.{HUGE}.0\n"
        assert Hostile.failed(tmp_path, ".github/workflows/w.yml", workflow) == []


URLS = st.one_of(
    st.sampled_from(
        [
            "https://[x]/",
            "http://[::1",
            "https://[",
            "http://\u2100.com",
            "https://a@[b]/",
            "http://:::/",
            "https://x.y:99999999999/",
            "http://%zz/",
            "https://\x00/",
        ]
    ),
    st.text(alphabet="[]:/.@%\u2100\x00abc0123-_", max_size=40).map(lambda tail: "https://" + tail),
)
PINS = st.one_of(
    st.sampled_from(
        [
            f"v1.{HUGE}.0",
            f"{HUGE}.1.1",
            "v1.0",
            "v",
            "v1.0.0.0",
            "\u0661.\u0662.\u0663",
            "beta",
            "v0",
            "main",
            f"v{HUGE}",
        ]
    ),
    st.from_regex(r"v?[0-9]{0,12}(\.[0-9]{0,12}){0,3}", fullmatch=True),
)
ACTIONS = (
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
    "openai/codex-action",
)


class TestSourcesAndPinsTheGeneralFuzzDoesNotReach:
    @FUZZ
    @given(url=URLS, name=st.sampled_from(("server.js", "server.py", "index.ts")))
    def test_an_mcp_server_source_with_a_hostile_url_literal(
        self, tmp_path_factory: pytest.TempPathFactory, url: str, name: str
    ) -> None:
        source = f'const {{ Server }} = require("@modelcontextprotocol/sdk/server/index.js");\nserver.tool("x", {{}}, async () => fetch("{url}"));\nconst target = "{url}";\n'
        if name.endswith(".py"):
            source = f'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n@mcp.tool()\ndef t():\n    return "{url}"\n'
        assert Hostile.failed(tmp_path_factory.mktemp("s"), name, source.replace("\x00", "")) == []

    @FUZZ
    @given(action=st.sampled_from(ACTIONS), pin=PINS)
    def test_a_workflow_pinning_an_agent_action_at_a_hostile_version(
        self, tmp_path_factory: pytest.TempPathFactory, action: str, pin: str
    ) -> None:
        text = f"on: push\njobs:\n  a:\n    steps:\n      - uses: {action}@{pin}\n"
        assert Hostile.failed(tmp_path_factory.mktemp("w"), ".github/workflows/w.yml", text) == []
