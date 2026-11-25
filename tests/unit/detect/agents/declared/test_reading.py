"""BP-12-7: a fixture server declares each of the four capabilities (network, shell, filesystem, environment) and the reading finds it.

Each fixture is the files of one server or skill, by path: the configuration that launches it, its code, its SKILL.md. The control declares
none and the reading says so."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from cordon_scanner.detect.agents.declared.reading import DeclaredCapabilities


class Fixture:
    @staticmethod
    def config(server: Mapping[str, object]) -> dict[str, str]:
        return {".mcp.json": json.dumps({"mcpServers": {"fixture": dict(server)}})}


class TestEachCapabilityIsFoundWhereItIsDeclared:
    CONFIG = {
        "network": {"url": "https://tools.example.com/mcp"},
        "shell": {"command": "bash", "args": ["-c", "run-tool"]},
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]},
        "environment": {"command": "node", "args": ["server.js"], "env": {"API_REGION": "eu"}},
    }
    PYTHON = {
        "network": "import requests\nrequests.get(url)\n",
        "shell": "import subprocess\nsubprocess.run(['ls'])\n",
        "filesystem": "with open(path) as handle:\n    data = handle.read()\n",
        "environment": "import os\ntoken = os.environ['TOKEN']\n",
    }
    JAVASCRIPT = {
        "network": "const r = await fetch(url);\n",
        "shell": "const cp = require('child_process');\ncp.execSync('ls');\n",
        "filesystem": "import { readFileSync } from 'fs';\nreadFileSync(p);\n",
        "environment": "const key = process.env.API_KEY;\n",
    }
    SKILL = {
        "network": "---\nname: s\ndescription: d\nallowed-tools: WebFetch\n---\nBody\n",
        "shell": "---\nname: s\ndescription: d\nallowed-tools: Bash(git status:*), Read\n---\nBody\n",
        "filesystem": "---\nname: s\ndescription: d\nallowed-tools: [Read, Edit]\n---\nBody\n",
    }

    @pytest.mark.parametrize("name", DeclaredCapabilities.NAMES)
    def test_a_server_that_declares_it_in_its_configuration(self, name: str) -> None:
        assert name in DeclaredCapabilities.of_files(Fixture.config(self.CONFIG[name]))

    @pytest.mark.parametrize("name", DeclaredCapabilities.NAMES)
    def test_a_python_server_that_uses_it(self, name: str) -> None:
        assert DeclaredCapabilities.of_files({"server.py": self.PYTHON[name]}) == {name}

    @pytest.mark.parametrize("name", DeclaredCapabilities.NAMES)
    def test_a_javascript_server_that_uses_it(self, name: str) -> None:
        assert DeclaredCapabilities.of_files({"src/index.ts": self.JAVASCRIPT[name]}) == {name}

    @pytest.mark.parametrize("name", sorted(SKILL))
    def test_a_skill_that_is_granted_the_tool_for_it(self, name: str) -> None:
        assert name in DeclaredCapabilities.of_files({"skill/SKILL.md": self.SKILL[name]})

    def test_a_skill_script_that_uses_it(self) -> None:
        files = {"skill/SKILL.md": "---\nname: s\n---\nBody\n", "skill/run.py": self.PYTHON["network"]}
        assert DeclaredCapabilities.of_files(files) == {"network"}

    def test_a_server_that_declares_all_four_is_read_as_all_four(self) -> None:
        files = {**Fixture.config({"command": "bash", "args": ["-c", "x"], "env": {"A": "b"}, "url": "https://x.example.com"}), "fs.py": self.PYTHON["filesystem"]}
        assert DeclaredCapabilities.of_files(files) == set(DeclaredCapabilities.NAMES)


class TestWhatDeclaresNothing:
    def test_a_server_that_only_computes(self) -> None:
        files = {**Fixture.config({"command": "node", "args": ["server.js"]}), "server.js": "export const add = (a, b) => a + b;\n"}
        assert DeclaredCapabilities.of_files(files) == frozenset()

    def test_a_remote_server_with_an_empty_url_declares_no_network(self) -> None:
        assert DeclaredCapabilities.of_files(Fixture.config({"url": "  "})) == frozenset()

    def test_an_empty_env_block_declares_no_environment(self) -> None:
        assert DeclaredCapabilities.of_files(Fixture.config({"command": "node", "env": {}})) == frozenset()

    def test_a_file_of_another_language_is_not_read_as_code(self) -> None:
        assert DeclaredCapabilities.of_files({"notes.md": "import requests; subprocess.run; process.env"}) == frozenset()

    def test_a_skill_with_no_tools_list(self) -> None:
        assert DeclaredCapabilities.of_files({"SKILL.md": "---\nname: s\n---\nUse Bash and WebFetch freely.\n"}) == frozenset()

    def test_a_configuration_that_is_not_json_names_no_server(self) -> None:
        assert DeclaredCapabilities.of_files({".mcp.json": "{not json"}) == frozenset()


class TestTheReadingIsBounded:
    def test_a_large_file_is_read_only_to_its_cap(self) -> None:
        late = "x = 1\n" * (DeclaredCapabilities.MAX_BYTES // 6 + 10) + "import requests\n"
        assert DeclaredCapabilities.of_files({"big.py": late}) == frozenset()

    def test_at_most_the_first_files_are_read(self) -> None:
        files = {f"a{i:04d}.py": "x = 1\n" for i in range(DeclaredCapabilities.MAX_FILES)}
        files["z_last.py"] = "import requests\n"
        assert DeclaredCapabilities.of_files(files) == frozenset()

    def test_the_declaration_is_written_sorted(self) -> None:
        assert DeclaredCapabilities.as_json(frozenset({"shell", "network"})) == '["network", "shell"]'
